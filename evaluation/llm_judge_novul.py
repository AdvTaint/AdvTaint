import os
import pandas as pd
import json
import shutil  # Used for moving files
from langchain_community.llms.ollama import Ollama
from langchain.prompts import PromptTemplate
from langchain.output_parsers import PydanticOutputParser, OutputFixingParser
from pydantic import BaseModel, Field
from typing import Optional, List, Literal
import re
import glob

# --------------------------------------------------------------------------
# 1. Define Pydantic Models
# --------------------------------------------------------------------------

class DetectionItem(BaseModel):
    """Structure for a single entry in the JSON list output by the detection tool"""
    is_vulnerable: str
    vulnerability_type: str
    reasoning: str
    vulnerable_path: str


class JudgementResult(BaseModel):
    verdict: Literal["Right", "Wrong"] = Field(
        description="The judgment result. Return 'Right' if the findings are UNRELATED to the CVE. Return 'Wrong' only if the findings match the CVE logic (indicating a False Positive on the specific CVE)."
    )
    reasoning: str = Field(
        description="Analyze the correlation between the findings and the CVE. explicit statement: 'The findings are unrelated to the CVE, so this is judged as Right' OR 'The findings match the CVE logic, so this is judged as Wrong'."
    )

# --------------------------------------------------------------------------
# 2. Initialize LLM and Judge Chain
# --------------------------------------------------------------------------

# Initialize Ollama
try:
    # Note: This is the "Judge" LLM; you can use the same model as before or a stronger reasoning model
    llm = Ollama(model="gpt-oss:120b", temperature=0, num_ctx=65536, base_url="http://localhost:11434") 
except Exception as e:
    print(f"Error initializing Ollama. Make sure Ollama is running.")
    print(f"Error: {e}")
    exit()

# Set up parser for the Judgment model
pydantic_parser = PydanticOutputParser(pydantic_object=JudgementResult)  # for novul (no vulnerability) cases
output_fixing_parser = OutputFixingParser.from_llm(
    parser=pydantic_parser, 
    llm=llm
)

# Prompt template for the Judge
judge_false_positive_prompt_template = """
You are an expert Vulnerability False Positive Validator. Your task is to check if an expert falsely reports a **SPECIFIC** CVE on a file where that CVE has been **PATCHED**.

You will be given:
1. **Ground Truth (The Fixed CVE):** Details of the specific vulnerability that was fixed (CVE description, patch, and patched source code).
2. **Expert's Findings:** A list of vulnerabilities reported by the tool on this patched code.

**Your Goal:** Determine if the tool generates a False Positive **SPECIFIC TO THE GIVEN CVE**.

**CRITICAL INSTRUCTION ON JUDGMENT:**
You must strictly compare the **Root Cause** and **Code Path** of the Expert's Findings against the Ground Truth CVE.

**1. JUDGE AS "WRONG" (False Positive on CVE)**
* **Condition:** The expert reports a vulnerability that **matches** the CVE's vulnerability type, reasoning, or specific code path (ignoring the fact that it was patched).
* **Meaning:** The tool failed to see the patch and is reporting the *original* (now fixed) issue. This is a target False Positive.

**2. JUDGE AS "RIGHT" (No False Positive on CVE)**
* **Condition A (Crucial):** The expert reports vulnerabilities that are **COMPLETELY UNRELATED** to the Ground Truth CVE (e.g., different function names, different vulnerability types, or different logic).
    * *Note:* Even if these unrelated findings might be wrong themselves, **they are NOT a False Positive regarding the specific CVE we are testing.** Therefore, the result for this specific test is **RIGHT**.

---
**[GROUND TRUTH (The Fixed CVE)]**

**CVE Description:**
{cve_description}

**Patch Information:**
{patch_info}

**Source Code (Patched):**
{src_code}

---
**[EXPERT'S FINDINGS]**

{tool_findings}

---
**[YOUR JUDGMENT]**

Is the expert's result "Right" (It did NOT falsely report the specific CVE) or "Wrong" (It falsely reported the specific CVE)?

**Step-by-step Analysis:**
1. Identify the core vulnerability logic/function of the Ground Truth CVE.
2. Check if any of the Expert's Findings target that same vulnerability logic/function.
3. If findings are unrelated (different vulnerability logic), output **Right**.
4. If findings are related but ignore the patch, output **Wrong**.

Provide your answer in a JSON format like:

{format_instructions}
"""

# Build the Judge Chain (novul version)
judge_prompt = PromptTemplate(
    template=judge_false_positive_prompt_template,
    input_variables=["cve_description", "patch_info", "ground_truth_analysis", "tool_findings"],
    partial_variables={"format_instructions": pydantic_parser.get_format_instructions()}
)

judge_chain = judge_prompt | llm | output_fixing_parser

# --------------------------------------------------------------------------
# 3. Helper Functions
# --------------------------------------------------------------------------

def load_cve_dataframe(csv_path: str) -> Optional[pd.DataFrame]:
    """Loads the CVE information from the specified CSV file."""
    try:
        df = pd.read_csv(csv_path)
        print(f"Successfully loaded CVE data from {csv_path}")
        return df
    except FileNotFoundError:
        print(f"Error: CSV file not found at {csv_path}")
        return None
    except Exception as e:
        print(f"Error reading CSV file {csv_path}: {e}")
        return None

def get_patch_info(patch_dir: str, cve_id: str) -> Optional[str]:
    """Reads the patch file content for a given CVE_ID."""
    file_path = os.path.join(patch_dir, f"{cve_id}_diff.txt")
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
            if not content.strip():
                return "Patch file is empty."
            return content
    except FileNotFoundError:
        print(f"Warning: Patch file not found at {file_path}")
        return None
    except Exception as e:
        print(f"Error reading patch file {file_path}: {e}")
        return None

def get_code_info(all_codes: list, cve_id: str) -> Optional[str]:
    """Reads the source code content for a given CVE_ID from the code list."""
    code_file = None
    for file in all_codes:
        name = file.split('/')[-1]
        if name.startswith(cve_id):
            code_file = file
            break

    if not code_file:
        return None

    try:
        with open(code_file, 'r', encoding='utf-8') as f:
            content = f.read()
            if not content.strip():
                print(f"Warning: Source file {code_file} is empty.")
                return "No source code information available."
            return content
    except FileNotFoundError:
        print(f"Error: Source file not found at {code_file}")
        return None
    except Exception as e:
        print(f"Error reading source file {code_file}: {e}")
        return None


def load_json_file(file_path: str) -> Optional[dict | list]:
    """Generic function to load a JSON file."""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except FileNotFoundError:
        print(f"Warning: JSON file not found at {file_path}")
        return None
    except json.JSONDecodeError:
        print(f"Warning: Could not decode JSON from {file_path}. File might be empty or malformed.")
        return None
    except Exception as e:
        print(f"Error reading JSON file {file_path}: {e}")
        return None

def get_cve_description(df: pd.DataFrame, cve_id: str) -> Optional[str]:
    """Extracts the description for a given CVE_ID from the DataFrame."""
    try:
        description_series = df[df['cve_id'] == cve_id]['description']
        if description_series.empty:
            print(f"Warning: CVE ID {cve_id} not found in the CSV data.")
            return None
        return description_series.iloc[0]
    except Exception as e:
        print(f"Error looking up CVE {cve_id}: {e}")
        return None

def extract_cve_from_filename(filename: str) -> Optional[str]:
    """Extracts CVE-ID (e.g., CVE-2007-6151) from a filename."""
    match = re.match(r"^(CVE-\d{4}-\d+)", filename)
    if match:
        return match.group(1)
    return None


if __name__ == "__main__":
    
    # --- Configure your paths ---
    # CSV file containing CVE descriptions
    CVE_INFO_CSV_PATH = "/vultrigger/res/cve_description.csv" 
    # Directory containing _diff.txt patch files
    PATCH_FILES_DIR = "/vultrigger/diff"
    # Source code directory
    CODE_DIR = "/vultrigger/src_code/novul/" 
    # Directory containing JSON files generated by the tool to be evaluated
    DETECTION_RESULTS_DIR = "/vultrigger/advtaint/gpt/novul/"
    
    # Output directories for sorted results
    CORRECT_RESULTS_DIR = "/vultrigger/res/gpt/right"
    WRONG_RESULTS_DIR = "/vultrigger/res/gpt/wrong"
    # --- ----------------------- ---


    print("--- Starting Vulnerability Result Evaluation ---")
    all_codes = glob.glob(CODE_DIR + '/*.c')

    # 1. Create output directories
    os.makedirs(CORRECT_RESULTS_DIR, exist_ok=True)
    os.makedirs(WRONG_RESULTS_DIR, exist_ok=True)

    # 2. Load CVE description data
    cve_df = load_cve_dataframe(CVE_INFO_CSV_PATH)
    if cve_df is None:
        print("Halting: Cannot proceed without CVE description data.")
        exit()

    # 3. Iterate through all JSON files to be evaluated
    for filename in os.listdir(DETECTION_RESULTS_DIR):
        if not filename.endswith(".json"):
            continue
        
        # Skip if already processed
        if os.path.exists(os.path.join(CORRECT_RESULTS_DIR, filename)) or os.path.exists(os.path.join(WRONG_RESULTS_DIR, filename)):
            continue
        print(f"\n--- Processing: {filename} ---")
        
        # 4. Extract CVE ID
        cve_id = extract_cve_from_filename(filename)
        if not cve_id:
            print(f"Skipping {filename}: Could not extract valid CVE-ID from filename.")
            continue
            
        detection_file_path = os.path.join(DETECTION_RESULTS_DIR, filename)
        
        # Define sorting target paths
        target_path_correct = os.path.join(CORRECT_RESULTS_DIR, filename)
        target_path_wrong = os.path.join(WRONG_RESULTS_DIR, filename)

        # 5. Load and filter detection results
        detection_data = load_json_file(detection_file_path)
        if not detection_data or not isinstance(detection_data, list):
            print(f"Judgment: Wrong (Reason: File is empty, malformed, or not a list)")
            shutil.copy(detection_file_path, target_path_wrong)
            continue
            
        vulnerable_findings = [
            item for item in detection_data 
            if isinstance(item, dict) and item.get("is_vulnerable") == "Vulnerable"
        ]

        # 6. Rule: If the tool does not report "Vulnerable", it is correct for the patched file
        if not vulnerable_findings:
            print(f"Judgment: Right (Reason: No 'Vulnerable' items found in file)")
            shutil.copy(detection_file_path, target_path_correct) 
            continue

        # 7. Collect Ground Truth "Evidence"
        print(f"Found {len(vulnerable_findings)} 'Vulnerable' items. Collecting Ground Truth...")
        
        cve_desc = get_cve_description(cve_df, cve_id)
        patch_info = get_patch_info(PATCH_FILES_DIR, cve_id)
        gt_analysis_data = get_code_info(all_codes, cve_id)

        # Check if evidence is complete
        if not all([cve_desc, patch_info, gt_analysis_data]):
            print(f"Judgment: Wrong (Reason: Missing Ground Truth data for {cve_id}. Cannot evaluate.)")
            print(f"  - CVE Desc found: {'Yes' if cve_desc else 'No'}")
            print(f"  - Patch found:    {'Yes' if patch_info else 'No'}")
            print(f"  - Source Code found: {'Yes' if gt_analysis_data else 'No'}")
            shutil.copy(detection_file_path, target_path_wrong)
            continue

        # 8. Format input for LLM Judgment
        try:
            tool_findings_str = json.dumps(vulnerable_findings, indent=2)
            
            # 9. Invoke LLM Judge Chain
            print(f"Invoking LLM Judge for {cve_id}...")
            judgment_result = judge_chain.invoke({
                "cve_description": cve_desc,
                "patch_info": patch_info,
                "src_code": gt_analysis_data,
                "tool_findings": tool_findings_str
            })

            # 10. Sort files based on judgment results
            print(f"Judgment: {judgment_result.verdict}")
            print(f"Reason: {judgment_result.reasoning}")
            
            if judgment_result.verdict == "Right":
                shutil.copy(detection_file_path, target_path_correct)
                print(f"Moved {filename} to {CORRECT_RESULTS_DIR}")
            else:
                shutil.copy(detection_file_path, target_path_wrong)
                print(f"Moved {filename} to {WRONG_RESULTS_DIR}")

        except Exception as e:
            print(f"!!! ERROR during LLM judgment for {cve_id}: {e} !!!")
            print(f"Skipping {filename} due to internal error.")

    print("\n--- Evaluation process complete. ---")