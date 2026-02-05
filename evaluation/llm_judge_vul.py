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

class Judgment(BaseModel):
    """Structure that the LLM Judge must output"""
    verdict: Literal["Right", "Wrong"] = Field(description="Only 'Right' or 'Wrong'")
    reasoning: str = Field(description="Reasons for making this judgment, explain whether/how the results identified known vulnerabilities.")    


# --------------------------------------------------------------------------
# 2. Initialize LLM and Judge Chain
# --------------------------------------------------------------------------

# Initialize Ollama
try:
    # Note: This is the "Judge" LLM. You can use the same model as before or a stronger reasoning model.
    llm = Ollama(model="gpt-oss:120b", temperature=0, num_ctx=65536, base_url="http://localhost:11434") 
except Exception as e:
    print(f"Error initializing Ollama. Make sure Ollama is running.")
    print(f"Error: {e}")
    exit()

# Set up the parser for the Judgment model
pydantic_parser = PydanticOutputParser(pydantic_object=Judgment)  # Specifically for 'vul' (vulnerability present) cases
output_fixing_parser = OutputFixingParser.from_llm(
    parser=pydantic_parser, 
    llm=llm
)

# Prompt template for the Judge
judge_prompt_template = """
You are an expert vulnerability analysis evaluator. Your task is to determine if an expert's findings are correct.

You will be given:
1.  **Ground Truth Vulnerability:** The true details of the vulnerability, based on its CVE description, patch, and source_code.
2.  **Expert's Findings:** A list of items reported as "Vulnerable" by an expert.

**Your Goal:** Summarize the details of the vulnerability based on the "Ground Truth" and Compare the "Expert's Findings" against the vulnerability details. You must determine if **at least one** of the expert's findings correctly identifies the real vulnerability described in the Ground Truth.

-   **"Right"** means: At least one of the expert's findings (in terms of `vulnerability_type`, `reasoning`, or `vulnerable_path`) clearly and accurately matches the Ground Truth vulnerability principle.
-   **"Wrong"** means: None of the expert's findings match the Ground Truth. They are likely false positives or have found a different, unrelated vulnerability.

Each vulnerability type may have more than one, with a focus on analyzing whether the specific principles of the vulnerability are analyzed correctly!

---
**[GROUND TRUTH VULNERABILITY (The 'Answer Key')]**

**CVE Description:**
{cve_description}

**Patch File:**
{patch_info}

**Source Code:**
{src_code}

---
**[Expert'S FINDINGS (List of vulnerabilities reported as 'Vulnerable')]**

{tool_findings}

---
**[YOUR JUDGMENT]**

Based on your comparison, is the tool's result "Right" or "Wrong"? Give your reasons.
Provide your answer in a JSON format like:

{format_instructions}
"""


# Build the Judge Chain for 'vul' cases
judge_prompt = PromptTemplate(
    template=judge_prompt_template,
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
    for file in all_codes:
        name = file.split('/')[-1]
        if name.startswith(cve_id):
            code_file = file
            break

    try:
        with open(code_file, 'r', encoding='utf-8') as f:
            content = f.read()
            if not content.strip():
                print(f"Warning: Source file {code_file} is empty.")
                return "No patch information available."
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

# --------------------------------------------------------------------------
# 4. Main Execution Logic
# --------------------------------------------------------------------------
if __name__ == "__main__":
    
    # --- Please configure your paths ---
    # CSV file containing CVE descriptions
    CVE_INFO_CSV_PATH = "/vultrigger/res/cve_description.csv" 
    # Directory containing _diff.txt patch files
    PATCH_FILES_DIR = "/vultrigger/diff"
    # Directory containing source code files
    CODE_DIR = "/vultrigger/src_code/vul/" 
    # Directory containing the JSON files generated by the tool to be evaluated
    DETECTION_RESULTS_DIR = "/vultrigger/advtaint/gpt/vul/"
    
    # Output directories for sorted results
    CORRECT_RESULTS_DIR = "/vultrigger/res/gpt/right"
    WRONG_RESULTS_DIR = "/vultrigger/res/gpt/wrong"
    # --- ----------------------- ---


    print("--- Starting Vulnerability Result Evaluation ---")
    all_codes = glob.glob(CODE_DIR+'/*.c')

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
        
        # Skip if the file has already been processed
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

        # 6. Rule: If the tool does not report "Vulnerable", it is automatically judged as Wrong
        # (This is the 'vul' script, meaning these files are known to contain vulnerabilities)
        if not vulnerable_findings:
            print(f"Judgment: Wrong (Reason: No 'Vulnerable' items found in file)")
            shutil.copy(detection_file_path, target_path_wrong)
            continue

        # 7. Collect Ground Truth "Evidence"
        print(f"Found {len(vulnerable_findings)} 'Vulnerable' items. Collecting Ground Truth...")
        
        cve_desc = get_cve_description(cve_df, cve_id)
        patch_info = get_patch_info(PATCH_FILES_DIR, cve_id)
        gt_analysis_data = get_code_info(all_codes, cve_id)

        # Verify that all evidence is available
        if not all([cve_desc, patch_info, gt_analysis_data]):
            print(f"Judgment: Wrong (Reason: Missing Ground Truth data for {cve_id}. Cannot evaluate.)")
            print(f"  - CVE Desc found: {'Yes' if cve_desc else 'No'}")
            print(f"  - Patch found:    {'Yes' if patch_info else 'No'}")
            print(f"  - Source Code found: {'Yes' if gt_analysis_data else 'No'}")
            shutil.copy(detection_file_path, target_path_wrong)
            continue

        # 8. Format input for LLM judgment
        try:
            tool_findings_str = json.dumps(vulnerable_findings, indent=2)
            
            # 9. Invoke the LLM Judge Chain
            print(f"Invoking LLM Judge for {cve_id}...")
            judgment_result = judge_chain.invoke({
                "cve_description": cve_desc,
                "patch_info": patch_info,
                "src_code": gt_analysis_data,
                "tool_findings": tool_findings_str
            })

            # 10. Sort files based on the judgment result
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
            print(f"Moving {filename} to {WRONG_RESULTS_DIR} as a fallback.")
            try:
                # shutil.copy(detection_file_path, target_path_wrong)
                print('Error occurred during processing.')
            except Exception as move_e:
                print(f"Error moving file: {move_e}")

    print("\n--- Evaluation process complete. ---")