import os
import json
import glob
import re
import warnings
from typing import Dict, List, Any
from tqdm import tqdm
from collections import defaultdict

# --- LangChain Imports ---
from langchain_community.llms.ollama import Ollama
from langchain.output_parsers import PydanticOutputParser, OutputFixingParser
from langchain_core.prompts import PromptTemplate
from pydantic import BaseModel, Field

warnings.filterwarnings("ignore")

# Configuration
MODEL_NAME = "gpt-oss:20b" 
MAX_CONTEXT = 65536

# ==========================================
# 1. Output Model
# ==========================================
class VulnerabilityFinding(BaseModel):
    """The output structure for the Slice-based Baseline."""
    is_vulnerable: str = Field(description="Must be 'Vulnerable' or 'Non-Vulnerable' based on the analysis.")
    vulnerability_type: str = Field(description="If Vulnerable, return the specific type (e.g. Buffer Overflow, DMA Race Condition). If Non-Vulnerable, return 'Non-Vulnerable'.", default="Non-Vulnerable")
    reasoning: str = Field(description="Detailed step-by-step analysis of the taint path, transformations, and validation gaps.")
    vulnerable_path: str = Field(description="The specific lines of code where the vulnerability manifests (Sink).", default="N/A")

# ==========================================
# 2. LLM Initialization
# ==========================================

llm = Ollama(model=MODEL_NAME, temperature=0.1, num_ctx=MAX_CONTEXT, keep_alive='8h',base_url="http://localhost:11435")
parser = PydanticOutputParser(pydantic_object=VulnerabilityFinding)
fixer = OutputFixingParser.from_llm(parser=parser, llm=llm)

# ==========================================
# 3. Prompt Template (Integrated with User's Tool Prompt)
# ==========================================

PROMPT_TEMPLATE = """
You are a specialized vulnerability analyzer with deep expertise in taint analysis and secure coding practices.

**Core Functions**:
- Process sequential taint paths that show data flow from source to sink
- Analyze each transformation's security implications
- Detect missing input validations and sanitization
- Identify potential memory, buffer, and integer vulnerabilities
- Assess DMA operation safety
- Evaluate resource management

**Behavioral Guidelines**:
- Focus exclusively on the provided taint path sequence (Code Slice)
- Track how data transforms through each step
- Consider implicit type conversions and edge cases
- Look for validation gaps between transformations
- Evaluate final sink operation safety
- Provide deterministic **Vulnerable** or **Non-Vulnerable** classification

**Vulnerability Categories**:
- **Buffer/Integer Operations**: Overflow/Underflow potential, Sign conversion issues, Boundary checks
- **Memory Management**: Use-after-free, Double free, Memory corruption, Uninitialized access
- **DMA Operations**: Address validation, Boundary checking, Translation safety, Size verification
- **Input Processing**: Validation completeness, Sanitization effectiveness, Type safety, Range checking

**Analysis Method**:
1. Parse source-to-sink flow in the provided slice.
2. Identify critical transformations.
3. Detect validation gaps.
4. Evaluate sink safety.
5. Consider edge cases.
6. Make final decision (Vulnerable or Non-Vulnerable).

---
**Code Slice (Taint Path Sequence)**:
{code_slice}
---

**Output Instructions**:
You must output the result in a structured JSON format as defined below.
- Set `is_vulnerable` to either "Vulnerable" or "Non-Vulnerable".
- Provide your analysis in the `reasoning` field.

{format_instructions}
"""

prompt = PromptTemplate(
    template=PROMPT_TEMPLATE,
    input_variables=["code_slice"],
    partial_variables={"format_instructions": parser.get_format_instructions()}
)

chain = prompt | llm | fixer

# ==========================================
# 4. Helper Functions
# ==========================================

def get_cve_id_from_filename(filename: str) -> str:
    """
    Extracts the base CVE ID from the slice filename.
    Format: CVE-xxxx-xxxx_CWE-xxx.c_path0_enhanced.c -> CVE-xxxx-xxxx_CWE-xxx
    """
    # Regex to capture everything before ".c_path"
    match = re.match(r"(.*?)\.c_path", filename)
    if match:
        return match.group(1)
    return filename.split('.c_path')[0]

def analyze_single_slice(file_path: str) -> Dict:
    """Reads a slice file and sends it to LLM."""
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            code_content = f.read()
        
        if not code_content.strip():
            return None

        result: VulnerabilityFinding = chain.invoke({
            "code_slice": code_content
        })
        
        res_dict = result.dict()
        res_dict["slice_file"] = os.path.basename(file_path)
        return res_dict

    except Exception as e:
        print(f"[Error] Failed to analyze {os.path.basename(file_path)}: {e}")
        return None

# ==========================================
# 5. Main Execution
# ==========================================

if __name__ == "__main__":
    # Settings
    slice_dir = '/llmxcpg/queries/output/vul/slices/thread_4_enhanced_code' 
    output_dir = '/llmxcpg/queries/output/vul/detect_res'
    
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    # 1. Group Files
    all_files = glob.glob(os.path.join(slice_dir, "*_path*.c"))
    cve_groups = defaultdict(list)
    
    print(f"Scanning directory... Found {len(all_files)} slice files.")
    
    for f_path in all_files:
        filename = os.path.basename(f_path)
        cve_id = get_cve_id_from_filename(filename)
        cve_groups[cve_id].append(f_path)
        
    print(f"Grouped into {len(cve_groups)} unique CVEs.")

    # 2. Process Groups
    for cve_id, slice_files in tqdm(cve_groups.items(), desc="Processing CVEs"):
        output_json_path = os.path.join(output_dir, f"{cve_id}.json")
        
        if os.path.exists(output_json_path):
            continue
            
        cve_findings = []
        
        for slice_file in slice_files:
            finding = analyze_single_slice(slice_file)
            if finding:
                cve_findings.append(finding)
                # print output for debug
                # if finding['is_vulnerable'] == 'VULNERABLE':
                #    print(f"  [!] {os.path.basename(slice_file)} -> VULNERABLE")

        # Save results
        with open(output_json_path, 'w', encoding='utf-8') as f:
            json.dump(cve_findings, f, indent=4, ensure_ascii=False)

    print("\n--- Baseline Experiment (Slices) Complete ---")