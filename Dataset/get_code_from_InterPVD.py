import os, sys
import glob
import re
from tqdm import tqdm

# Set working directory and path
os.chdir('/home/langgraph')
sys.path.append('/home/langgraph')

# Import custom tree-sitter tools
from tools.ts_sast import get_full_call_chain_from_code, get_func_from_code, get_func_name_from_line

C_KEYWORDS = {
    "if", "for", "while", "switch", "case", "sizeof",
    "struct", "enum", "union", "return"
}

def find_vulnerable_functions(patch_content: str, code_before: str) -> list[str]:
    """
    Uses a hybrid strategy to extract modified function names from a patch.
    Strategy 1: Regex with keyword and macro filtering.
    Strategy 2: AST-based fallback using line numbers.
    """
    function_names = set()
    lines = patch_content.splitlines()

    # --- Strategy 1: Regex (Fast attempt) ---
    func_pattern = re.compile(r'\b((?:[a-zA-Z_]\w*::)*~?[a-zA-Z_]\w*)\s*\(')
    
    for line in lines:
        if line.startswith('@@') and '@@' in line[2:]:
            context = line.split('@@', 2)[-1].strip()
            match = func_pattern.search(context)
            if match:
                function_name = match.group(1)
                
                # Filter out C keywords (e.g., 'if', 'for')
                if function_name in C_KEYWORDS:
                    continue
                    
                # Filter out uppercase functional macros (e.g., 'MY_MACRO')
                if function_name.isupper() and len(function_name) > 1:
                    continue

                function_names.add(function_name)

    # --- Strategy 2: AST Fallback ---
    # Triggered if Strategy 1 fails to find valid functions
    if not function_names:
        # print(f"Strategy 1 failed, starting Strategy 2 (AST + Line Number)")
        
        hunk_pattern = re.compile(r'^@@ -(\d+)(?:,\d+)? \+\d+(?:,\d+)? @@')
        
        for line in lines:
            match = hunk_pattern.search(line)
            if match:
                line_num = int(match.group(1))
                
                # Call tree-sitter helper to get function name from line number
                func_name = get_func_name_from_line(code_before, line_num, language='c')
                
                if func_name:
                    # Apply the same filters for consistency
                    if func_name in C_KEYWORDS:
                        continue
                    if func_name.isupper() and len(func_name) > 1:
                        continue
                        
                    function_names.add(func_name)

    return list(function_names)


def find_vulnerable_functions_from_patch(patch_content: str) -> list[str]:
    """
    Parses patch content to extract modified function names using regex.
    """
    function_names = set()
    # Matches valid C/C++ identifiers followed by an opening parenthesis
    func_pattern = re.compile(r'\b((?:[a-zA-Z_]\w*::)*~?[a-zA-Z_]\w*)\s*\(')
    lines = patch_content.splitlines()

    for line in lines:
        if line.startswith('@@') and '@@' in line[2:]:
            # Extract the context part after '@@ ... @@'
            context = line.split('@@', 2)[-1].strip()
            match = func_pattern.search(context)
            if match:
                function_name = match.group(1)
                function_names.add(function_name)

    return list(function_names)

if __name__ == "__main__":
    dest_vul = '/vultrigger/src_code/vul/'
    dest_novul = '/vultrigger/src_code/novul/'
    dest_diff = '/vultrigger/diff/'
    
    all_files = glob.glob('/vultrigger/DIFF_NEW_OLD' + '/*/*')
    cve_dict = {}

    print("Processing diff files...")
    for file in tqdm(all_files):
        cve_id = file.split('/')[-1]
        diff_files = glob.glob(file + '/*.diff') 
        c_files = glob.glob(file + '/*.c') 
        
        if not c_files:
            continue

        for diff_file in diff_files:
            code_before = ''
            code_after = ''
            file_name = diff_file.split('.diff')[0]
            file_name_abs = file_name.split('/')[-1]
            
            with open(diff_file, 'r') as f1:
                patch = f1.read()
            
            for c_file in c_files:
                c_file_name = c_file.split('/')[-1]
                # Match corresponding OLD and NEW C files
                if c_file_name.startswith(file_name_abs) and c_file_name.endswith('OLD.c'):
                    with open(c_file, 'r', encoding='utf-8', errors='ignore') as f2:
                        code_before = f2.read()
                if c_file_name.startswith(file_name_abs) and c_file_name.endswith('NEW.c'):
                    with open(c_file, 'r', encoding='utf-8', errors='ignore') as f3:
                        code_after = f3.read()

            if code_before != '' and code_after != '':
                vul_functions = find_vulnerable_functions(patch, code_before)
                if not vul_functions:
                    continue
                
                name = '_'.join(file_name_abs.split('_')[:2])
                if name not in cve_dict:
                    cve_dict[name] = {}
                
                cve_dict[name][file_name_abs] = {
                    'patch_funcs': vul_functions,
                    'code_before': code_before,
                    'code_after': code_after
                }

    print("Generating function call chains and saving output...")
    for name, file_dict in tqdm(cve_dict.items()):
        if not file_dict:
            continue
            
        before_code = ''
        after_code = ''
        
        for file_name, file_detail in file_dict.items():
            code_vul = file_detail['code_before']
            code_novul = file_detail['code_after']
            vul_funcs = file_detail['patch_funcs']
            
            all_calls_vul = []
            all_calls_novul = []
            
            for vul_func in vul_funcs:
                # Filter out macros
                if vul_func.isupper() and len(vul_func) > 1:
                    continue
                
                # Get call chain for vulnerable version
                call_list_vul = get_full_call_chain_from_code(vul_func, code_vul, language='c')
                if call_list_vul:
                    all_calls_vul += call_list_vul
                
                # Get call chain for non-vulnerable version
                call_list_novul = get_full_call_chain_from_code(vul_func, code_novul, language='c')
                if call_list_novul:
                    all_calls_novul += call_list_novul
            
            # Remove duplicates
            all_calls_vul = list(set(all_calls_vul))
            all_calls_novul = list(set(all_calls_novul))
            
            # Extract function source code based on call chains
            for func in all_calls_vul:
                fun_vul = get_func_from_code(func, code_vul)
                if fun_vul:
                    before_code += fun_vul + '\n'
                    
            for func in all_calls_novul:
                fun_novul = get_func_from_code(func, code_novul)
                if fun_novul:
                    after_code += fun_novul + '\n'

        # Save the aggregated source code
        if before_code != '' and after_code != '':
            with open(os.path.join(dest_vul, f"{name}.c"), 'w') as f1:
                f1.write(before_code)
            with open(os.path.join(dest_novul, f"{name}.c"), 'w') as f2:
                f2.write(after_code)