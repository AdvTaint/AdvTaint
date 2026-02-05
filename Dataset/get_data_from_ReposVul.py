import os, sys
import json
import re
from tqdm import tqdm

# Set working directory and path
os.chdir('/home/langgraph')
sys.path.append('/home/langgraph')

# Import custom tree-sitter tools
from tools.ts_sast import get_full_call_chain_from_code, get_func_from_code

cwe_lists = [
    'CWE-119',  'CWE-125', 'CWE-190',
    'CWE-191', 'CWE-476', 'CWE-416', 'CWE-415', 'CWE-787'
]


def find_vulnerable_functions_from_patch(patch_content: str) -> list[str]:
    """
    Parses and extracts modified function names from patch content.

    Args:
        patch_content: String containing diff information, similar to 'git diff' output.

    Returns:
        A list of all modified function names (deduplicated).
    """
    # Use a set to store function names to handle duplicates automatically.
    # For example, two non-contiguous changes within the same function will result in two hunks pointing to the same function.
    function_names = set()

    # Basic regex for function names in languages like C/C++.
    # Matches a valid identifier (including underscores) followed by an opening parenthesis '('.
    # \b((?:[a-zA-Z_]\w*::)*~?[a-zA-Z_]\w*)\s*\( 
    # This handles namespaces and destructors (e.g., `MyClass::my_method` or `~MyClass`).
    func_pattern = re.compile(r'\b((?:[a-zA-Z_]\w*::)*~?[a-zA-Z_]\w*)\s*\(')

    # Split patch content by lines
    lines = patch_content.splitlines()

    for line in lines:
        # Hunk headers start with "@@ " and end with " @@"
        if line.startswith('@@') and '@@' in line[2:]:
            # Extract the part after '@@ ... @@', which usually contains the function signature
            context = line.split('@@', 2)[-1].strip()
            
            # Search for function name patterns in the context
            match = func_pattern.search(context)
            
            if match:
                # group(1) contains the matched function name
                function_name = match.group(1)
                function_names.add(function_name)

    return list(function_names)


if __name__ == '__main__':
    cwe_reposvul = set()
    cve_dict = {}
    num = 0
    
    # Process the dataset
    with open('/reposvul/ReposVul_c.jsonl', 'r', encoding='utf-8') as f:
        print("Parsing JSONL dataset...")
        for line in tqdm(f):
            line = line.strip()
            if line:
                flag = False
                data = json.loads(line)
                commit_url = data['html_url']
                cwe_id_str = ''
                
                # Check if entry contains any of our targeted CWEs
                for cwe in data['cwe_id']:
                    if cwe in cwe_lists:
                        flag = True
                        cwe_id_str += cwe + '_'
                        cwe_reposvul.add(cwe)
                
                if not flag:
                    continue
                
                # Create a key using CVE ID and the first relevant CWE ID
                name = data['cve_id'] + '_' + cwe_id_str.split('_')[0]
                
                if name not in cve_dict:
                    cve_dict[name] = {}
                else:
                    num += 1
                
                # Iterate through file details in the commit
                for detail in data['details']:
                    patch = detail['patch']
                    code_novul = detail['code']
                    code_vul = detail['code_before']
                    file_name = detail['file_name']
                    
                    # Only process C files
                    if not file_name.endswith('.c'):
                        continue 
                        
                    if file_name in cve_dict[name]:
                        vul_functions = find_vulnerable_functions_from_patch(patch)
                        if not vul_functions:
                            continue
                        
                        # Merge and deduplicate function names
                        cve_dict[name][file_name]['patch_funcs'].extend(vul_functions)
                        cve_dict[name][file_name]['patch_funcs'] = list(set(cve_dict[name][file_name]['patch_funcs']))
                        
                        # Keep the most recent 'after' code and oldest 'before' code
                        if data['commit_date'] > cve_dict[name][file_name]['commit_date']:
                            cve_dict[name][file_name]['code_after'] = code_novul
                        if data['commit_date'] < cve_dict[name][file_name]['commit_date']:
                            cve_dict[name][file_name]['code_before'] = code_vul
                    else:
                        vul_functions = find_vulnerable_functions_from_patch(patch)
                        if not vul_functions:
                            continue
                            
                        cve_dict[name][file_name] = {
                            'patch_funcs': vul_functions,
                            'code_before': code_vul,
                            'code_after': code_novul,
                            'commit_date': data['commit_date']
                        }

        print("Extracting function call chains and saving files...")
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
                    # Ignore macros (all uppercase)
                    if vul_func.isupper() and len(vul_func) > 1:
                        continue
                        
                    # Get full call chain for vulnerable version
                    call_list_vul = get_full_call_chain_from_code(vul_func, code_vul, language='c')
                    if call_list_vul:
                        all_calls_vul += call_list_vul
                        
                    # Get full call chain for non-vulnerable version
                    call_list_novul = get_full_call_chain_from_code(vul_func, code_novul, language='c')
                    if call_list_novul:
                        all_calls_novul += call_list_novul
                
                # Remove duplicates in call chains
                all_calls_vul = list(set(all_calls_vul))
                all_calls_novul = list(set(all_calls_novul))
                
                # Aggregate source code of functions in the call chains
                for func in all_calls_vul:
                    fun_vul = get_func_from_code(func, code_vul)
                    if fun_vul:
                        before_code += fun_vul + '\n'
                        
                for func in all_calls_novul:
                    fun_novul = get_func_from_code(func, code_novul)
                    if fun_novul:
                        after_code += fun_novul + '\n'

            # Save the gathered code to respective directories
            if before_code != '' and after_code != '':
                with open(f'/reposvul/src_code/vul/{name}.c', 'w') as f1:
                    f1.write(before_code)
                with open(f'/reposvul/src_code/novul/{name}.c', 'w') as f2:
                    f2.write(after_code)

        print("Identified CWEs:", list(cwe_reposvul))
        print("Duplicate entries found:", num)