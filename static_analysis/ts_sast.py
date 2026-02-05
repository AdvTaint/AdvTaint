from tree_sitter import Language, Parser, Node
import os
import json, re
from collections import deque

KNOWN_BUFFER_INPUT_FUNCS = {
    # --- File / Socket / Standard I/O ---
    # int read(int fd, void *buf, size_t count);
    'read': [1],
    # ssize_t pread(int fd, void *buf, size_t count, off_t offset);
    'pread': [1],
    # size_t fread(void *ptr, size_t size, size_t nmemb, FILE *stream);
    'fread': [0],
    # char *fgets(char *s, int size, FILE *stream);
    'fgets': [0],
    # char *gets(char *s);  // Deprecated and dangerous, but a classic source
    'gets': [0],
    # ssize_t recv(int sockfd, void *buf, size_t len, int flags);
    'recv': [1],
    # ssize_t recvfrom(int sockfd, void *buf, size_t len, int flags, ...);
    'recvfrom': [1],

    # --- C/POSIX: String Formatting (Destination buffer) ---
    # int sprintf(char *str, const char *format, ...);
    'sprintf': [0],
    # int vsprintf(char *str, const char *format, va_list ap);
    'vsprintf': [0],
    # int snprintf(char *str, size_t size, const char *format, ...);
    'snprintf': [0],
    # int vsnprintf(char *str, size_t size, const char *format, va_list ap);
    'vsnprintf': [0],

    # --- C/POSIX: Filesystem / System Information ---
    # char *getcwd(char *buf, size_t size);
    'getcwd': [0],
    # int gethostname(char *name, size_t len);
    'gethostname': [0],
    # int getdomainname(char *name, size_t len);
    'getdomainname': [0],
    # ssize_t readlink(const char *pathname, char *buf, size_t bufsiz);
    'readlink': [1],
    # char *realpath(const char *path, char *resolved_path);
    'realpath': [1],
    # int ttyname_r(int fd, char *buf, size_t buflen);
    'ttyname_r': [1],
    # size_t confstr(int name, char *buf, size_t len);
    'confstr': [1],
    # int getlogin_r(char *buf, size_t bufsize);
    'getlogin_r': [0],

    # --- C/POSIX: Re-entrant User/Group Lookups (struct + buffer) ---
    # int getpwuid_r(uid_t uid, struct passwd *pwd, char *buf, ...);
    'getpwuid_r': [1, 2],
    # int getpwnam_r(const char *name, struct passwd *pwd, char *buf, ...);
    'getpwnam_r': [1, 2],
    # int getgrgid_r(gid_t gid, struct group *grp, char *buf, ...);
    'getgrgid_r': [1, 2],
    # int getgrnam_r(const char *name, struct group *grp, char *buf, ...);
    'getgrnam_r': [1, 2],
    
    # --- C/POSIX: Inter-Process Communication (IPC) ---
    # ssize_t mq_receive(mqd_t mqdes, char *msg_ptr, size_t msg_len, ...);
    'mq_receive': [1],
}

# --- NEW: Moved from extract_filtered_local_variables for global use ---
# Defines a rich set of integer type keywords covering most C projects
INTEGER_KEYWORDS = {
    # C Standard integer type keywords
    'int', 'long', 'short', 'char', '_Bool', 'signed', 'unsigned',
    
    # Types in <stddef.h>
    'size_t', 'ssize_t', 'ptrdiff_t',

    # Fixed-width integer types in <stdint.h>
    'int8_t', 'int16_t', 'int32_t', 'int64_t',
    'uint8_t', 'uint16_t', 'uint32_t', 'uint64_t',

    # Minimum-width integer types in <stdint.h>
    'int_least8_t', 'int_least16_t', 'int_least32_t', 'int_least64_t',
    'uint_least8_t', 'uint_least16_t', 'uint_least32_t', 'uint_least64_t',

    # Fastest minimum-width integer types in <stdint.h>
    'int_fast8_t', 'int_fast16_t', 'int_fast32_t', 'int_fast64_t',
    'uint_fast8_t', 'uint_fast16_t', 'uint_fast32_t', 'uint_fast64_t',

    # Integer types capable of holding pointers in <stdint.h>
    'intptr_t', 'uintptr_t',

    # Maximum-width integer types in <stdint.h>
    'intmax_t', 'uintmax_t',

    # Common integer type aliases in POSIX / <sys/types.h>
    'pid_t', 'uid_t', 'gid_t', 'mode_t', 'dev_t', 'off_t', 'ino_t', 'time_t', 'clock_t'
}

class UnionFind:
    """
    A Union-Find data structure used to track variable aliases (equivalence classes).
    Implements path compression and union by size for efficiency.
    """
    def __init__(self, elements):
        self.parent = {el: el for el in elements}
        self.size = {el: 1 for el in elements}

    def find(self, i):
        if self.parent[i] == i:
            return i
        # Path compression
        self.parent[i] = self.find(self.parent[i])
        return self.parent[i]

    def union(self, i, j):
        root_i = self.find(i)
        root_j = self.find(j)
        if root_i != root_j:
            # Union by size
            if self.size[root_i] < self.size[root_j]:
                root_i, root_j = root_j, root_i
            self.parent[root_j] = root_i
            self.size[root_i] += self.size[root_j]

    def get_set(self, i):
        """Returns the entire equivalence set containing element i."""
        root = self.find(i)
        return {el for el in self.parent if self.find(el) == root}

def traverse_outfunc(node, res = None):
    if res is None:
        res = list()
    if node.type == 'function_definition':
        res.append(node)
    else:
        if isinstance(node.children, list):
            for n in node.children:
                res.extend(traverse_outfunc(n, None))
    return res

def get_func_name(node: Node) -> str | None:
    """
    A more robust function to find the function name from a function_definition node.
    It traverses the AST to find the identifier within the declarator field.
    """
    if node.type != 'function_definition':
        return None

    # Tree-sitter's C grammar usually nests the name inside a 'declarator' field.
    declarator_node = node.child_by_field_name('declarator')
    if not declarator_node:
        return None

    # The actual function name is usually an 'identifier' node. We need to find it 
    # inside the declarator because it might be nested (e.g., in pointer_declarator).
    
    # Use a queue for breadth-first search inside the declarator
    queue = [declarator_node]
    while queue:
        current = queue.pop(0)
        if current.type == 'identifier':
            return current.text.decode('utf-8')
        # Add children to queue to continue search
        queue.extend(current.children)
        
    return None


def traverse_calls_in_node(node, res=None):
    if res is None: res = []
    if node.type == 'call_expression':
        identifier_node = node.children[0]
        call_name = identifier_node.text.decode('utf-8')
        res.append(call_name)
    
    for child in node.children:
        traverse_calls_in_node(child, res)
    return list(set(res))

def get_all_function_names_from_file(file_path, language='c'):
    try:
        LANGUAGE = Language('/tree_sitter/build/my-languages.so', language)
        parser = Parser()
        parser.set_language(LANGUAGE)
        with open(file_path, 'r') as f:
            source_code = f.read()
        tree = parser.parse(source_code.encode('utf-8'))
        function_nodes = traverse_outfunc(tree.root_node)
        all_names = [name for func_node in function_nodes if (name := get_func_name(func_node))]
        return all_names
    except FileNotFoundError:
        print(f"[Error] File not found: {file_path}")
        return []
    except Exception as e:
        print(f"[Error] Error parsing file {file_path}: {e}")
        return []

def get_code_from_file(function_name, file_path, language='c'):
    try:
        LANGUAGE = Language('/tree_sitter/build/my-languages.so', language)
        parser = Parser()
        parser.set_language(LANGUAGE)
        with open(file_path, 'r', encoding='utf8') as f:
            source_code = f.read()
        tree = parser.parse(bytes(source_code,"utf8"))
        function_nodes = traverse_outfunc(tree.root_node)
        for func_node in function_nodes:
            if get_func_name(func_node) == function_name:
                return func_node.text.decode('utf-8', errors='ignore')
        return None
    except FileNotFoundError:
        return None
    except Exception as e:
        print(f"[Error] Error parsing file {file_path}: {e}")
        return None
    
def get_func_from_code(function_name, source_code, language='c'):
    try:
        LANGUAGE = Language('/tree_sitter/build/my-languages.so', language)
        parser = Parser()
        parser.set_language(LANGUAGE)
        tree = parser.parse(bytes(source_code,"utf8"))
        function_nodes = traverse_outfunc(tree.root_node)
        for func_node in function_nodes:
            if get_func_name(func_node) == function_name:
                return func_node.text.decode('utf-8', errors='ignore')
        return None
    except FileNotFoundError:
        return None
    except Exception as e:
        print(f"[Error] Error parsing code: {e}")
        return None    

def get_code_from_repository(project_path, target_func_name, language='c'):
    lang_extensions = {
        'c': ['.c', '.h'],
        'cpp': ['.cpp', '.hpp', '.cxx', '.h']
    }
    found_functions = []
    for root, dirs, files in os.walk(project_path):
        for file_name in files:
            if any(file_name.endswith(ext) for ext in lang_extensions.get(language, [])):
                file_path = os.path.join(root, file_name)
                content = get_code_from_file(target_func_name, file_path, language)
                if content:
                    print(f"[*] Found target function '{target_func_name}' in file: {file_path}")
                    result = {'file_path': file_path, 'code': content}
                    found_functions.append(result)
    return found_functions

def get_all_function_names_in_project(project_path, language='c'):
    # Used to store all function names in a set, automatically handling duplicates
    all_project_funcs_set = set()
    
    # Determine file extensions based on language
    lang_extensions = {
        'c': ['.c', '.h'],
        'cpp': ['.cpp', '.hpp', '.cxx', '.h']
    }
    
    # Recursively traverse project directory
    print(f"--- Starting project scan: {project_path} ---")
    for root, dirs, files in os.walk(project_path):
        for file_name in files:
            # Check if file extension matches
            if any(file_name.endswith(ext) for ext in lang_extensions.get(language, [])):
                file_path = os.path.join(root, file_name)
                print(f"Processing file: {file_path}")
                
                # Call existing function to get all function names from a single file
                names_in_file = get_all_function_names_from_file(file_path, language)
                
                # If function names found, add them to the global set
                if names_in_file:
                    all_project_funcs_set.update(names_in_file)
    
    print("--- Scan complete ---")
    # Convert set to sorted list for stable and readable output
    return sorted(list(all_project_funcs_set))


def _parse_file_and_build_graph_data(file_path: str, language: str = 'c'):
    """
    Internal helper function encapsulating common logic for file parsing, 
    function extraction, and root node identification.
    Returns core data structures required for subsequent processing.
    """
    # Assuming your .so path is as follows, please modify as needed
    so_path = '/tree_sitter/build/my-languages.so'
    if not os.path.exists(so_path):
        raise FileNotFoundError(f"Tree-sitter library not found at {so_path}. Please build it first.")
        
    C_LANGUAGE = Language(so_path, language)
    parser = Parser()
    parser.set_language(C_LANGUAGE)

    with open(file_path, 'r', encoding='utf8') as f:
        source_code = f.read()
    tree = parser.parse(bytes(source_code, "utf8"))
    
    all_func_nodes = traverse_outfunc(tree.root_node)
    
    defined_funcs_map = {name: n for n in all_func_nodes if (name := get_func_name(n))}
    all_defined_names = set(defined_funcs_map.keys())
    
    all_internal_callees = set()
    for func_node in defined_funcs_map.values():
        calls = traverse_calls_in_node(func_node)
        for call in calls:
            if call in all_defined_names:
                all_internal_callees.add(call)
                
    root_funcs = sorted(list(all_defined_names - all_internal_callees))
    # If no explicit root (e.g., all functions call each other), treat all as potential entries
    if not root_funcs and all_defined_names:
        root_funcs = sorted(list(all_defined_names))

    return defined_funcs_map, all_defined_names, root_funcs



def generate_rooted_call_graphs(file_path: str, language: str = 'c'):
    """
    Generates independent adjacency list call graphs for each root node in the specified file.
    Recommended format for logically isolated analysis.

    :return: A dictionary where keys are root function names and values are reachable subgraphs.
             Example: {'main': {'main': ['a'], 'a': ['b']}, 'api': {'api': ['c']}}
    """
    try:
        defined_funcs_map, all_defined_names, root_funcs = _parse_file_and_build_graph_data(file_path, language)
        
        # Step 1: Generate a complete adjacency list containing all relationships
        full_adjacency_list = {}
        for func_name, func_node in defined_funcs_map.items():
            callees = traverse_calls_in_node(func_node)
            internal_callees = sorted(list(set([c for c in callees if c in all_defined_names])))
            full_adjacency_list[func_name] = internal_callees

        # Step 2: Build independent subgraphs via BFS starting from each root node
        rooted_graphs = {}
        for root in root_funcs:
            sub_graph = {}
            queue = deque([root])
            visited = {root}
            
            while queue:
                current_func = queue.popleft()
                
                # Get direct calls for current function from full graph
                direct_callees = full_adjacency_list.get(current_func, [])
                sub_graph[current_func] = direct_callees
                
                for callee in direct_callees:
                    if callee not in visited:
                        visited.add(callee)
                        queue.append(callee)
            
            rooted_graphs[root] = sub_graph
        
        return rooted_graphs

    except Exception as e:
        print(f"Error occurred while processing file {file_path}: {e}")
        return None




def _generate_markdown_tree_recursive(func_name, defined_funcs_map, all_defined_names, visited_path, indent_level):
    indent = "  " * indent_level
    if func_name in visited_path:
        return f"{indent}- {func_name} (Recursive Call)\n"
    result_str = f"{indent}- {func_name}\n"
    new_visited_path = visited_path | {func_name}
    func_body_node = defined_funcs_map.get(func_name)
    if not func_body_node:
        return result_str
    callees = traverse_calls_in_node(func_body_node)
    internal_callees = sorted([c for c in callees if c in all_defined_names])
    for callee_name in internal_callees:
        result_str += _generate_markdown_tree_recursive(
            callee_name, defined_funcs_map, all_defined_names, new_visited_path, indent_level + 1
        )
    return result_str

def generate_markdown_call_graph(file_path, language='c'):
    """
    Generates a structured function call graph (Markdown format) for the specified file.
    """
    try:
        # Directly call internal helper to get required data
        defined_funcs_map, all_defined_names, root_funcs = _parse_file_and_build_graph_data(file_path, language)

        print(f"Functions defined in file: {list(sorted(all_defined_names))}")
        print(f"Call graph root nodes found: {root_funcs}")

        markdown_graphs_map = {}
        for root_name in root_funcs:
            markdown_tree = _generate_markdown_tree_recursive(
                root_name, defined_funcs_map, all_defined_names, visited_path=set(), indent_level=0
            )
            markdown_graphs_map[root_name] = markdown_tree.strip()
            
        return markdown_graphs_map

    except Exception as e:
        print(f"Error occurred while processing file {file_path}: {e}")
        return None


def is_declarator_node(node: Node) -> bool:
    """
    Helper function to determine if an AST node is a declarator.
    Defined based on tree-sitter C grammar to identify variable names and modifiers.
    """
    return node.type in [
        'identifier',
        'pointer_declarator',
        'array_declarator',
        'init_declarator', # e.g., for `var = 1`
        'parenthesized_declarator'
    ]


def extract_filtered_local_variables(function_code: str, language: str = 'c') -> list[str]:
    """
    [MODIFIED VERSION]
    Uses AST traversal to extract local variable names of specified types (pointer, array, integer).
    - Returns only variable names, not types.
    - Filters out variables that are not of the specified types.
    """
    source_bytes = bytes(function_code, "utf8")

    LANGUAGE = Language('/tree_sitter/build/my-languages.so', language)
    parser = Parser()
    parser.set_language(LANGUAGE)
    tree = parser.parse(source_bytes)
    
    results = []
    
    def find_nodes_by_type(node: Node, target_type: str, found_nodes: list):
        if node.type == target_type:
            found_nodes.append(node)
        for child in node.children:
            find_nodes_by_type(child, target_type, found_nodes)

    function_bodies = []
    find_nodes_by_type(tree.root_node, 'compound_statement', function_bodies)
    if not function_bodies:
        return []

    main_body = function_bodies[0]

    declaration_nodes = []
    find_nodes_by_type(main_body, 'declaration', declaration_nodes)

    for decl_node in declaration_nodes:
        
        first_declarator_node = None
        for child in decl_node.children:
            if is_declarator_node(child):
                type_node_check = decl_node.child_by_field_name('type')
                if child != type_node_check:
                    first_declarator_node = child
                    break
        
        if not first_declarator_node:
            continue

        start_byte = decl_node.start_byte
        end_byte = first_declarator_node.start_byte
        full_type_text = source_bytes[start_byte:end_byte].decode('utf8').strip()

        all_declarators = [child for child in decl_node.children if is_declarator_node(child) and child != decl_node.child_by_field_name('type')]
        
        for declarator_node in all_declarators:
            full_declarator_text = declarator_node.text.decode('utf8')
            # Clean part with initialization, e.g., "var = 0" -> "var"
            clean_declarator = full_declarator_text.split('=')[0].strip()
            
            if not clean_declarator:
                continue

            # --- NEW LOGIC: Determine if variable type meets requirements ---
            is_pointer = '*' in clean_declarator
            is_array = '[' in clean_declarator
            
            # Use split() to divide type string for accurate keyword matching
            type_tokens = set(full_type_text.replace("const", "").replace("static", "").strip().split())
            is_integer = False
            # Only consider it a pure integer type if it's not a pointer or array
            if not is_pointer and not is_array:
                if type_tokens.intersection(INTEGER_KEYWORDS): # Use global keywords
                    is_integer = True

            # --- If target type, extract variable name ---
            if is_pointer or is_array or is_integer:
                # 1. Remove array portion, e.g., "name[IFNAMSIZ]" -> "name"
                var_name = clean_declarator.split('[')[0]
                # 2. Remove pointer portion, e.g., "*s" -> "s"
                var_name = var_name.lstrip(' *')
                # 3. Final whitespace cleaning
                var_name = var_name.strip()

                if var_name:
                    results.append(var_name)

    return sorted(list(set(results)))



def extract_local_variables(function_code: str, language: str = 'c') -> list[str]:
    """
    Uses AST traversal to extract local variables and their full types.
    - Employs location-based logic to correctly handle const/static type modifiers.
    - Resolves all known issues.
    """
    source_bytes = bytes(function_code, "utf8")

    LANGUAGE = Language('/tree_sitter/build/my-languages.so', language)
    parser = Parser()
    parser.set_language(LANGUAGE)
    tree = parser.parse(source_bytes)
    
    results = []
    
    def find_nodes_by_type(node: Node, target_type: str, found_nodes: list):
        if node.type == target_type:
            found_nodes.append(node)
        for child in node.children:
            find_nodes_by_type(child, target_type, found_nodes)

    function_bodies = []
    find_nodes_by_type(tree.root_node, 'compound_statement', function_bodies)
    if not function_bodies:
        return []

    main_body = function_bodies[0]

    declaration_nodes = []
    find_nodes_by_type(main_body, 'declaration', declaration_nodes)

    for decl_node in declaration_nodes:
        
        # --- Step 1: Find first declarator node as split point for "type" and "variable" ---
        first_declarator_node = None
        for child in decl_node.children:
            # Skip type nodes and other non-declarator nodes
            if is_declarator_node(child):
                 # Ensure this declarator isn't part of the type (e.g., typedef MyInt int;)
                 # In local variable declarations, the first declarator won't be the 'type' field
                 type_node_check = decl_node.child_by_field_name('type')
                 if child != type_node_check:
                    first_declarator_node = child
                    break
        
        if not first_declarator_node:
            continue

        # --- Step 2: Extract full type string ---
        # Full type = All text from start of declaration to start of first declarator
        start_byte = decl_node.start_byte
        end_byte = first_declarator_node.start_byte
        full_type_text = source_bytes[start_byte:end_byte].decode('utf8').strip()

        # --- Step 3: Iterate through all declarators and concatenate with full type ---
        all_declarators = [child for child in decl_node.children if is_declarator_node(child) and child != decl_node.child_by_field_name('type')]
        
        for declarator_node in all_declarators:
            full_declarator_text = declarator_node.text.decode('utf8')
            clean_declarator = full_declarator_text.split('=')[0].strip()
            
            # Filter out empty or invalid declarators
            if not clean_declarator:
                continue

            final_declaration = f"{full_type_text} {clean_declarator}"
            results.append(final_declaration)

    return sorted(list(set(results)))


def get_funcnames_from_file(file_path, language='c'):
    try:
        res=[]
        LANGUAGE = Language('/tree_sitter/build/my-languages.so', language)
        parser = Parser()
        parser.set_language(LANGUAGE)
        with open(file_path, 'r', encoding='utf8') as f:
            source_code = f.read()
        tree = parser.parse(bytes(source_code,"utf8"))
        function_nodes = traverse_outfunc(tree.root_node)
        for func_node in function_nodes:
            res.append(get_func_name(func_node))
        return res
    except FileNotFoundError:
        return []
    except Exception as e:
        print(f"[Error] Error parsing file {file_path}: {e}")
        return []


def _parse_code_and_get_funcs(source_code: str, language: str = 'c') -> dict:
    """
    Helper function: Directly parses source code string and returns mapping of 
    function names to their AST nodes. This is a non-file IO version of _parse_file_and_build_graph_data.
    """
    so_path = '/tree_sitter/build/my-languages.so'
    if not os.path.exists(so_path):
        raise FileNotFoundError(f"Tree-sitter library not found at {so_path}.")
        
    LANGUAGE = Language(so_path, language)
    parser = Parser()
    parser.set_language(LANGUAGE)

    tree = parser.parse(bytes(source_code, "utf8"))
    
    all_func_nodes = traverse_outfunc(tree.root_node)
    
    defined_funcs_map = {name: n for n in all_func_nodes if (name := get_func_name(n))}
    return defined_funcs_map

def get_full_call_chain_from_code(
    target_function_name: str, 
    full_file_code: str, 
    language: str = 'c', 
    max_callee_depth: int = 4, 
    max_caller_depth: int = 3  
) -> list[str]:
    """
    Searches for a complete, recursive bidirectional call chain for a specified function 
    within a full code text. Includes upstream callers and downstream callees with depth limits.

    Args:
        target_function_name (str): Target function name obtained from a patch.
        full_file_code (str): Full file code text containing the target function.
        language (str): Programming language. Defaults to 'c'.
        max_callee_depth (int): Max depth to trace downstream callees. Defaults to 4. -1 for infinite.
        max_caller_depth (int): Max depth to trace upstream callers. Defaults to 3. -1 for infinite.

    Returns:
        list[str]: Flattened list containing all function names in the chain (deduplicated and sorted).
    """
    try:
        # Step 1: Parse code and build function node map
        defined_funcs_map = _parse_code_and_get_funcs(full_file_code, language)
        
        if target_function_name not in defined_funcs_map:
            print(f"[Error] Target function '{target_function_name}' not found in provided code.")
            return []

        # Step 2: Build Callee and Caller graphs
        callee_graph = {}
        caller_graph = {}
        all_defined_func_names = set(defined_funcs_map.keys())

        for func_name, func_node in defined_funcs_map.items():
            callees = traverse_calls_in_node(func_node)
            internal_callees = [c for c in callees if c in all_defined_func_names]
            
            if internal_callees:
                callee_graph[func_name] = internal_callees
            
            for callee in internal_callees:
                caller_graph.setdefault(callee, []).append(func_name)
        
        print("[*] Bidirectional call graph within file constructed.")

        full_chain_set = {target_function_name}

        # Step 3: Upstream tracing (Callers) with depth limit
        # Queue item format: (function_name, current_depth)
        caller_queue = deque([(target_function_name, 0)]) 
        visited_callers = {target_function_name}
        
        while caller_queue:
            current_func, current_depth = caller_queue.popleft()
            
            # Check depth limit
            if max_caller_depth >= 0 and current_depth >= max_caller_depth:
                continue

            callers = caller_graph.get(current_func, [])
            for caller in callers:
                if caller not in visited_callers:
                    visited_callers.add(caller)
                    full_chain_set.add(caller)
                    caller_queue.append((caller, current_depth + 1))

        print(f"[*] Upstream caller tracing complete, found {len(visited_callers)} related functions.")

        # Step 4: Downstream tracing (Callees)
        callee_queue = deque([(target_function_name, 0)]) 
        visited_callees = {target_function_name}
        
        while callee_queue:
            current_func, current_depth = callee_queue.popleft()
            
            if max_callee_depth >= 0 and current_depth >= max_callee_depth:
                continue

            callees = callee_graph.get(current_func, [])
            for callee in callees:
                if callee not in visited_callees:
                    visited_callees.add(callee)
                    full_chain_set.add(callee)
                    callee_queue.append((callee, current_depth + 1))
        print(f"[*] Downstream callee tracing complete, found {len(visited_callees)} related functions.")

        print(f"[*] Full call chain tracing complete, total {len(full_chain_set)} unique functions found.")

        return sorted(list(full_chain_set))

    except Exception as e:
        print(f"[Error] An error occurred during analysis: {e}")
        return []

def _get_enclosing_statement(node: Node) -> Node | None:
    statement_types = {
        "expression_statement", "declaration", "if_statement", "while_statement",
        "for_statement", "do_statement", "return_statement", "switch_statement",
        "case_statement", "labeled_statement"
    }
    current = node
    while current:
        if current.type in statement_types:
            return current
        current = current.parent
    return None

def _get_variable_c_type(root_node: Node, variable_name: str) -> str:
    so_path = '/tree_sitter/build/my-languages.so'
    LANGUAGE = Language(so_path, 'c')
    query_string = f"""(identifier) @variable"""
    query = LANGUAGE.query(query_string)
    captures = query.captures(root_node)
    variable_nodes = [node for node, tag in captures if node.text.decode('utf8') == variable_name]
    
    # --- MODIFIED: Prioritize declarations then parameters ---
    
    # 1. Prioritize local variable declarations
    for identifier_node in variable_nodes:
        declaration_node = identifier_node
        # Move up to find declaration node
        while declaration_node:
            if declaration_node.type == 'declaration':
                break
            if declaration_node.type == 'function_definition': # Out of scope for local variable
                declaration_node = None
                break
            declaration_node = declaration_node.parent
            
        if not declaration_node: continue
        
        base_type_node = declaration_node.child_by_field_name('type')
        if not base_type_node: continue
        base_type = base_type_node.text.decode('utf8')
        
        # Find the specific declarator containing this identifier_node
        target_declarator_node = None
        
        for child in declaration_node.children:
            if is_declarator_node(child): 
                # Ensure this declarator isn't the type itself
                if child == base_type_node:
                    continue
                    
                q = [child]
                found = False
                while q:
                    curr = q.pop(0)
                    if curr == identifier_node:
                        found = True
                        break
                    q.extend(curr.children)
                if found:
                    target_declarator_node = child
                    break
                    
        if not target_declarator_node: continue
        
        declarator_text = target_declarator_node.text.decode('utf8').split('=')[0].strip()
        modifiers = declarator_text.replace(variable_name, "").strip()
        # Combine type
        full_type = f"{base_type} {modifiers}" if modifiers else base_type
        return re.sub(r'\s+', ' ', full_type).strip() # Clean redundant spaces

    # 2. If no local declaration found, check if it's a function parameter
    param_info = get_parameter_info(root_node, -1, variable_name) # Use -1 and name to search
    if param_info:
        return param_info["type"]
        
    return "unknown_type"

def get_parameter_info(root_node: Node, param_index: int, param_name: str | None = None) -> dict | None:
    # --- MODIFIED: Allows search by index or name ---
    param_list_query_str = "(parameter_list) @params"
    so_path = '/tree_sitter/build/my-languages.so'
    LANGUAGE = Language(so_path, 'c')
    query = LANGUAGE.query(param_list_query_str)
    captures = query.captures(root_node)
    
    param_list_node = None
    for node, tag in captures:
        ancestor, is_in_func_def = node, False
        while ancestor:
            if ancestor.type == 'function_definition':
                is_in_func_def = True
                break
            ancestor = ancestor.parent
        if is_in_func_def:
            param_list_node = node
            break
            
    if not param_list_node: return None
    
    param_nodes = [child for child in param_list_node.children if child.type == 'parameter_declaration']
    
    target_param_node = None
    if param_name:
        # --- Search by name ---
        for node in param_nodes:
            current_var_name = ""
            param_name_node = node.child_by_field_name('declarator')
            if param_name_node:
                q = [param_name_node]
                while q:
                    curr = q.pop(0)
                    if curr.type == 'identifier':
                        current_var_name = curr.text.decode('utf8')
                        break
                    q.extend(curr.children)
            if current_var_name == param_name:
                target_param_node = node
                break
    elif param_index >= 0:
        # --- Search by index ---
        if param_index >= len(param_nodes): return None
        target_param_node = param_nodes[param_index]
    
    if not target_param_node: return None

    # --- Extract name and type ---
    variable_name = ""
    param_name_node = target_param_node.child_by_field_name('declarator')
    if param_name_node:
        q = [param_name_node]
        while q:
            curr = q.pop(0)
            if curr.type == 'identifier':
                variable_name = curr.text.decode('utf8')
                break
            q.extend(curr.children)
            
    if not variable_name: 
        # Might be an unnamed parameter like `int`
        if param_name: return None 
        variable_name = f"[unnamed_param_{param_index}]"

    full_text = target_param_node.text.decode('utf8')
    
    # Use declarator's start position to split type and name
    declarator_start_byte = param_name_node.start_byte if param_name_node else target_param_node.end_byte
    type_end_byte = declarator_start_byte - target_param_node.start_byte
    param_type_text = full_text[:type_end_byte].strip()

    # If no declarator (e.g., int), type is all text
    if not param_name_node:
        param_type_text = full_text.strip()
        
    # --- MODIFIED: Robust type extraction ---
    # Extract declarator text (e.g., "*s", "s[]", "**s")
    declarator_text = param_name_node.text.decode('utf8') if param_name_node else ""
    # Remove variable name
    modifiers = declarator_text.replace(variable_name, "").strip()
    # Combine
    param_type = f"{param_type_text} {modifiers}" if modifiers else param_type_text
    param_type = re.sub(r'\s+', ' ', param_type).strip()
    
    return {"name": variable_name, "type": param_type}


def _find_control_dependencies(sink_node: Node) -> list[str]:
    """
    Starts from a critical Sink node and traverses the AST upwards, 
    searching for two types of dependencies on each level:
    1. Nested Control (Parent): if (A) { SINK } -> depends on A
    2. Guard Clause (Preceding Sibling): if (B) return; SINK; -> depends on !(B)
    """
    controlling_conditions = set()
    
    # We start traversal from the statement containing the SINK
    current_node = _get_enclosing_statement(sink_node)
    if not current_node:
        current_node = sink_node # Fallback

    while current_node:
        
        parent = current_node.parent
        if not parent:
            break
            
        # 1. Check for "Guard Clauses" (preceding siblings)
        # Check all *preceding siblings* of `current_node` in its parent block
        if parent.type == 'compound_statement':
            for child_statement in parent.children:
                # 1a. Stop once we reach the current node
                if child_statement == current_node:
                    break
                
                # 1b. Check if this sibling statement is an 'if' guard
                if child_statement.type == 'if_statement':
                    # Guard clause shouldn't have an else
                    if child_statement.child_by_field_name('alternative'):
                        continue

                    body = child_statement.child_by_field_name('consequence')
                    if not body: body = child_statement.child_by_field_name('body')
                    if not body: continue

                    # 1c. Check if body *ends with* an exit statement
                    is_guard_body = False
                    exit_types = {'return_statement', 'break_statement', 'continue_statement'}
                    
                    if body.type in exit_types:
                        # Pattern 1: if (c) break;
                        is_guard_body = True
                    elif body.type == 'compound_statement' and body.named_child_count > 0:
                        # Pattern 2: if (c) { ...; break; }
                        last_statement_in_body = body.named_children[-1]
                        if last_statement_in_body.type in exit_types:
                            is_guard_body = True
                    
                    # 1d. If it is a guard...
                    if is_guard_body:
                        condition_node = child_statement.child_by_field_name('condition')
                        if condition_node:
                            # SINK execution implies guard condition was *false*
                            condition_text = condition_node.text.decode('utf8')
                            
                            # Cleanup logic
                            if condition_text.startswith('(') and condition_text.endswith(')'):
                                 inner_text = condition_text[1:-1]
                                 if not inner_text.split() or inner_text.split()[0] not in INTEGER_KEYWORDS:
                                     condition_text = inner_text
                                     
                            controlling_conditions.add(f"!({condition_text})")

        # 2. Check "Nested Control" (Parent node)
        # Check if `current_node` is inside the body of `parent`
        control_node_type = parent.type
        if control_node_type in {"if_statement", "while_statement", "for_statement", "switch_statement"}:
            
            body_node = parent.child_by_field_name('body')
            if not body_node and control_node_type == 'if_statement':
                body_node = parent.child_by_field_name('consequence')
            
            if body_node and \
               current_node.start_byte >= body_node.start_byte and \
               current_node.end_byte <= body_node.end_byte:
                
                # Found nesting! Extract condition
                condition_node = parent.child_by_field_name('condition')
                
                if condition_node:
                    condition_text = condition_node.text.decode('utf8')
                    if control_node_type == 'switch_statement':
                        controlling_conditions.add(f"switch ({condition_text})")
                    else:
                        controlling_conditions.add(condition_text)
                elif control_node_type == 'for_statement':
                    l_paren = parent.child(1)
                    r_paren = body_node.prev_sibling
                    if l_paren and r_paren and l_paren.type == '(':
                         full_cond_text = parent.text[l_paren.start_byte:r_paren.end_byte].decode('utf8')
                         controlling_conditions.add(f"for {full_cond_text}")
                    else:
                        controlling_conditions.add("for (...)")
            
        # 3. Move upwards
        if parent.type == 'function_definition':
            break
            
        current_node = parent # We traverse parent *statements*
        
    return sorted(list(controlling_conditions))

def _classify_sink(node: Node, variable_c_type: str) -> tuple[str, Node] | None:
    """
    Implements expert-defined, vulnerability-oriented, hierarchical Sink classification rules.
    
    Args:
        node (Node): The `identifier` node of the found tainted variable.
        variable_c_type (str): The C type string (e.g., "char *", "int").
        
    Returns:
        tuple[str, Node] | None: (Sink Category, Critical Sink Node), or None if benign or a Source.
    """
    
    # [Helper] Type guessing
    base_type_tokens = set(variable_c_type.replace("const", "").replace("static", "").strip().split())
    is_pointer_or_array = '*' in variable_c_type or '[' in variable_c_type
    is_integer = False
    if not is_pointer_or_array:
        if base_type_tokens.intersection(INTEGER_KEYWORDS):
            is_integer = True
    
    parent = node.parent
    if not parent:
        return None

    # --- Rule 0 (Exclusion Rule - Non-Sink) ---
    if parent.type == 'assignment_expression' and parent.child_by_field_name('left') == node:
        return None 

    # --- Rule 1 (Generic Rule: Function Call - High Priority) ---
    ancestor = node
    while ancestor and ancestor.type != 'function_definition':
        if ancestor.type == 'argument_list':
            call_expression_node = ancestor.parent
            if call_expression_node and call_expression_node.type == 'call_expression':
                
                # --- EXCLUSION LOGIC FOR KNOWN SOURCES ---
                # Check if this call is a known Source function and variable is its buffer argument
                func_name_node = call_expression_node.child_by_field_name('function')
                if func_name_node:
                    func_name = func_name_node.text.decode('utf8')
                    if func_name in KNOWN_BUFFER_INPUT_FUNCS:
                        arg_list_node = call_expression_node.child_by_field_name('arguments')
                        if arg_list_node:
                            args = [arg for arg in arg_list_node.children if arg.is_named]
                            known_buffer_indices = KNOWN_BUFFER_INPUT_FUNCS[func_name]
                            for idx in known_buffer_indices:
                                if idx < len(args):
                                    if args[idx] == node:
                                        return None # This is a Source, not a Sink
                                        
                return "Function Call", call_expression_node 
            break 
        ancestor = ancestor.parent
    
    # --- Rule 2 (Specific Rules: Pointer / Array - Non-call Sink) ---
    if is_pointer_or_array:
        # Rule 2.A: Memory Dereference (NPD / UAF)
        
        # Pattern 1: *node
        if parent.type == 'pointer_expression' and parent.child(1) == node:
            return "Dereference", parent 
        
        # Pattern 2: node->field
        if parent.type == 'field_expression' and parent.child_by_field_name('argument') == node:
            return "Dereference", parent
            
        # Pattern 3: Check if parent expression is dereferenced (e.g., *(node++) / *(node+1))
        grandparent = parent.parent
        if grandparent and grandparent.type == 'pointer_expression' and grandparent.child(1) == parent:
            return "Dereference", grandparent

        # Rule 2.B: Array Base Access (NPD / UAF / OOB Base)
        if parent.type == 'subscript_expression' and parent.child_by_field_name('argument') == node:
            return "Array Base", parent
            
        # Rule 2.C: Array Index (OOB Read/Write)
        if parent.type == 'subscript_expression' and parent.child_by_field_name('index') == node:
            return "Array Index", parent

    # --- Rule 3 (Specific Rules: Integer - Non-call Sink) ---
    if is_integer:
        # Rule 3.A: Integer Arithmetic (Integer Overflow)
        if parent.type == 'binary_expression':
            op_node = parent.child(1)
            if op_node and op_node.type in {'+', '-', '*', '/', '%', '<<', '>>'}:
                 return "Integer Arithmetic", parent
        
        if parent.type == 'unary_expression':
             op_node = parent.child(0)
             if op_node and op_node.type in {'-'}:
                 return "Integer Arithmetic", parent
                 
        if parent.type == 'update_expression': 
            return "Integer Arithmetic", parent
            
        if parent.type == 'assignment_expression':
            op_node = parent.child(1)
            if op_node and op_node.type in {'+=', '-=', '*=', '/=', '%=', '<<=', '>>='}:
                return "Integer Arithmetic", parent
                        
        # Rule 3.B: Array Index (OOB Read/Write)
        if parent.type == 'subscript_expression' and parent.child_by_field_name('index') == node:
            return "Array Index", parent

    # --- Default: Benign use ---
    return None


def _pre_analyze_and_build_context(function_code: str, language: str = 'c') -> dict:
    """
    Stage 1: Pre-analyze function code to build context including 
    alias analysis and generic taint sources. A taint source is defined as any 
    variable assigned or modified via a function call.
    """
    so_path = '/tree_sitter/build/my-languages.so'
    LANGUAGE = Language(so_path, language)
    parser = Parser()
    parser.set_language(LANGUAGE)
    tree = parser.parse(bytes(function_code, "utf8"))
    root_node = tree.root_node

    # 1. Extract all local variable names to initialize Union-Find
    local_vars = extract_filtered_local_variables(function_code, language)
    uf = UnionFind(local_vars)
    
    high_quality_sources = {} # var_name -> source_info

    # 2. Traverse AST to discover aliases and high-quality taint sources
    q = deque([root_node])
    while q:
        node = q.popleft()

        # --- Alias Analysis: Find y = x; ---
        if node.type == 'assignment_expression':
            left_node = node.child_by_field_name('left')
            right_node = node.child_by_field_name('right')
            if left_node and right_node and left_node.type == 'identifier' and right_node.type == 'identifier':
                var_left = left_node.text.decode('utf8')
                var_right = right_node.text.decode('utf8')
                if var_left in uf.parent and var_right in uf.parent:
                    uf.union(var_left, var_right)

        if node.type == 'call_expression':
            func_name_node = node.child_by_field_name('function')
            func_name = func_name_node.text.decode('utf8') if func_name_node else "[unknown_function]"
            
            enclosing_statement = _get_enclosing_statement(node)
            if not enclosing_statement: continue

            # --- Smart extraction of Source code snippet ---
            code_snippet = None
            control_flow_types = {"if_statement", "while_statement", "for_statement", "switch_statement"}

            if enclosing_statement.type in control_flow_types:
                condition_node = enclosing_statement.child_by_field_name('condition')
                # Check if call expression is inside condition
                if condition_node and \
                   node.start_byte >= condition_node.start_byte and \
                   node.end_byte <= condition_node.end_byte:
                    
                    keyword_node = enclosing_statement.child(0)
                    keyword_text = keyword_node.text.decode('utf8') if keyword_node else enclosing_statement.type.split('_')[0]

                    if enclosing_statement.type == 'for_statement':
                        body_node = enclosing_statement.child_by_field_name('body')
                        l_paren = enclosing_statement.child(1) # '('
                        r_paren = body_node.prev_sibling if body_node else enclosing_statement.last_named_child # ')'
                        if l_paren and r_paren and l_paren.type == '(':
                            control_content_bytes = enclosing_statement.text[l_paren.start_byte:r_paren.end_byte]
                            control_content_text = control_content_bytes.decode('utf8')
                            code_snippet = f"for {control_content_text}"
                        else:
                            code_snippet = f"for ({condition_node.text.decode('utf8')})" # Fallback
                    else:
                        code_snippet = f"{keyword_text} ({condition_node.text.decode('utf8')})"

            if code_snippet is None:
                code_snippet = enclosing_statement.text.decode('utf8').strip().replace('\n', ' ')

            # Mode 1: Variable assigned the return value of a function call (e.g., var = func();)
            parent = node.parent
            if parent and parent.type == 'assignment_expression':
                left_node = parent.child_by_field_name('left')
                if left_node and left_node.type == 'identifier':
                    var_name = left_node.text.decode('utf8')
                    if var_name in uf.parent:
                        high_quality_sources[var_name] = {"code": code_snippet, "source_from_function": func_name}

            # --- Precise "out-parameter" logic ---
            arg_list_node = node.child_by_field_name('arguments')
            if arg_list_node:
                args = [arg for arg in arg_list_node.children if arg.is_named]

                # Mode 2: (High confidence generic rule) Look for params passed via "&var"
                for arg in args:
                    if arg.type == 'pointer_expression' and arg.children[0].type == 'identifier':
                        var_name = arg.children[0].text.decode('utf8')
                        if var_name and var_name in uf.parent:
                            if var_name not in high_quality_sources:
                                high_quality_sources[var_name] = {"code": code_snippet, "source_from_function": f"[address passed to {func_name}]"}
                
                # Mode 3: (High confidence specific rule) Check for known buffer input functions
                if func_name in KNOWN_BUFFER_INPUT_FUNCS:
                    for arg_index in KNOWN_BUFFER_INPUT_FUNCS[func_name]:
                        if arg_index < len(args) and args[arg_index].type == 'identifier':
                            var_name = args[arg_index].text.decode('utf8')
                            if var_name in uf.parent:
                                if var_name not in high_quality_sources:
                                    high_quality_sources[var_name] = {"code": code_snippet, "source_from_function": func_name}


        if node.children:
            q.extend(node.children)
            
    return {"union_find": uf, "sources": high_quality_sources}

def analyze_taint_paths(function_code: str, variable_name: str, language: str = 'c'):
    """
    Implements a hybrid Source strategy:
    1. Prioritizes using _pre_analyze_and_build_context to find high-quality taint sources.
    2. Fallback to treating variable "declaration" as taint source if no high-quality source is found.
    """
    # Step 1: Perform pre-analysis
    try:
        context = _pre_analyze_and_build_context(function_code, language)
        uf = context["union_find"]
        high_quality_sources = context["sources"]
    except Exception as e:
        print(f"[Error] During pre-analysis phase: {e}")
        return {"path_segments": []}

    # Step 2: Get alias set
    if variable_name not in uf.parent:
        # Variable not found in local variables (might be param or not extracted)
        return {"path_segments": []}
        
    taint_alias_set = uf.get_set(variable_name)
    
    # Step 3: Hybrid Source lookup
    all_found_sources = []
    source_code_snippets_seen = set() # For deduplication

    # Strategy 1: Find high-quality Source (Preferred)
    for var in taint_alias_set:
        if var in high_quality_sources:
            source_info = high_quality_sources[var]
            if source_info['code'] not in source_code_snippets_seen:
                all_found_sources.append(source_info)
                source_code_snippets_seen.add(source_info['code'])
    
    # Step 4: Parse AST for Fallback only if needed
    so_path = '/tree_sitter/build/my-languages.so'
    LANGUAGE = Language(so_path, language)
    parser = Parser()
    parser.set_language(LANGUAGE)
    tree = parser.parse(bytes(function_code, "utf8"))
    root_node = tree.root_node
    
    # Strategy 2: Fallback - Search for declaration if no high-quality Source found
    if not all_found_sources:
        query_string = f"""(identifier) @variable"""
        query = LANGUAGE.query(query_string)
        captures = query.captures(root_node)
        
        # Filter identifiers to only those in the alias set
        variable_nodes = [node for node, tag in captures if node.text.decode('utf8') in taint_alias_set]

        for node in variable_nodes:
            statement_node = _get_enclosing_statement(node)
            if not statement_node or statement_node.type != 'declaration':
                continue

            # Confirm this is indeed the identifier's declaration
            for declarator in statement_node.children:
                if 'declarator' in declarator.type:
                    q_decl = [declarator]
                    found_id_node = None
                    while q_decl:
                        curr = q_decl.pop(0)
                        if curr.type == 'identifier':
                            found_id_node = curr
                            break
                        q_decl.extend(curr.children)
                    
                    if found_id_node == node:
                        code_snippet = statement_node.text.decode('utf8').strip().replace('\n', ' ')
                        if code_snippet not in source_code_snippets_seen:
                            fallback_source_info = {
                                "code": code_snippet,
                                "source_from_function": "" # Declaration
                            }
                            all_found_sources.append(fallback_source_info)
                            source_code_snippets_seen.add(code_snippet)
                        break 
    
    # Step 5: Final exit point
    if not all_found_sources:
        return {"path_segments": []}

    # Step 6: Find Sinks (using parsed tree)
    variable_c_type = _get_variable_c_type(root_node, variable_name)
    found_sinks_map = {}
    q = deque([root_node])
    
    while q:
        node = q.popleft()
        
        if node.type == 'identifier' and node.text.decode('utf8') in taint_alias_set:
            
            sink_info = _classify_sink(node, variable_c_type)
            
            if sink_info:
                category, sink_node = sink_info
                
                statement_node = _get_enclosing_statement(sink_node)
                if not statement_node: statement_node = sink_node

                code_snippet = None
                control_flow_types = {"if_statement", "while_statement", "for_statement", "switch_statement"}

                if statement_node.type in control_flow_types:
                    condition_node = statement_node.child_by_field_name('condition')
                    if condition_node and \
                       sink_node.start_byte >= condition_node.start_byte and \
                       sink_node.end_byte <= condition_node.end_byte:
                        
                        keyword_node = statement_node.child(0)
                        keyword_text = keyword_node.text.decode('utf8') if keyword_node else statement_node.type.split('_')[0]

                        if statement_node.type == 'for_statement':
                            body_node = statement_node.child_by_field_name('body')
                            l_paren = statement_node.child(1)
                            r_paren = body_node.prev_sibling if body_node else statement_node.last_named_child
                            if l_paren and r_paren and l_paren.type == '(':
                                control_content_bytes = statement_node.text[l_paren.start_byte:r_paren.end_byte]
                                control_content_text = control_content_bytes.decode('utf8')
                                code_snippet = f"for {control_content_text}"
                            else:
                                code_snippet = f"for ({condition_node.text.decode('utf8')})"
                        else:
                            code_snippet = f"{keyword_text} ({condition_node.text.decode('utf8')})"
                
                if code_snippet is None:
                    code_snippet = statement_node.text.decode('utf8').strip().replace('\n', ' ')

                # Check if it's any known Source
                if code_snippet in source_code_snippets_seen:
                    continue
                if statement_node.start_byte in found_sinks_map:
                    continue
                
                controls = _find_control_dependencies(sink_node)
                
                found_sinks_map[statement_node.start_byte] = {
                    "code": code_snippet,
                    "category": category,
                    "control_dependence": controls
                }

        if node.children:
            q.extend(node.children)

    # Step 7: Assemble final result
    final_sinks_list = list(found_sinks_map.values())
    
    if not final_sinks_list:
        return {"path_segments": []}

    final_segment = {
        "source_variable": sorted(list(taint_alias_set)),
        "source_type": variable_c_type, 
        "taint_source": [s['code'] for s in all_found_sources],
        "source_from_function": [s['source_from_function'] for s in all_found_sources],
        "sinks": final_sinks_list
    }
    return final_segment


def analyze_taint_paths_by_param_index(function_code: str, param_index: int, language: str = 'c'):
    """
    Hybrid Source strategy for parameters:
    1. Treat function parameter entry always as the first Source.
    2. Append any other high-value Sources found via _pre_analyze_and_build_context.
    """
    so_path = '/tree_sitter/build/my-languages.so'
    LANGUAGE = Language(so_path, language)
    parser = Parser()
    parser.set_language(LANGUAGE)
    tree = parser.parse(bytes(function_code, "utf8"))
    root_node = tree.root_node

    # Step 1: Get parameter info
    param_info = get_parameter_info(root_node, param_index)
    if not param_info or not param_info.get("name"):
        return {"path_segments": []}
    
    variable_name = param_info["name"]
    variable_c_type = param_info["type"]
    
    # Step 2: Perform pre-analysis
    try:
        context = _pre_analyze_and_build_context(function_code, language)
        uf = context["union_find"]
        high_quality_sources = context["sources"]
    except Exception as e:
        print(f"[Error] During pre-analysis phase: {e}")
        return {"path_segments": []}
        
    if variable_name not in uf.parent:
        uf.parent[variable_name] = variable_name
        uf.size[variable_name] = 1

    taint_alias_set = uf.get_set(variable_name)
    
    # Step 3: Hybrid Source lookup
    all_found_sources = []
    source_code_snippets_seen = set()

    # Strategy 1: Function entry (Preferred)
    func_declarator_node = root_node.child_by_field_name('declarator')
    taint_source_code = func_declarator_node.text.decode('utf8') if func_declarator_node else ""
    entry_source_info = {"code": f"Function parameter: {taint_source_code}", "source_from_function": "[Function Entry]"}
    all_found_sources.append(entry_source_info)
    source_code_snippets_seen.add(entry_source_info['code'])
    
    # Strategy 2: Append other high-quality Sources
    for var in taint_alias_set:
        if var in high_quality_sources:
            source_info = high_quality_sources[var]
            if source_info['code'] not in source_code_snippets_seen:
                all_found_sources.append(source_info)
                source_code_snippets_seen.add(source_info['code'])
    
    # Step 4: Find Sinks
    found_sinks_map = {}
    q = deque([root_node])
    
    while q:
        node = q.popleft()
        if node.type == 'identifier' and node.text.decode('utf8') in taint_alias_set:
            
            sink_info = _classify_sink(node, variable_c_type)
            
            if sink_info:
                category, sink_node = sink_info
                
                statement_node = _get_enclosing_statement(sink_node)
                if not statement_node: statement_node = sink_node
                
                code_snippet = None
                control_flow_types = {"if_statement", "while_statement", "for_statement", "switch_statement"}

                if statement_node.type in control_flow_types:
                    condition_node = statement_node.child_by_field_name('condition')
                    if condition_node and \
                       sink_node.start_byte >= condition_node.start_byte and \
                       sink_node.end_byte <= condition_node.end_byte:
                        
                        keyword_node = statement_node.child(0)
                        keyword_text = keyword_node.text.decode('utf8') if keyword_node else statement_node.type.split('_')[0]

                        if statement_node.type == 'for_statement':
                            body_node = statement_node.child_by_field_name('body')
                            l_paren = statement_node.child(1)
                            r_paren = body_node.prev_sibling if body_node else statement_node.last_named_child
                            if l_paren and r_paren and l_paren.type == '(':
                                control_content_bytes = statement_node.text[l_paren.start_byte:r_paren.end_byte]
                                control_content_text = control_content_bytes.decode('utf8')
                                code_snippet = f"for {control_content_text}"
                            else:
                                code_snippet = f"for ({condition_node.text.decode('utf8')})"
                        else:
                            code_snippet = f"{keyword_text} ({condition_node.text.decode('utf8')})"
                
                if code_snippet is None:
                    code_snippet = statement_node.text.decode('utf8').strip().replace('\n', ' ')

                # Check if it's any known Source
                if code_snippet in source_code_snippets_seen:
                    continue
                if statement_node.start_byte in found_sinks_map:
                    continue
                
                controls = _find_control_dependencies(sink_node)
                
                found_sinks_map[statement_node.start_byte] = {
                    "code": code_snippet,
                    "category": category,
                    "control_dependence": controls
                }

        if node.children:
            q.extend(node.children)

    # Step 5: Assemble results
    final_sinks_list = list(found_sinks_map.values())
    
    if not final_sinks_list:
        return {"path_segments": []}
        
    final_segment = {
        "source_variable": sorted(list(taint_alias_set)),
        "source_type": variable_c_type,
        "taint_source": [s['code'] for s in all_found_sources],
        "source_from_function": [s['source_from_function'] for s in all_found_sources],
        "sinks": final_sinks_list
    }
    return final_segment

# --- 4. Example Usage ---
if __name__ == "__main__":

    code = """
int kvm_iommu_map_pages(struct kvm *kvm, struct kvm_memory_slot *slot)
{
	gfn_t gfn, end_gfn;
	pfn_t pfn;
	int r = 0;
	struct iommu_domain *domain = kvm->arch.iommu_domain;
	int flags;

	/* check if iommu exists and in use */
	if (!domain)
		return 0;

	gfn     = slot->base_gfn;
	end_gfn = gfn + slot->npages;

	flags = IOMMU_READ;
	if (!(slot->flags & KVM_MEM_READONLY))
		flags |= IOMMU_WRITE;
	if (!kvm->arch.iommu_noncoherent)
		flags |= IOMMU_CACHE;


	while (gfn < end_gfn) {
		unsigned long page_size;

		/* Check if already mapped */
		if (iommu_iova_to_phys(domain, gfn_to_gpa(gfn))) {
			gfn += 1;
			continue;
		}

		/* Get the page size we could use to map */
		page_size = kvm_host_page_size(kvm, gfn);

		/* Make sure the page_size does not exceed the memslot */
		while ((gfn + (page_size >> PAGE_SHIFT)) > end_gfn)
			page_size >>= 1;

		/* Make sure gfn is aligned to the page size we want to map */
		while ((gfn << PAGE_SHIFT) & (page_size - 1))
			page_size >>= 1;

		/* Make sure hva is aligned to the page size we want to map */
		while (__gfn_to_hva_memslot(slot, gfn) & (page_size - 1))
			page_size >>= 1;

		/*
		 * Pin all pages we are about to map in memory. This is
		 * important because we unmap and unpin in 4kb steps later.
		 */
		pfn = kvm_pin_pages(slot, gfn, page_size);
		if (is_error_noslot_pfn(pfn)) {
			gfn += 1;
			continue;
		}

		/* Map into IO address space */
		r = iommu_map(domain, gfn_to_gpa(gfn), pfn_to_hpa(pfn),
			      page_size, flags);
		if (r) {
			printk(KERN_ERR "kvm_iommu_map_address:"
			       "iommu failed to map pfn=%llx\n", pfn);
			kvm_unpin_pages(kvm, pfn, page_size);
			goto unmap_pages;
		}

		gfn += page_size >> PAGE_SHIFT;


	}

	return 0;

unmap_pages:
	kvm_iommu_put_pages(kvm, slot->base_gfn, gfn - slot->base_gfn);
	return r;
}
"""
    print("="*20 + " Analyzing variable: 'page_size' " + "="*20)
    variable_to_trace = "page_size"
    results = analyze_taint_paths(code, variable_to_trace)
    
    # Print results in beautified JSON format
    print(json.dumps(results, indent=4))