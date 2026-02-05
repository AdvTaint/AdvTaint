import re
import os
import json
import glob
import warnings
from typing import Dict, List, Any, Set, Optional
from tqdm import tqdm
import numpy as np  
# from sentence_transformers import SentenceTransformer
from functools import partial
from concurrent.futures import ThreadPoolExecutor

# --- LangChain/LangGraph Imports ---
from langchain_community.llms.ollama import Ollama
from langchain_openai import ChatOpenAI
from langchain_core.tools import tool
from langchain.output_parsers import PydanticOutputParser, OutputFixingParser
from langchain_core.prompts import PromptTemplate
from langchain_core.runnables import Runnable
from pydantic import BaseModel, Field
from typing_extensions import TypedDict
from langgraph.graph import StateGraph, START, END

# --- Local Tool Imports ---
from tools.ts_sast import (
    generate_rooted_call_graphs, get_code_from_file, 
    extract_filtered_local_variables, get_funcnames_from_file, 
    analyze_taint_paths, analyze_taint_paths_by_param_index
)

warnings.filterwarnings("ignore")

MAX_TRACE_DEPTH = 4
MAX_LLM_CONCURRENCY = 1 # Max threads for parallel LLM calls

################################################################################
# SECTION 1: PYDANTIC MODELS FOR STRUCTURED OUTPUT
################################################################################

# --- Agent 2.5 (Screener) Pydantic Models ---
class DangerousSink(BaseModel):
    """Describes a sink operation identified by the Screener as potentially vulnerable."""
    vul_sink_operation: str = Field(description="The potentially vulnerable sink operation code.")
    potential_vulnerability_type: str = Field(description="The *potential* vulnerability type guessed by the screener (e.g., 'Buffer Overflow', 'Use-After-Free', 'Integer Overflow').")
    reason_for_vulnerable: str = Field(description="The 'hypothesis' - why this sink is *potentially* vulnerable.")

class DangerousSink2(BaseModel):
    """Describes a sink operation identified by the Screener as potentially dangerous."""
    sink_operation: str = Field(description="The potentially vulnerable sink operation code.")
    call_chain_context: str = Field(description="The context of call chain")
    potential_vulnerability_type: str = Field(description="The *potential* vulnerability type guessed by the screener (e.g., 'Buffer Overflow', 'Use-After-Free', 'Integer Overflow').") 
    reason_for_danger: str = Field(description="The 'hypothesis' - why this sink is *potentially* vulnerable.")
    relevant_control_checks: List[str] = Field(description="The control dependency of sinks")

class SinkScreeningResult(BaseModel):
    """The complete JSON output from Agent 2.5 (Screener) for a single NODE."""
    vulnerable_sinks: List[DangerousSink] = Field(description="A list of ALL vulnerable sink operations identified at this node.")

# --- Agent 3 (Analyzer) Pydantic Model ---
class VulnerabilityFinding(BaseModel):
    """The output structure for Agent 3 (Supervisor): the final vulnerability judgment for ONE node."""
    is_vulnerable: str = Field(description="Vulnerable or Not Vulnerable")
    vulnerability_type: str = Field(description="If there is a confirmed vulnerability, return its type (e.g. Buffer Overflow, Out-of-Bounds Access, Null Pointer Dereference, Use-After-Free, Double Free, etc)", default="N/A")
    reasoning: str = Field(description="Detailed reasoning process *validating * the Screener's hypotheses, referencing lines of code and the full context.")
    vulnerable_path: str = Field(description="Key lines of code related to the *confirmed* vulnerability", default="N/A")

################################################################################
# SECTION 2: GRAPH STATE AND LLM INITIALIZATION
################################################################################

class AnalysisTask(TypedDict):
    """A task for Agent 1 to analyze a function."""
    function_name: str
    call_chain: List[str]
    is_transitive_analysis: bool 
    path_history_context: Optional[str]
    accumulated_path: List[Dict]
    parameter_index: Optional[int]

class ScreenerTask(TypedDict):
    """A 'Node-level' task for Agent 2.5 to screen *one node* (function) in the call tree."""
    call_chain_context: str  # The full call chain prefix, e.g., "main(`buf`) -> A(`data`)"
    call_chain_list: List[str]
    source_defining_func: Optional[str]
    sinks_at_this_node: List[Dict[str, Any]] 
    # e.g., [{"operation": "strcpy(..)", "controls": ["if..."], "type": "Terminal"}, ...]

# --- *** NEW *** ---
class AnalyzerTask(TypedDict):
    """A task for Agent 3 to *verify* the dangerous sinks at one node."""
    call_chain_context: str
    call_chain_list: List[str]
    source_defining_func: Optional[str]
    dangerous_sinks_from_screener: List[Dict] # List of DangerousSink.dict()
    # The shared context (source_origin, full_code) will be pulled from current_variable_group


class GraphState(TypedDict):
    """The complete state of the analysis graph."""
    file_path: str
    rooted_call_graphs: Dict[str, Dict[str, List[str]]]
    defined_function_names: List[str] 
    
    # --- Task Queues ---
    discovery_queue: List[AnalysisTask] 
    trace_queue: List[AnalysisTask]     
    final_analysis_queue: List[List[Dict]] 
    
    # --- Agent 1 ---
    last_finished_task: Optional[AnalysisTask]
    agent1_result: List[Dict] 
    
    # --- Agent 2 -> 2.5 -> 3 Workflow State ---
    current_variable_group: Optional[Dict[str, Any]]
    """
    Stores the full context for the variable group currently being processed:
    { "source_origin": str, "full_code": str }
    """
    screener_todo_queue: List[ScreenerTask] # Input for Agent 2.5
    agent_3_todo_queue: List[AnalyzerTask]    # *** NEW ***: Input for Agent 3
    
    # --- Final Output ---
    completed_findings: List[Dict] # Final results
    
    # --- Miscellaneous ---
    queued_functions : Set[str]
    function_analysis_cache: Dict[str, List[Dict]]

# --- Initialize LLM Agents ---
# vd_superviser = Ollama(model="qwen3:30b", temperature=0,num_ctx=65536,keep_alive='8h',base_url="http://localhost:11434")
# sink_superviser = Ollama(model="qwen3:30b", temperature=0,num_ctx=65536,keep_alive='8h',base_url="http://localhost:11434")

vd_superviser = Ollama(model="deepseek-r1:32b", temperature=0,num_ctx=65536,keep_alive='8h',base_url="http://localhost:11434")
sink_superviser = Ollama(model="deepseek-r1:32b", temperature=0,num_ctx=65536,keep_alive='8h',base_url="http://localhost:11435")



################################################################################
# SECTION 3: UTILITY FUNCTIONS
################################################################################

def extract_function_name_from_string(code_line: str) -> Optional[str]:
    if not isinstance(code_line, str): return None
    keywords = {'if', 'while', 'for', 'switch', 'catch', 'return', 'sizeof'}
    keywords_pattern = '|'.join(keywords)
    pattern = r'\b(?! (?:' + keywords_pattern + r')\b) ([a-zA-Z_][a-zA-Z0-9_]*) \s*\('
    match = re.search(pattern, code_line, re.VERBOSE) 
    if match: return match.group(1)
    return None

def get_argument_positions(statement: str, target_func_name: str, source_variable: str) -> List[int]:
    try:
        call_pattern = r'\b' + re.escape(target_func_name) + r'\s*\('
        match = re.search(call_pattern, statement)
        if not match: return []
        content_start = match.end()
        paren_level = 1
        content_end = -1
        for i, char in enumerate(statement[content_start:]):
            if char == '(': paren_level += 1
            elif char == ')': paren_level -= 1
            if paren_level == 0:
                content_end = content_start + i
                break
        if content_end == -1: return []
        args_str = statement[content_start:content_end]
        args_list = []
        current_arg_start = 0
        paren_level = 0
        for i, char in enumerate(args_str):
            if char == '(': paren_level += 1
            elif char == ')': paren_level -= 1
            elif char == ',' and paren_level == 0:
                args_list.append(args_str[current_arg_start:i].strip())
                current_arg_start = i + 1
        args_list.append(args_str[current_arg_start:].strip())
        positions = []
        var_pattern = r'\b' + re.escape(source_variable) + r'\b'
        for i, arg in enumerate(args_list):
            if re.search(var_pattern, arg):
                positions.append(i)
        return positions
    except Exception:
        return []

################################################################################
# SECTION 4: AGENT AND TOOL NODES
################################################################################

def load_and_initialize(state: GraphState) -> Dict[str, Any]:
    print("\n--- [Node: Initializing] ---")
    file_path_to_analyze = state["file_path"] 
    rooted_call_graphs = generate_rooted_call_graphs(file_path_to_analyze)
    defined_function_names = get_funcnames_from_file(file_path_to_analyze)
    if not rooted_call_graphs:
        print("ERROR: Failed to generate call graphs. Terminating workflow.")
        return {"rooted_call_graphs": {}, "discovery_queue": []}
    print(f"Call graphs loaded. Found {len(rooted_call_graphs)} entry points.")
    initial_tasks: List[AnalysisTask] = []
    queued_functions = set()
    for root in rooted_call_graphs.keys():
        if root not in queued_functions:
            initial_tasks.append({
                "function_name": root, 
                "call_chain": [root],
                "is_transitive_analysis": False,
                "path_history_context": None,
                "accumulated_path": []
            })
            queued_functions.add(root)
    return {
        "file_path": file_path_to_analyze,
        "rooted_call_graphs": rooted_call_graphs,
        "defined_function_names": defined_function_names,
        "discovery_queue": initial_tasks,
        "trace_queue": [],
        "final_analysis_queue": [],
        "completed_findings": [],
        "last_finished_task": None,
        "agent1_result": [],
        "current_variable_group": None, 
        "screener_todo_queue": [],       
        "agent_3_todo_queue": [], # *** NEW ***
        "current_final_analysis_context": None,
        "queued_functions": queued_functions,
        "function_analysis_cache": {}
    }


def agent_1_identifier(state: GraphState) -> Dict[str, Any]:
    print("\n--- [Node: Static Analyzer (Agent 1)] ---")
    trace_queue, discovery_queue = state["trace_queue"], state["discovery_queue"]
    if trace_queue: current_task = trace_queue.pop(0)
    elif discovery_queue: current_task = discovery_queue.pop(0)
    else: return {} 
    function_name = current_task["function_name"]
    function_code = get_code_from_file(function_name, state["file_path"])
    raw_segments = [] 
    if not function_code:
        print(f"Warning: Failed to get code for function '{function_name}'.")
        return { "last_finished_task": current_task, "agent1_result": [] }
    print(f"Analyzing function: '{function_name}'")
    if not current_task["is_transitive_analysis"]:
        local_vars = extract_filtered_local_variables(function_code)
        if local_vars:
            for var in local_vars:
                analysis_result = analyze_taint_paths(function_code, var)
                if analysis_result and analysis_result.get("sinks"):
                    raw_segments.append(analysis_result)
    else:
        param_idx = current_task.get("parameter_index")
        cache_key = (function_name, param_idx)
        if param_idx is not None and cache_key in state["function_analysis_cache"]:
            print(f"  - Cache hit: '{function_name}' (Param: {param_idx}).")
            raw_segments = state["function_analysis_cache"][cache_key]
        elif param_idx is not None:
            print(f"  - Cache miss: '{function_name}' (Param: {param_idx}).")
            analysis_result = analyze_taint_paths_by_param_index(function_code, param_idx)
            if analysis_result and analysis_result.get("sinks"):
                raw_segments = [analysis_result] 
            else: raw_segments = []
            state["function_analysis_cache"][cache_key] = raw_segments
    return {
        "discovery_queue": discovery_queue, "trace_queue": trace_queue,
        "last_finished_task": current_task, "agent1_result": raw_segments,
        "function_analysis_cache": state["function_analysis_cache"]
    }


def process_agent_1_output(state: GraphState) -> Dict[str, Any]:
    print("\n--- [Node: Process Static Analysis Output (Adapter)] ---")
    raw_analysis_results, last_task = state["agent1_result"], state["last_finished_task"]
    if not last_task: return {}
    history = last_task["accumulated_path"]
    new_trace_tasks, new_final_paths = [], []
    defined_funcs = state["defined_function_names"]
    for raw_analysis in raw_analysis_results:
        source_variable_list = raw_analysis.get("source_variable", [])
        source_type = raw_analysis.get("source_type")
        taint_source_list = raw_analysis.get("taint_source", [])
        source_from_function_list = raw_analysis.get("source_from_function", [])
        sinks_list = raw_analysis.get("sinks", []) 
        for source_var in source_variable_list:
            for sink_dict in sinks_list:
                sink_op = sink_dict.get("code")
                if not sink_op: continue 
                control_checks = sink_dict.get("control_dependence", [])
                standard_segment = {
                    "source_variable": source_var, "source_type": source_type,
                    "taint_source": ", ".join(taint_source_list),
                    "source_from_function": ", ".join(f for f in source_from_function_list if f),
                    "sink_operation": sink_op, "current_call_chain": last_task["call_chain"],
                    "control_checks": control_checks 
                }
                called_func_name = extract_function_name_from_string(sink_op)
                if called_func_name and called_func_name in defined_funcs:
                    standard_segment["sink_type"] = "Transitive"
                    standard_segment["sink_target_function"] = called_func_name
                else:
                    standard_segment["sink_type"] = "Terminal"
                    standard_segment["sink_target_function"] = called_func_name
                if standard_segment["sink_type"] == "Transitive":
                    target_func = standard_segment["sink_target_function"]
                    current_depth = len(standard_segment['current_call_chain'])
                    if target_func and target_func not in standard_segment['current_call_chain'] and current_depth < MAX_TRACE_DEPTH:
                        param_indices = get_argument_positions(standard_segment['sink_operation'], target_func, standard_segment['source_variable'])
                        if not param_indices: continue 
                        for param_idx in param_indices:
                            history_context = (f"The variable `{standard_segment['source_variable']}` of type `{standard_segment['source_type']}` "
                                f"is passed in from function `{standard_segment['current_call_chain'][-1]}` "
                                f"via the operation: `{standard_segment['sink_operation']}`.")
                            new_task: AnalysisTask = {"function_name": target_func, "call_chain": standard_segment['current_call_chain'] + [target_func], 
                                "is_transitive_analysis": True, "path_history_context": history_context, 
                                "accumulated_path": history + [standard_segment], "parameter_index": param_idx}
                            new_trace_tasks.append(new_task)
                    else:
                        if current_depth >= MAX_TRACE_DEPTH: print(f"  - Trace depth limit reached ({current_depth}). Treating sink '{sink_op}' as terminal.")
                        else: print(f"  - Recursive/Repeated call detected. Treating sink '{sink_op}' as terminal.")
                        standard_segment["sink_type"] = "Terminal (Stopped)"
                        new_final_paths.append(history + [standard_segment])
                elif "Terminal" in standard_segment["sink_type"]:
                    new_final_paths.append(history + [standard_segment])
    queued_functions = state["queued_functions"]
    all_callees = set()
    for graph in state["rooted_call_graphs"].values():
        if last_task['function_name'] in graph:
            all_callees.update(graph[last_task['function_name']])
    general_tasks_to_add = []
    for callee in all_callees:
        if callee not in queued_functions:
            new_task: AnalysisTask = {"function_name": callee, "call_chain": [callee], "is_transitive_analysis": False, "path_history_context": None, "accumulated_path": [], "parameter_index": None}
            general_tasks_to_add.append(new_task)
            queued_functions.add(callee)
    return {
        "discovery_queue": state["discovery_queue"] + general_tasks_to_add,
        "trace_queue": new_trace_tasks + state["trace_queue"],
        "final_analysis_queue": state["final_analysis_queue"] + new_final_paths,
        "queued_functions": queued_functions
    }
    

def agent_2_retriever(state: GraphState) -> Dict[str, Any]:
    print("\n--- [Node: Agent 2 (Variable Group Processor)] ---")
    if not state["final_analysis_queue"]: return {}
    all_paths_in_queue = state["final_analysis_queue"]
    source_groups = {}
    print("  - Grouping completed paths by 'source_function + source_variable'...")
    for path in all_paths_in_queue:
        if not path: continue
        initial_segment = path[0]
        grouping_key = (initial_segment['current_call_chain'][0], initial_segment['source_variable'])
        if grouping_key not in source_groups: source_groups[grouping_key] = []
        source_groups[grouping_key].append(path)
    if not source_groups: return {} 
    first_group_key = next(iter(source_groups))
    paths_to_process = source_groups.pop(first_group_key)
    path_for_metadata = paths_to_process[0] # Extract the first complete path of this group
    source_defining_func_name = None
    for segment in path_for_metadata:
        raw_source = segment.get('source_from_function')
        if raw_source and raw_source!='[Function Entry]':
            source_defining_func_name = raw_source.split(',')[0].strip()
            break
    print(f"  - Processing variable group: '{first_group_key[0]}::{first_group_key[1]}' (with {len(paths_to_process)} paths).")
    remaining_paths_in_queue = [p for group in source_groups.values() for p in group]
    print("  - Building rich call tree and filtering for terminal sinks...")
    call_tree = {}
    functions_to_retrieve = set()
    source_origin_descriptions = set()
    for path in paths_to_process:
        original_source = path[0]
        source_desc = (f"In function `{original_source['current_call_chain'][0]}`, "
            f"the variable `{original_source['source_variable']}` (type: `{original_source['source_type']}`) "
            f"originates from: `{original_source['taint_source']}`.")
        source_origin_descriptions.add(source_desc)
        current_level = call_tree
        for segment in path:
            call_key = f"{segment['current_call_chain'][-1]}(`{segment['source_variable']}`)"
            if call_key not in current_level:
                current_level[call_key] = {"sinks": {}, "children": {}}
            sink_type = segment['sink_type']
            # if sink_type.startswith("Terminal"): # Captures "Terminal" and "Terminal (Stopped)"
            if sink_type == "Terminal":
                sink_op = segment['sink_operation']
                control_checks = set(segment.get('control_checks', []))
                if sink_op not in current_level[call_key]["sinks"]:
                    current_level[call_key]["sinks"][sink_op] = {"controls": control_checks, "type": sink_type}
                else:
                    current_level[call_key]["sinks"][sink_op]["controls"].update(control_checks)
            current_level = current_level[call_key]["children"]
            functions_to_retrieve.update(segment.get('current_call_chain', []))
            source_from_func = segment.get('source_from_function')
            if source_from_func: functions_to_retrieve.update(f.strip() for f in source_from_func.split(','))
    
    def flatten_tree_to_node_tasks(tree_node: dict, chain_prefix: List[str], chain_prefix_list: List[str]) -> List[ScreenerTask]:
        tasks = []
        for call_key, data in tree_node.items():
            func_name_only = call_key.split('(')[0].strip()
            new_chain_list = chain_prefix_list + [func_name_only]
            current_call_chain_str = " -> ".join(chain_prefix + [call_key])
            sinks_at_this_node = []
            for op, info in data["sinks"].items():
                sinks_at_this_node.append({"operation": op, "controls": sorted(list(info["controls"])), "type": info["type"]})
            if sinks_at_this_node:
                tasks.append({"call_chain_context": current_call_chain_str, "call_chain_list": new_chain_list, "source_defining_func": source_defining_func_name,"sinks_at_this_node": sinks_at_this_node})
            if data["children"]:
                tasks.extend(flatten_tree_to_node_tasks(data["children"], chain_prefix + [call_key], new_chain_list))
        return tasks

    screener_todo_queue = flatten_tree_to_node_tasks(call_tree, [],[])
    print(f"  - Created {len(screener_todo_queue)} node-level screening tasks for Agent 2.5.")
    # full_code_context = ""
    # for func_name in sorted(list(functions_to_retrieve)):
    #     code = get_code_from_file(func_name, state['file_path'])
    #     if code: full_code_context += f"{code}\n"
    # current_variable_group = {"source_origin": "\n".join(source_origin_descriptions), "full_code": full_code_context}
    code_map = {}
    for func_name in sorted(list(functions_to_retrieve)):
        code = get_code_from_file(func_name, state['file_path'])
        if code: 
            code_map[func_name] = code
            
    # current_variable_group 现在存储的是 Map
    current_variable_group = {
        "source_origin": "\n".join(source_origin_descriptions), 
        "code_map": code_map  # <--- 变成了字典
    }
    return {
        "final_analysis_queue": remaining_paths_in_queue, 
        "current_variable_group": current_variable_group,
        "screener_todo_queue": screener_todo_queue,
        "agent_3_todo_queue": [] # Clear any old tasks
    }


# --- AGENT 2.5 (SCREENER) BATCH NODES ---

def _run_screener_task(task: ScreenerTask, shared_context: Dict[str, Any], chain: Runnable) -> List[Dict]:
    """Worker function for Agent 2.5 parallel execution. Generates hypotheses."""
    try:
        needed_funcs = []
        
        # 1. Prioritize adding the Source Definition Function
        source_func = task.get('source_defining_func')
        if source_func:
            needed_funcs.append(source_func)
            
        # 2. Add functions on Call Chain
        needed_funcs.extend(task['call_chain_list'])
        
        code_map = shared_context["code_map"]
        dynamic_code_context = ""
        
        # 3. Remove duplicates and assemble them in order
        #Use dict.fromkeys to maintain insertion order: Source first, then Root ->A ->B
        unique_funcs = list(dict.fromkeys(needed_funcs))
        
        for fname in unique_funcs:
            if fname in code_map:
                if fname == source_func:
                    dynamic_code_context += f"// Source Definition Function: {fname}\n{code_map[fname]}\n\n"
                else:
                    dynamic_code_context += f"// Call Chain Function: {fname}\n{code_map[fname]}\n\n"
        sinks_list_str_builder = []
        full_call_chain = task['call_chain_context']
        try:
            current_function_segment = full_call_chain.split(' -> ')[-1]
            current_function_name = current_function_segment.split('(')[0]
        except Exception:
            current_function_name = "Unknown" # Fallback
        original_sink_info_map = {s['operation']: s for s in task['sinks_at_this_node']}
        for i, sink_info in enumerate(task['sinks_at_this_node']):
            sinks_list_str_builder.append(f"  Sink {i+1}:")
            sinks_list_str_builder.append(f"    Operation: `{sink_info['operation']}`")
            sinks_list_str_builder.append(f"    Type: {sink_info['type']}")
            sinks_list_str_builder.append(f"    Controls: {sink_info['controls'] if sink_info['controls'] else 'None'}")
        sinks_list_for_prompt = "\n".join(sinks_list_str_builder)
        
        finding: SinkScreeningResult = chain.invoke({
            "source_origin": shared_context["source_origin"],
            "call_chain_context": full_call_chain,
            "current_function_name": current_function_name,
            "sinks_list_for_prompt": sinks_list_for_prompt,
            "full_code": dynamic_code_context,
        })

        if finding.vulnerable_sinks:
            print(f"    -> [Screener] Found {len(finding.vulnerable_sinks)} dangerous sinks at node '{full_call_chain}'")
            
            dangerous_sinks_for_agent_3: List[Dict] = []
            
            # 2. *** CRITICAL RE-ASSEMBLY STEP ***
            # We combine the LLM's output (hypothesis) with our static data (call_chain, controls)
            for hypothesis in finding.vulnerable_sinks:
                # Find the original sink info
                original_sink = original_sink_info_map.get(hypothesis.vul_sink_operation)
                
                if original_sink:
                    # Build the *full* DangerousSink object that Agent 3 expects
                    full_sink_data: Dict = {
                        "sink_operation": hypothesis.vul_sink_operation,
                        "potential_vulnerability_type": hypothesis.potential_vulnerability_type,
                        "reason_for_danger": hypothesis.reason_for_vulnerable,
                        "call_chain_context": full_call_chain, # From our static task
                        "relevant_control_checks": original_sink['controls'] # From our static task
                    }
                    dangerous_sinks_for_agent_3.append(full_sink_data)
                else:
                    # Should not happen if LLM follows instructions, but good to check
                    print(f"    -> [Screener] Warning: LLM hallucinated a sink operation: {hypothesis.vul_sink_operation}")

            if not dangerous_sinks_for_agent_3:
                return None
            return dangerous_sinks_for_agent_3
        else:
            return None
    except Exception as e:
        print(f"    -> [Screener] ERROR screening node '{task['call_chain_context']}': {e}")
        return []

def agent_2_5_screener_batch(state: GraphState) -> Dict[str, Any]:
    """Processes the entire node-level todo queue in parallel to generate hypotheses."""
    print(f"\n--- [Node: Agent 2.5 (Batch Node Screener)] ---")
    screener_todo_queue = state["screener_todo_queue"]
    full_context = state["current_variable_group"]
    if not screener_todo_queue or not full_context:
        print("  - Warning: Screener queue or context is empty. Skipping.")
        return {"screener_todo_queue": [], "agent_3_todo_queue": []}
    print(f"  - Screening {len(screener_todo_queue)} nodes in parallel (max {MAX_LLM_CONCURRENCY} threads)...")

    pydantic_parser = PydanticOutputParser(pydantic_object=SinkScreeningResult)
    output_fixing_parser = OutputFixingParser.from_llm(parser=pydantic_parser, llm=sink_superviser)
    
    prompt_template_str = """
    You are an expert C/C++ static analysis screener. Your task is to analyze a *list* of terminal sinks found at a *single* target function in a call chain.

    You will be given:
    1.  **Source Origin**: Where the tainted data comes from.
    2.  **Full Code Context**: All relevant functions.
    3.  **Call Chain Context**: The *exact* call chain leading to the node being analyzed.
    4.  **Target Function Name**: The specific function you need to analyze.
    5.  **Sinks List**: A list of *all* terminal sinks found at this node.

    Your task is to review *every sink* in the "Sinks List" and generate a "hypothesis" (a `reason_for_vulnerable`) for each one that is *potentially vulnerable*.

    **Analysis Rules**:
    1. Assume Potentially Dangerous: Your primary goal is to identify credible hypotheses for the senior analyst to investigate. Your priority is to find all potential threats. Missing a real vulnerability (a False Negative) is a critical failure. Flagging a safe sink (a False Positive) is an acceptable trade-off to ensure nothing is missed.
    
    2. Localized Code Tracing: For each sink, you MUST trace the tainted data from the arguments of {current_function_name} (or where it enters the function) down to the sink's Operation. You must understand how the data is transformed within this function before reaching the sink.

    3. Scrutinize Controls (Do Not Trust Blindly): The provided Controls list is just a hint. You MUST find the control logic in the Full Code Context and verify that it:
       * Actually exists on the code path from the function entry to the sink.
       * Is sufficient to prevent the specific vulnerability (e.g., a len > 0 check does not prevent a buffer overflow).
       * Is not bypassed by other logic.

    4. Vulnerability Class Focus: Pay close attention to the following vulnerability classes:
       * Memory Safety (Pointers/Arrays): Look for potential Heap/Stack Buffer Overflows (e.g., strcpy, sprintf, memcpy without bounds checks), Out-of-Bounds Read/Write (e.g., array access arr[i] where i is not properly constrained).
       * Pointer Lifecycle: Look for Null Pointer Dereference (using a pointer that could be NULL), Use-After-Free (using a pointer after free() has been called on it), Double Free (calling free() twice on the same pointer).
       * Integer Safety (Numeric Variables): Look for Integer Overflow/Underflow or Wraparound and Conversion Errors (like unsafe type conversions or integer truncation), especially when the variable is used for memory allocation (malloc(count * size)), array indexing (arr[count]), or bounds checking (if (len < MAX_SIZE)).
    
    5. Safe Sinks: Only ignore sinks if your Localized Code Tracing (Rule 2) and Control Scrutiny (Rule 3) provably demonstrate that the sink is safe within this function's context.

    Return a JSON fomat `vulnerable_sinks` list containing *only* the sinks you identified as vulnerable, *along with your `reason_for_vulnerable` for each*. If no sinks are dangerous, return an empty list '[]'.

    ---
    **Source Origin**:
    {source_origin}

    ---
    **Full Code Context**:
    {full_code}
    
    ---
    **Analysis Target Function**: `{current_function_name}`

    **Call Chain**:
    {call_chain_context}
        
    ---
    **Sinks List to Analyze within `{current_function_name}`**:
    {sinks_list_for_prompt}

    ---
    Output Format Instructions:
    {format_instructions}
    """
    # 1. Get instructions
    screener_format_instructions = pydantic_parser.get_format_instructions()
    # 2. Create prompt template
    prompt = PromptTemplate.from_template(prompt_template_str)
    # 3. Pre-fill instructions safely
    partial_prompt = prompt.partial(format_instructions=screener_format_instructions)
    # 4. Create the SIMPLIFIED chain
    chain = partial_prompt | sink_superviser | output_fixing_parser # <-- USE PydanticOutputParser directly
    # --- *** END CHAIN SETUP *** ---

    # Worker function setup remains the same
    worker_fn = partial(_run_screener_task,
                        shared_context=full_context,
                        chain=chain)
    
    agent_3_todo_queue: List[AnalyzerTask] = []
    
    with ThreadPoolExecutor(max_workers=MAX_LLM_CONCURRENCY) as executor:
        # results is a List[List[DangerousSink.dict()]]
        results = list(tqdm(
            executor.map(worker_fn, screener_todo_queue), 
            total=len(screener_todo_queue), 
            desc="  Screening Nodes"
        ))
        
        # *** NEW ***: Pair results with original tasks to build Agent 3's queue
        for task, dangerous_sinks_list in zip(screener_todo_queue, results):
            if dangerous_sinks_list:
                # If dangerous sinks were found, create a *single* verification task for this node
                new_analyzer_task: AnalyzerTask = {
                    "call_chain_context": task["call_chain_context"],
                    "call_chain_list": task["call_chain_list"],
                    "source_defining_func": task["source_defining_func"],
                    "dangerous_sinks_from_screener": dangerous_sinks_list
                }
                agent_3_todo_queue.append(new_analyzer_task)

    print(f"  - Batch screening complete. Found {len(agent_3_todo_queue)} nodes with dangerous sinks.")
    
    return {
        "screener_todo_queue": [], # Clear the queue, it's done
        "agent_3_todo_queue": agent_3_todo_queue # Populate the *next* queue
    }


# --- *** NEW *** AGENT 3 (ANALYZER) BATCH NODES ---

def _run_analyzer_task(task: AnalyzerTask, shared_context: Dict[str, Any], chain: Runnable) -> Optional[Dict]:
    """Worker function for Agent 3 parallel execution. Verifies hypotheses."""
    try:
       
        needed_funcs = []
        
        # 1. Prioritize adding the Source Definition Function
        source_func = task.get('source_defining_func')
        if source_func:
            needed_funcs.append(source_func)
            
        # 2. Add functions on Call Chain
        needed_funcs.extend(task['call_chain_list'])
        
        code_map = shared_context["code_map"]
        dynamic_code_context = ""
        
        # 3. Remove duplicates and assemble them in order
        #Use dict.fromkeys to maintain insertion order: Source first, then Root ->A ->B
        unique_funcs = list(dict.fromkeys(needed_funcs))
        
        for fname in unique_funcs:
            if fname in code_map:
                if fname == source_func:
                    dynamic_code_context += f"// Source Definition Function: {fname}\n{code_map[fname]}\n\n"
                else:
                    dynamic_code_context += f"// Call Chain Function: {fname}\n{code_map[fname]}\n\n"
        hypotheses_str_builder = []
        full_call_chain = task['call_chain_context']

        try:
            current_function_segment = full_call_chain.split(' -> ')[-1]
            current_function_name = current_function_segment.split('(')[0]
        except Exception:
            current_function_name = "Unknown"
        
        for i, sink_dict in enumerate(task['dangerous_sinks_from_screener']):
            sink = DangerousSink2(**sink_dict) # Re-create Pydantic model for easy access
            hypotheses_str_builder.append(f"  Hypothesis {i+1}:")
            hypotheses_str_builder.append(f"    Sink: `{sink.sink_operation}`")
            hypotheses_str_builder.append(f"    Screener's Potential Type: {sink.potential_vulnerability_type}")
            hypotheses_str_builder.append(f"    Screener's Reason: {sink.reason_for_danger}")
            hypotheses_str_builder.append(f"    Controls: {sink.relevant_control_checks if sink.relevant_control_checks else 'None'}")
        
        hypotheses_for_prompt = "\n".join(hypotheses_str_builder)
        
        # 2. Invoke the Analyzer chain
        finding: VulnerabilityFinding = chain.invoke({
            "source_origin": shared_context["source_origin"],
            "call_chain_context": full_call_chain,
            "current_function_name": current_function_name,
            "hypotheses_for_prompt": hypotheses_for_prompt,
            "full_code": dynamic_code_context,
        })
        
        print(f"    -> [Analyzer] Node '{full_call_chain}' -> Vulnerable: {finding.is_vulnerable}")
        
        # 3. Return the final finding
        return finding.dict()
        
    except Exception as e:
        print(f"    -> [Analyzer] ERROR verifying node '{task['call_chain_context']}': {e}")
        return None

def agent_3_analyzer_batch(state: GraphState) -> Dict[str, Any]:
    """
    Processes the entire agent_3_todo_queue in parallel to verify hypotheses.
    """
    print(f"\n--- [Node: Agent 3 (Batch Node Analyzer)] ---")
    
    agent_3_todo_queue = state["agent_3_todo_queue"]
    full_context = state["current_variable_group"]
    
    if not agent_3_todo_queue or not full_context:
        print("  - Warning: Agent 3 queue or context is empty. Skipping.")
        return {"agent_3_todo_queue": [], "current_variable_group": None}
        
    print(f"  - Verifying {len(agent_3_todo_queue)} dangerous nodes in parallel (max {MAX_LLM_CONCURRENCY} threads)...")

    # 1. Prepare the LLM chain
    pydantic_parser = PydanticOutputParser(pydantic_object=VulnerabilityFinding)
    output_fixing_parser = OutputFixingParser.from_llm(parser=pydantic_parser, llm=vd_superviser)
    
    # --- *** NEW PROMPT for Agent 3 *** ---
    prompt_template_str = """
    You are a 'Red Team' C/C++ exploitation analyst. Your primary task is to confirm and prove the exploitability of the hypotheses provided by the 'Screener' (expert) agent.
    Your default stance is 'Assume Vulnerable'. The screener has already flagged a credible threat. Your job is to find the attack path that proves it correct.

    You will be given:
    1.  **Source Origin**: Where the tainted data comes from.
    2.  **Full Code Context**: All relevant functions.
    3.  **Call Chain Context**: The *exact* call chain leading to the function.
    4.  **Target Function Name**: The specific function you need to analyze.
    5.  **Expert's Hypotheses**: A list of *potentially* dangerous sinks and the *expert's reasons* why.

    **Your Comprehensive Analysis Task**:
    1. Understand Hypotheses: Review the Expert's Hypotheses. Understand why the expert flagged each specific sink. Treat these as confirmed leads, not mere suggestions.
    2. Construct the Exploit Payload (Hypothetical): Before analyzing controls, your first step is to determine a malicious input value from the Source Origin that would trigger the vulnerability.
    3. Trace the Exploit Payload: Now, trace this specific payload through the Call Chain. Your goal is to find a path where this payload reaches the sink without being stopped.
    4. Aggressively Challenge Controls: When you encounter a control (like a check), your only question is: "Does this check unambiguously stop my malicious payload?"
    5. Final Judgment (Holistic): Based on your comprehensive attack-path analysis, make a single, final judgment (is_vulnerable) regarding this specific data flow path.
    
    **CRITICAL GUARDRAIL #2: DO NOT TRUST IMPLICIT GUARANTEES**
    Your goal is to find an attack path. You MUST assume all data sources are untrusted, even if they appear to come from the kernel or another system component.

    THE FOLLOWING ARGUMENT IS FORBIDDEN AND CONSTITUTES A FAILURE:

    "The data is safe because it comes from a trusted source (like /proc, a kernel API, or another internal function)."

    This is the exact flawed logic that creates vulnerabilities. Your task is to challenge this logic.

    You MUST prioritize the code's actual behavior (e.g., a vulnerable sink in a loop with no check) over external assumptions (e.g., "the kernel will never provide long data").

    **Conclude 'Not Vulnerable' Only as a Last Resort**:
    Only, and only if, you have exhausted all possible attack variations and can formally prove that no possible input from the Source Origin can ever trigger the dangerous sink, should you conclude "Not Vulnerable".

    Simply finding a control check is NOT sufficient proof of safety. You must prove the check itself is flawless and always active for this specific call path.

    If you confirm one or more vulnerabilities, set is_vulnerable to "Vulnerable", report the most relevant vulnerability_type, and detail all confirmed issues and your path-based reasoning in the reasoning field.

    Return one `VulnerabilityFinding` object with JSON format summarizing your end-to-end analysis for this data flow path.

    ---
    **Source Origin**:
    {source_origin}

    ---
    **Full Code Context**:
    {full_code}

    --- 
    **Call Chain**:
    {call_chain_context}
    
    **Analysis Target Function**: `{current_function_name}`

    ---
    **Expert's Hypotheses**:
    {hypotheses_for_prompt}
    
    ---
    Output Format Instructions:
    {format_instructions}
    """
    
    # 1. Get the instructions string *once*
    analyzer_format_instructions = pydantic_parser.get_format_instructions()

    # 2. Create the PromptTemplate *with* the placeholder
    prompt = PromptTemplate.from_template(prompt_template_str)

    # 3. Use .partial() to safely pre-fill the format_instructions
    partial_prompt = prompt.partial(format_instructions=analyzer_format_instructions)

    # 4. Create the chain using the partial prompt
    chain = partial_prompt | vd_superviser | output_fixing_parser
    # --- *** END CORRECTION *** ---


    # 2. Create worker function (worker no longer needs format_instructions)
    worker_fn = partial(_run_analyzer_task,
                        shared_context=full_context,
                        chain=chain) # Pass the final chain
    
    final_findings_for_this_group = []
    
    # 3. Run all verification tasks in parallel
    with ThreadPoolExecutor(max_workers=MAX_LLM_CONCURRENCY) as executor:
        # results is a List[Optional[VulnerabilityFinding.dict()]]
        results = list(tqdm(
            executor.map(worker_fn, agent_3_todo_queue),
            total=len(agent_3_todo_queue),
            desc="  Verifying Nodes"
        ))
        
        # Collect *successful* results
        for finding_dict in results:
            if finding_dict:
                final_findings_for_this_group.append(finding_dict)

    print(f"  - Batch verification complete. Confirmed {len(final_findings_for_this_group)} vulnerabilities.")
    
    # --- *** CRITICAL ***: Clean up state and accumulate results ---
    return {
        "completed_findings": state["completed_findings"] + final_findings_for_this_group,
        "agent_3_todo_queue": [], # Clear the queue
        "current_variable_group": None # Clear the context, this group is done
    }


def cleanup_variable_group(state: GraphState) -> Dict[str, Any]:
    """Cleans up the state after a variable group is fully processed (and no dangerous sinks were found)."""
    print("\n--- [Node: Cleanup Variable Group] ---")
    print("  - No dangerous sinks found/verified for this group. Cleaning up and continuing.")
    return {
        "current_variable_group": None,
        "screener_todo_queue": [],
        "agent_3_todo_queue": []
    }

################################################################################
# SECTION 5: GRAPH ROUTING LOGIC
################################################################################

def decide_next_action(state: GraphState) -> str:
    """The main router for the graph."""
    print("\n--- [Router: Decide Next Action] ---")
    if state["trace_queue"] or state["discovery_queue"]:
        print("  - Decision: Analysis queues are not empty. Continue to Agent 1.")
        return "agent_1"
    if state["final_analysis_queue"]:
        print("  - Decision: Final analysis queue is not empty. Proceed to Agent 2 for grouping.")
        return "agent_2_retriever"
    print("  - Decision: All queues are empty. Workflow complete.")
    return END

def route_after_retriever(state: GraphState) -> str:
    """Router after Agent 2. Checks if Agent 2 generated any sinks to screen."""
    print("\n--- [Router: After Retriever] ---")
    if state["screener_todo_queue"]:
        print(f"  - Decision: {len(state['screener_todo_queue'])} nodes to screen. Proceed to Agent 2.5 Batch.")
        return "agent_2_5_screener_batch"
    else:
        print("  - Decision: No terminal sinks found for this variable group. Proceed to cleanup.")
        return "cleanup_variable_group"
        
# --- *** NEW ROUTER *** ---
def route_after_screener_batch(state: GraphState) -> str:
    """Router after Agent 2.5 Batch. Checks if any dangerous sinks were found and put in Agent 3's queue."""
    print("\n--- [Router: After Screener Batch] ---")
    if state["agent_3_todo_queue"]:
        print(f"  - Decision: {len(state['agent_3_todo_queue'])} dangerous nodes found. Proceed to Agent 3 Batch Analyzer.")
        return "agent_3_analyzer_batch"
    else:
        print("  - Decision: No dangerous sinks confirmed by screener. Proceed to cleanup.")
        return "cleanup_variable_group"

################################################################################
# SECTION 6: GRAPH DEFINITION
################################################################################

workflow = StateGraph(GraphState)

# 1. Register all nodes
workflow.add_node("load_and_initialize", load_and_initialize)
workflow.add_node("agent_1", agent_1_identifier)
workflow.add_node("process_agent_1_output", process_agent_1_output)
workflow.add_node("agent_2_retriever", agent_2_retriever)
workflow.add_node("agent_2_5_screener_batch", agent_2_5_screener_batch)
workflow.add_node("agent_3_analyzer_batch", agent_3_analyzer_batch)
workflow.add_node("cleanup_variable_group", cleanup_variable_group)

# 2. Set entry point
workflow.set_entry_point("load_and_initialize")

# 3. Define unconditional edges
workflow.add_edge("agent_1", "process_agent_1_output")

# 4. Define conditional edges (Main Loop)
workflow.add_conditional_edges(
    "load_and_initialize",
    lambda s: "agent_1" if s["discovery_queue"] else END,
)
workflow.add_conditional_edges(
    "process_agent_1_output",
    decide_next_action, 
    {"agent_1": "agent_1", "agent_2_retriever": "agent_2_retriever", END: END}
)

# 5. Define Variable Group Sub-Loop
workflow.add_conditional_edges(
    "agent_2_retriever",
    route_after_retriever, 
    {"agent_2_5_screener_batch": "agent_2_5_screener_batch", "cleanup_variable_group": "cleanup_variable_group"}
)

# --- *** CORRECTED BLOCK *** ---
workflow.add_conditional_edges(
    "agent_2_5_screener_batch", 
    route_after_screener_batch, 
    {"agent_3_analyzer_batch": "agent_3_analyzer_batch", "cleanup_variable_group": "cleanup_variable_group"}
)
# --- *** END OF CORRECTION *** ---


# 6. Define exits from the sub-loop (back to main loop)
workflow.add_conditional_edges(
    "agent_3_analyzer_batch",
    decide_next_action, 
    {"agent_1": "agent_1", "agent_2_retriever": "agent_2_retriever", END: END}
)
workflow.add_conditional_edges(
    "cleanup_variable_group",
    decide_next_action, 
    {"agent_1": "agent_1", "agent_2_retriever": "agent_2_retriever", END: END}
)

# 7. Compile
app = workflow.compile()

################################################################################
# SECTION 7: MAIN EXECUTION
################################################################################
if __name__ == "__main__":
    # vul_files = ['/home/CVE-2025-46836_CWE121.c']
    vul_files = glob.glob('/vultrigger/src_code/vul'+'/*.c') #input path
    for vul_file in tqdm(vul_files):
        print(f"\n==================== Analyzing File: {vul_file} ====================")
        name = vul_file.split('/')[-1].split('.c')[0]+'.json'
        
        if os.path.exists('/vultrigger/src_code/vul/'+name):
            print(f"{name} has been processed!")
            continue

        initial_state = {
            "file_path": vul_file,
            "completed_findings": [], 
            "final_analysis_queue": [],
            "rooted_call_graphs": {}, 
            "last_finished_task": None,
            "agent1_result": [], 
            "current_final_analysis_context": None, # This field is no longer used, but harmless
            "current_variable_group": None,
            "screener_todo_queue": [],
            "agent_3_todo_queue": [], # *** NEW ***
            "queued_functions": set(),
            "discovery_queue": [],
            "trace_queue": []
        }
        
        try:
            final_state = app.invoke(initial_state, {"recursion_limit": 8000})

            print("\n==================== Workflow Execution Finished ====================")
            if final_state and final_state.get("completed_findings"):
                final_findings = final_state.get("completed_findings")
                print("\nFinal Findings:")
                res = json.dumps(final_findings, indent=4)
                print(res)
                
                with open('/vultrigger/src_code/vul/'+name,'w') as jf:   #output path
                    json.dump(final_findings, jf, indent=4, ensure_ascii=False)
            else:
                print("\nNo vulnerabilities found.")
                
        except Exception as e:
            print(f"\n!!!!!!!!!!!!!! FATAL ERROR during workflow execution !!!!!!!!!!!!!!")
            print(f"File: {vul_file}")
            print(f"Error: {e}")
            import traceback
            traceback.print_exc()
            print("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
            continue