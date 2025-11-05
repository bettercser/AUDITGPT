import json
from typing import TypedDict, Literal, List, Dict, Any
from langchain_openai import ChatOpenAI
from langgraph.graph import StateGraph, END
from dotenv import load_dotenv
from langchain_community.tools import ShellTool

# Assume all imports are correct
from agents.agent_d import create_agent_d, create_agent_d_with_retry_context, create_agent_d_with_dnslog, create_agent_d_with_dnslog_with_retrycontext
from agents.agent_e import create_agent_e, create_agent_e_with_retry_context
from agents.agent_b import create_agent_b_analyzer, create_agent_b_synthesizer, create_agent_b_with_retry_context
from agents.agent_g import create_agent_g
from agents.agent_a import create_agent_a
from agents.agent_c import create_agent_c
from agents.agent_f import create_agent_f
from prompts.easy_prompts import get_vuln_specific_prompt
from prompts.retry_prompts import get_adjustment_strategy, get_bypass_techniques_for_retry, should_retry_based_on_failure
from tools.ast_analyzer import DataFlowTracer
from utils.logger_config import get_logger
from test.code_test import CodeLookupTool, MethodTracerTool
from utils.todo_manager import TodoManager, TaskPriority
from utils.interactive_todo import DynamicTodoManager
from utils.llm_task_planner import create_adaptive_planner

from tools.dnslog_tools import get_dnslog_subdomain, check_dnslog_records
from requestrepo import Requestrepo

# Import vector RAG tools
try:
    from tools.vector_rag_tool import create_vector_rag_tool, create_vector_method_tracer
    HAS_VECTOR_RAG = True
except ImportError:
    HAS_VECTOR_RAG = False
    print("⚠️ Vector RAG tools not available, using traditional method tracing")

logger = get_logger(__name__)
shell_tool = ShellTool()

class AgentState(TypedDict):
    initial_json: dict
    source_code: Dict[str, str]
    call_chain: List[Dict[str, Any]]
    cookie: str | None
    task_type: Literal["poc_generation", "false_positive_detection", ""]
    exploitability_assessment: Dict[str, Any]
    c_f_discussion_history: List[str]
    c_f_discussion_count: int
    route_info: dict
    modification_functions: List[Dict[str, Any]]
    focused_code_context: str
    poc_details: Dict[str, Any]
    poc_verification_result: Dict[str, Any]
    final_result: str
    agent_b_tool_result: List[Dict[str, Any]] | None
    last_curl_result: str | None
    agent_e_tool_result: str | None
    retry_count: int
    retry_history: List[Dict[str, Any]]
    failure_analysis: Dict[str, Any]
    adjustment_strategy: str | None
    original_route_info: Dict[str, Any]
    bypass_techniques_used: List[str]

    d_e_can_use_dnslog: bool

    agent_g_feedback: str
    review_count: int

    c_f_last_action: str | None
    todo_manager: TodoManager | None

class GraphApp:

    
    def __init__(self, api_url: str, api_key: str, model_name: str, code_lookup_tool: CodeLookupTool, target_host: str = "http://127.0.0.1:8090", ):
        self.api_url = api_url
        self.api_key = api_key
        self.model_name = model_name
        self.target_host = target_host
        logger.info(f"GraphApp initialized. Target host: {self.target_host}")
        self.client = None

        
        self.method_tracer_tool = MethodTracerTool(code_lookup_tool)
        code_lookup_tool._parse_all_files()
        
        self.vector_rag_tool = None
        self.vector_method_tracer = None
        if HAS_VECTOR_RAG:
            try:
                source_base_dir = code_lookup_tool.source_base_dir
                self.vector_rag_tool = create_vector_rag_tool(str(source_base_dir), "./vector_db")
                self.vector_method_tracer = create_vector_method_tracer(self.vector_rag_tool)
                logger.info("✅ Vector RAG tools initialized successfully")
            except Exception as e:
                logger.warning(f"⚠️ Failed to initialize vector RAG tools: {e}")
        
        self.adaptive_planner = create_adaptive_planner(api_url, api_key, model_name)
        self.todo_manager = DynamicTodoManager(llm_planner=self.adaptive_planner.llm_planner)

    def _create_llm(self, json_mode: bool = True) -> ChatOpenAI:
        params = {"model": self.model_name, "temperature": 0, "base_url": self.api_url, "api_key": self.api_key, "max_tokens": 8190}
        if json_mode:
            return ChatOpenAI(model=self.model_name, temperature=0, base_url=self.api_url, api_key=self.api_key, max_tokens=8192).with_structured_output(method="json_mode")
        return ChatOpenAI(model=self.model_name, temperature=0, base_url=self.api_url, api_key=self.api_key, max_tokens=8192)





    def agent_g_node(self, state: AgentState):
        logger.info("--- Entering Agent G Node ---")
        print("--- Node: Agent G (Route Analyzer) ---")
        agent_g = create_agent_g(self._create_llm(json_mode=True))

        invoke_str = {
            "exploitability_assessment": json.dumps(state.get("exploitability_assessment")),
            "route_info": json.dumps(state.get("route_info")),
            "source_code": "\n\n".join(f"// File: {path}\n{code}" for path, code in state["source_code"].items()),
            "call_chain": json.dumps(state.get("call_chain"), indent=2, ensure_ascii=True)
        }

        response = agent_g.invoke(invoke_str)
        logger.info(f"Agent G Review Result: {response}")

        review_count = state.get("review_count", 0)
        if response.get("decision") == "reject":
            print(f"--- Agent G Decision: REJECT. Feedback: {response.get('feedback')} ---")
            return {"agent_g_feedback": response.get("feedback"), "review_count": review_count + 1}
        else:
            print("--- Agent G Decision: APPROVE ---")
            return({"agent_g_feedback": None, "review_count": 0})


    # --- Agent nodes (unchanged) ---
    def agent_b_node(self, state: AgentState):
        logger.info("--- Entering Agent B Node ---")
        
        tool_result = state.get("agent_b_tool_result")
        tool_result_str = json.dumps(tool_result if tool_result is not None else "N/A")
        source_code_context_str = "\n\n".join(f"// File: {path}\n{code}" for path, code in state["source_code"].items())

        # --- ** Core Change: Dynamically Select Agent ** ---
        if tool_result is None:
            print("--- Node: Agent B (Analyzer Role) ---")
            agent_b = create_agent_b_analyzer(self._create_llm(json_mode=True))
            # Analyzer doesn't need tool_result
            invoke_str = {
                "call_chain": json.dumps(state["call_chain"], indent=2, ensure_ascii=False),
                "source_code": source_code_context_str,
                "feedback": state.get("agent_g_feedback", None)
            }
        else:
            print("--- Node: Agent B (Synthesizer Role) ---")
            agent_b = create_agent_b_synthesizer(self._create_llm(json_mode=True))
            # Synthesizer needs all information
            invoke_str = {
                "call_chain": json.dumps(state["call_chain"], indent=2, ensure_ascii=False),
                "source_code": source_code_context_str,
                "tool_result": tool_result_str,
                "feedback": state.get("agent_g_feedback", None)
            }
            
        # --- Subsequent logic remains unchanged ---
        response = agent_b.invoke(invoke_str)
        
        if response.get("action") == "call_tool":
            tool_input = response["action_input"]
            if tool_input["tool_name"] == "ast_analyzer":
                tracer = DataFlowTracer(state["source_code"])
                flow_result = tracer.trace_parameter_flow(
                    start_class_name=tool_input["class_name"],
                    start_method_name=tool_input["method_name"],
                    parameter_to_trace=tool_input["parameter_to_trace"]
                )
                return {"agent_b_tool_result": flow_result}
                
        elif response.get("action") == "finalize_response":
            final_data = response["action_input"]
            return {
                "route_info": final_data["route_info"],
                "modification_functions": final_data["modification_functions"],
                "agent_b_tool_result": None, # **Critical**: Must reset tool result after completion
                "d_e_can_use_dnslog": final_data["d_e_can_use_dnslog"]
            }
            
        # Handle unexpected situations
        return {"agent_b_tool_result": [{"error": "Agent B returned unexpected action or format."}]}
    

    def agent_d_node(self, state: AgentState):
        logger.info("--- Entering Agent D Node ---")
        print("--- Node: Agent D (PoC Generator) ---")
        can_use_dnslog = state.get("d_e_can_use_dnslog", None)
        retry_count = state.get("retry_count", 0)


        if can_use_dnslog is True:
            print("---------------------------------------------d use dnslog-----------------------------------------------------------------")
            if retry_count > 0:
                agent_d = create_agent_d_with_dnslog_with_retrycontext(self._create_llm(json_mode=True), state)
            else:
                agent_d = create_agent_d_with_dnslog(self._create_llm(json_mode=True))
                self.client = get_dnslog_subdomain()
        else:



            if retry_count > 0:
                print("--- Agent D is using retry context ---")
                agent_d = create_agent_d_with_retry_context(self._create_llm(json_mode=True), state)
            else:
                agent_d = create_agent_d(self._create_llm(json_mode=True))

        
        vuln_type = state.get("route_info", {}).get("vuln_type", "default")
        vuln_specific_prompt_text = get_vuln_specific_prompt(vuln_type)
        cookie_str = state.get("cookie") or "N/A"
        
        invoke_str = {
            "route_info": state["route_info"],
            "modification_functions": state["modification_functions"],
            "source_code": state["focused_code_context"],
            "discussion_history": "",
            "current_thought": f"Attempt {retry_count + 1}. Applying {state.get('adjustment_strategy', 'initial')} strategy.",
            "vuln_specific_prompt": vuln_specific_prompt_text,
            "cookie": cookie_str
        }
        if can_use_dnslog is True:
            invoke_str["subdomain"] = self.client.domain

        response = agent_d.invoke(invoke_str)
        if response is None:
            error_msg = "Agent D's LLM call returned None."
            logger.error(error_msg)
            return {"poc_details": {"error": error_msg}, "last_curl_result": "LLM_CALL_FAILED"}
        poc_details_json = response.get("poc_details", {})
        command_to_execute = response.get("curl_command", "").replace("http://localhost:8080", self.target_host)
        if not command_to_execute:
            error_msg = "Agent D failed to generate curl command."
            logger.error(error_msg)
            return {"poc_details": poc_details_json, "last_curl_result": error_msg}
        logger.debug(f"Executing command: {command_to_execute}")
        shell_result = shell_tool.invoke({"commands": [command_to_execute]})
        logger.debug(f"Shell tool result: {shell_result}")
        return {"poc_details": poc_details_json, "last_curl_result": shell_result}

    def agent_e_node(self, state: AgentState):

        can_use_dnslog = state.get("d_e_can_use_dnslog", None)

        if can_use_dnslog is True:
            
            if check_dnslog_records(client=self.client):
                return {"poc_verification_result": {"success": True, "details": "Successfully obtained DNS log records proving successful exploitation"}}
            else:
                return {"poc_verification_result": {"success": False, "failure_type": "unexpected_action", "details": "No DNS log records received, need to regenerate PoC"}}

        logger.info("--- Entering Agent E Node ---")
        print("--- Node: Agent E (Validator) ---")
        retry_count = state.get("retry_count", 0)
        llm_raw = self._create_llm(json_mode=False)
        if retry_count > 0:
            print("--- Agent E is using retry context ---")
            reviewer_chain = create_agent_e_with_retry_context(llm_raw, state)
        else:
            reviewer_chain = create_agent_e(llm_raw)
        initial_result = state.get("last_curl_result", "N/A")
        follow_up_result = state.get("agent_e_tool_result") if state.get("agent_e_tool_result") is not None else "N/A"
        response_message = reviewer_chain.invoke({"route_info" : state["route_info"],"initial_curl_result": initial_result,"redirect_follow_up_result": follow_up_result})
        raw_response_text = response_message.content
        logger.debug(f"Agent E raw response text: {raw_response_text}")
        try:
            clean_text = raw_response_text
            if "```json" in raw_response_text:
                clean_text = raw_response_text.split("```json")[1].split("```")[0].strip()
            response = json.loads(clean_text)
        except (json.JSONDecodeError, IndexError) as e:
            error_msg = f"Failed to parse JSON from Agent E. Error: {e}. Raw text: {raw_response_text}"
            logger.error(error_msg)
            return {"poc_verification_result": {"success": False, "failure_type": "json_parsing_error", "details": error_msg}, "agent_e_tool_result" : None}
        if response.get("action") == "call_tool":
            logger.info(f"Agent E requested redirect follow-up: {response['action_input']}")
            tool_input = response["action_input"]
            if tool_input["tool_name"] == "shell_tool":
                command_to_execute = tool_input["command"]
                if state.get("cookie"):
                    command_to_execute = command_to_execute.replace("your_cookie_here", state["cookie"])
                command_to_execute = command_to_execute.replace("http://localhost:8080", self.target_host)
                shell_result = shell_tool.invoke({"commands": [command_to_execute]})
                return {"agent_e_tool_result": shell_result}
        elif response.get("action") in ["finalize_response", "suggest_retry"]:
            final_data = response["action_input"]
            return {"poc_verification_result": final_data, "agent_e_tool_result": None}
        logger.error(f"Agent E returned unexpected action: {response}")
        return {"poc_verification_result": {"success": False, "failure_type": "unexpected_action", "details": "Agent E returned unexpected action."}}

    def retry_analysis_node(self, state: AgentState):
        logger.info("--- Entering Retry Analysis Node ---")
        print("--- Node: Retry Analysis ---")
        poc_verification = state.get("poc_verification_result", {})
        retry_count = state.get("retry_count", 0)
        failure_type = poc_verification.get("failure_type", "unknown")
        details = poc_verification.get("details", "")
        adjustment_strategy = get_adjustment_strategy(failure_type, retry_count + 1)
        failure_analysis = {"failure_type": failure_type, "details": details, "retry_attempt": retry_count + 1}
        retry_history = state.get("retry_history", [])
        retry_history.append({"attempt": retry_count + 1,"failure_type": failure_type,"strategy_used": state.get("adjustment_strategy", "initial"),"result_details": details})
        logger.info(f"Retry analysis completed. Strategy: {adjustment_strategy}, Failure type: {failure_type}")
        return {"failure_analysis": failure_analysis, "adjustment_strategy": adjustment_strategy, "retry_history": retry_history}

    def strategy_adjustment_node(self, state: AgentState):
        logger.info("--- Entering Strategy Adjustment Node ---")
        print("--- Node: Strategy Adjustment ---")
        retry_count = state.get("retry_count", 0) + 1
        logger.info(f"Preparing for retry attempt {retry_count}.")
        return {"retry_count": retry_count,"poc_details": {},"last_curl_result": None,"agent_e_tool_result": None,"poc_verification_result": {}}

    def agent_a_node(self, state: AgentState):
        logger.info("--- Entering Agent A Node ---")
        print("--- Node: Agent A is analyzing call chain and making decisions ---")
        
        # Update TODOLIST status
        self._update_todo_status(state, "agent_a")
        
        llm = self._create_llm(json_mode=True)
        agent_a_runnable = create_agent_a(llm)
        source_code_context_str = "\n\n".join(f"// File: {path}\n{code}" for path, code in state["source_code"].items())
        invoke_input = {"call_chain": json.dumps(state["call_chain"], indent=2, ensure_ascii=False), "source_code_context": source_code_context_str}
        logger.debug(f"Agent A input payload: {invoke_input}")
        response = agent_a_runnable.invoke(invoke_input)
        logger.info(f"Agent A raw response: {response}")
        
        # Complete TODOLIST task
        self._complete_todo_task(state, "agent_a", {"task_type": response["task_type"]})
        
        # Show updated TODOLIST
        if state.get("todo_manager"):
            print("\n--- Current TODOLIST Status ---")
            print(state["todo_manager"].get_overall_display())
        
        return {"task_type": response["task_type"]}

    def agent_c_node(self, state: AgentState):
        logger.info("--- Entering Agent C Node ---")
        print("--- Node: Agent C is analyzing exploitability ---")
        llm = self._create_llm(json_mode=True)
        agent_c = create_agent_c(llm)
        source_code_context_str = "\n\n".join(f"// File: {path}\n{code}" for path, code in state["source_code"].items())
        thought = "This is my first analysis. I need to determine the authenticity of this vulnerability."
        history = state.get("c_f_discussion_history", [])
        if state.get('c_f_last_action') == 'lookup_method': # Check if previous step was a tool call
            thought = "The tool returned new code, I now need to continue analysis based on this new information."


        if state.get('c_f_discussion_history'):
            thought = f"Agent F has new input: {state['c_f_discussion_history'][-1]}"

        response = agent_c.invoke({"source_code": source_code_context_str, "discussion_history": "\n".join(history), "current_thought": thought})
        logger.info(f"Agent C structured analysis: {response}")

        action = response.get("action")

        if action == "lookup_method":
            print(f"--- Agent C requested tool call: {response['reason_for_lookup']} ---")
            tool_input = response['tool_input']

            history.append(f"Agent C's thought: {response['reason_for_lookup']}")
            
            # Use vector RAG tools for more intelligent method tracing (if available)
            if self.vector_method_tracer:
                print("🔍 Using vector RAG tool for semantic method tracing...")
                trace_result = self.vector_method_tracer.trace_method_with_context(
                    class_name=tool_input['class_name'],
                    method_name=tool_input['method_name'],
                    param_count=tool_input['param_count'],
                    semantic_context=response['reason_for_lookup']
                )
                tool_name = "VectorRAGTool"
            else:
                # Fall back to traditional method tracing
                trace_result = self.method_tracer_tool.trace_method_logic(
                    class_name=tool_input['class_name'],
                    method_name=tool_input['method_name'],
                    param_count=tool_input['param_count']
                )
                tool_name = "MethodTracerTool"

            tool_output_str = json.dumps(trace_result, indent=2, ensure_ascii=False)
            history.append(f"Tool ({tool_name}) returned code:\n```json\n{tool_output_str}\n```")
            print("--- Tool executed, new code added to context. Will loop back to Agent C. ---")

            return {
                "c_f_discussion_history": history,
                "c_f_last_action": "lookup_method" # Set a flag indicating need to loop
            }
        
        elif action == "finalize_analysis":
            print("--- Agent C has made final analysis. ---")
            final_analysis = response['analysis']
            
            history.append(f"Agent C final analysis: {json.dumps(final_analysis, indent=2, ensure_ascii=False)}")
            
            # Update state, prepare to enter next node (Agent F)
            count = state.get("c_f_discussion_count", 0) + 1
            return {
                "c_f_discussion_history": history,
                "c_f_discussion_count": count,
                "exploitability_assessment": final_analysis,
                "c_f_last_action": "finalize_analysis" # Flag indicating can continue
            }

        
        history.append(f"Agent C analysis: {json.dumps(response, indent=2, ensure_ascii=False)}")
        count = state.get("c_f_discussion_count", 0) + 1
        return {"c_f_discussion_history": history, "c_f_discussion_count": count, "exploitability_assessment": response, "c_f_last_action": "finalize_analysis"}

    def agent_f_node(self, state: AgentState):
        logger.info("--- Entering Agent F Node ---")
        print("--- Node: Agent F is reviewing and making final decision ---")
        llm = self._create_llm(json_mode=True)
        agent_f = create_agent_f(llm)
        source_code_context_str = "\n\n".join(f"// File: {path}\n{code}" for path, code in state["source_code"].items())
        response = agent_f.invoke({"source_code": source_code_context_str, "discussion_history": "\n".join(state.get("c_f_discussion_history", [])), "current_thought": "I will now make the final decision."})
        logger.info(f"Agent F final decision: {response}")
        history = state.get("c_f_discussion_history", [])
        history.append(f"Agent F decision: {json.dumps(response, indent=2, ensure_ascii=False)}")
        return {"c_f_discussion_history": history, "exploitability_assessment": response}

    def prepare_d_context_node(self, state: AgentState):
        logger.info("--- Entering Prepare D Context Node ---")
        print("--- Node: Preparing focused context for Agent D ---")
        source_files = state["source_code"]
        modification_functions = state["modification_functions"]
        context_snippets = []
        entry_point_file = state["call_chain"][0]["file"]
        context_snippets.append(f"// File: {entry_point_file}\n{source_files.get(entry_point_file, 'Source code not found.')}")
        for func_call in modification_functions:
            file_path = func_call.get("file_path") 
            if file_path and file_path not in entry_point_file:
                 context_snippets.append(f"// File: {file_path}\n{source_files.get(file_path, 'Source code not found.')}")
        focused_context = "\n\n".join(context_snippets)
        logger.debug(f"Focused context for Agent D generated. Length: {len(focused_context)}")
        return {"focused_code_context": focused_context}

    def final_report_node(self, state: AgentState):
        logger.info("--- Entering Final Report Node ---")
        print("--- Node: Generating final report from structured assessment ---")
        assessment = state.get("exploitability_assessment")
        if not assessment:
            final_conclusion = "Conclusion: Analysis failed, no exploitability assessment generated."
        else:
            status = assessment.get("status", "unknown").replace("_", " ").title()
            reason = assessment.get("reason", "No reason provided.")
            final_conclusion = f"Conclusion: {status}\nReason: {reason}"
        logger.info(f"Final report generated:\n{final_conclusion}")
        return {"final_result": final_conclusion}
    
    def final_poc_node(self, state: AgentState):
        logger.info("--- Entering Final PoC Node ---")
        print("--- Node: Outputting final PoC verification results ---")
        verification_result = state.get("poc_verification_result", {})
        poc_details = state.get("poc_details", {})
        vuln_type = state.get("initial_json", {}).get("vuln_type", "Unknown")
        success_status = "Success" if verification_result.get("success") else "Failure"
        details = verification_result.get("details", "No detailed information provided.")
        retry_history_str = json.dumps(state.get("retry_history", []), indent=2, ensure_ascii=False)

        # Add TODOLIST summary
        todo_summary = ""
        if state.get("todo_manager"):
            todo_summary = f"\n-------------------\nTODOLIST Summary:\n{state['todo_manager'].get_task_summary()}"

        final_report = f"""
Vulnerability Type: {vuln_type}
Verification Result: [{success_status}]
-------------------
Agent E Analysis Details:
{details}
-------------------
Agent D PoC Details:
{json.dumps(poc_details, indent=2, ensure_ascii=False)}
-------------------
Final Curl Execution Output:
{state.get('last_curl_result')}
-------------------
Retry History:
{retry_history_str}{todo_summary}
"""
        logger.info(f"Final PoC report generated:\n{final_report}")
        return {"final_result": final_report}

    def initialize_todo_node(self, state: AgentState):
        """Initialize TODOLIST node with dynamic task generation"""
        logger.info("--- Entering Initialize TODO Node ---")
        print("--- Node: Initializing TODOLIST for multi-agent workflow ---")
        
        # Initialize TODOLIST with vulnerability data
        vulnerability_data = {
            'vuln_id': state['initial_json'].get('vuln_id', 'unknown'),
            'call_chain': state['call_chain'],
            'source_code': state['source_code']
        }
        
        self.todo_manager.initialize_for_vulnerability(vulnerability_data)
        
        logger.info("TODOLIST initialization completed with dynamic task generation")
        print("TODOLIST initialization completed:")
        print(self.todo_manager.get_overall_display())
        
        return {"todo_manager": self.todo_manager}

    def _update_todo_status(self, state: AgentState, agent_name: str) -> bool:
        """Update TODOLIST status and start agent task"""
        if state.get("todo_manager"):
            return state["todo_manager"].start_agent_task(agent_name)
        return False

    def _complete_todo_task(self, state: AgentState, agent_name: str, result: Any = None) -> bool:
        """Complete agent task in TODOLIST"""
        if state.get("todo_manager"):
            return state["todo_manager"].mark_agent_task_complete(agent_name, result)
        return False

    
    def should_agent_b_continue(self, state: AgentState):
        if state.get("agent_b_tool_result") is None:
            return "proceed"
        else:
            return "continue"


    def route_after_agent_g(self, state: AgentState):
        review_count = state.get("review_count", 0)
        if review_count >= 2:
            return "fail_review"
        return "reject" if state.get("agent_g_feedback") else "approve"

    def route_after_agent_e(self, state: AgentState):
       
        
        
        if state.get("agent_e_tool_result") is not None:
            return "continue_e"

        if state.get("poc_verification_result", {}).get("success"):
            return "success"
        else:
            return "failure"

    def should_retry_payload(self, state: AgentState):
        retry_count = state.get("retry_count", 0)
        verification_result = state.get("poc_verification_result", {})
        
        

        if retry_count >= 3:
            return "final"
        
        failure_type = verification_result.get("failure_type", "unknown")
        retryable_failures = ["permission_denied", "syntax_error", "filtered", "timeout", "network_error", "server_error","unexpected_response"]
        
        if failure_type in retryable_failures:
            return "retry"
        elif failure_type == "unknown" and retry_count < 1:
            return "retry"
        else:
            return "final"
        

    def route_after_agent_c(self, state: AgentState):
        if state.get("c_f_last_action") == "lookup_method":
            return "continue_analysis"
        else:
            return "handover_to_f"

    
    def build_graph(self):
        workflow = StateGraph(AgentState)
        
        workflow.add_node("initialize_todo", self.initialize_todo_node)
        workflow.add_node("agent_a", self.agent_a_node)
        workflow.add_node("agent_c", self.agent_c_node)
        workflow.add_node("agent_f", self.agent_f_node)
        workflow.add_node("agent_b", self.agent_b_node)
        workflow.add_node("prepare_d_context", self.prepare_d_context_node)
        workflow.add_node("agent_d", self.agent_d_node)
        workflow.add_node("agent_e", self.agent_e_node)
        workflow.add_node("retry_analysis", self.retry_analysis_node)
        workflow.add_node("strategy_adjustment", self.strategy_adjustment_node)
        workflow.add_node("final_report", self.final_report_node)
        workflow.add_node("final_poc", self.final_poc_node)
        workflow.add_node("agent_g", self.agent_g_node)
        
        workflow.set_entry_point("initialize_todo")
        workflow.add_edge("initialize_todo", "agent_a")
        workflow.add_edge("agent_a", "agent_c")
        workflow.add_conditional_edges(
            "agent_c",
            self.route_after_agent_c,
            {
                "continue_analysis": "agent_c", 
                "handover_to_f": "agent_f"      
            }
        )
        
        workflow.add_conditional_edges(
            "agent_f",
            lambda s: "handover_to_b" if s["exploitability_assessment"].get("status") == "exploitable" else "generate_report",
            {"generate_report": "final_report", "handover_to_b": "agent_b"}
        )

        workflow.add_conditional_edges("agent_g", self.route_after_agent_g, {"approve": "prepare_d_context", "reject": "agent_b", "fail_review": "final_report"})
        
        workflow.add_conditional_edges(
            "agent_b",
            self.should_agent_b_continue,
            {"continue": "agent_b", "proceed": "agent_g"}
        )
        
        workflow.add_edge("prepare_d_context", "agent_d")
        workflow.add_edge("agent_d", "agent_e")
        
            workflow.add_conditional_edges(
            "agent_e",
            self.route_after_agent_e,
            {
                "continue_e": "agent_e",      
                "success": "final_poc",       
                "failure": "retry_analysis"   
            }
        )
        
        workflow.add_conditional_edges(
            "retry_analysis",
            self.should_retry_payload,
            {
                "retry": "strategy_adjustment",
                "final": "final_poc" 
            }
        )
        
        workflow.add_edge("strategy_adjustment", "agent_b")
        
        workflow.add_edge("final_report", END)
        workflow.add_edge("final_poc", END)
        
        return workflow.compile()
