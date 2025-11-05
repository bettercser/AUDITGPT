import json
import os
# Ensure importing from the updated graph builder file
from graph_builder import GraphApp, AgentState, END
from langgraph.errors import GraphRecursionError
from test.code_test import CodeLookupTool
from utils.sarif_parser import SarifJavaParser 

# --- Third-party API Configuration ---
THIRD_PARTY_API_URL = ""
THIRD_PARTY_API_KEY = ""
MODEL_NAME = "" # Or any model name you want to use

def run_framework(initial_data: dict, SOURCE_CODE_FOLDER: str):
    """
    Run the entire multi-agent framework
    """
    print("="*50)
    print(f"[*] Starting processing vulnerability ID: {initial_data['vuln_id']}")
    print(f"[*] Call chain to analyze (structured):")
    print(json.dumps(initial_data['call_chain'], indent=2, ensure_ascii=False))
    print("="*50)

    # 1. Initialize GraphApp and build graph
    app_builder = GraphApp(
        api_url=THIRD_PARTY_API_URL,
        api_key=THIRD_PARTY_API_KEY,
        model_name=MODEL_NAME,
        code_lookup_tool=CodeLookupTool(SOURCE_CODE_FOLDER)
    )
    app = app_builder.build_graph()

    # 2. Prepare initial state
    initial_state: AgentState = {
        "initial_json": initial_data,
        "source_code": initial_data["source_code"],
        "call_chain": initial_data["call_chain"], # Pass structured data
        "task_type": "",
        "c_f_discussion_history": [],
        "c_f_discussion_count": 0,
        "exploitability_assessment": {},
        "route_info": {},
        "modification_functions": [],
        "focused_code_context": "",
        "poc_details": {},
        "poc_verification_result": {},
        "final_result": "",
        "agent_b_tool_result": None,
        "last_curl_result": None,
        "agent_e_tool_result": None,
        "cookie": "SHIRO_SESSION_ID=ad1c670d-cddc-4445-8989-8f2b7840cd29; Hm_lvt_1cd9bcbaae133f03a6eb19da6579aaba=1756088569; HMACCOUNT=F65BE8A8D0B5F398; Hm_lvt_bfe2407e37bbaa8dc195c5db42daf96a=1756101433; Hm_lpvt_bfe2407e37bbaa8dc195c5db42daf96a=1756101657; csrf_token=9a6961da2294d8cf5abd3dddbfc16285; _jpanonym='NGY4N2RlNWJhZWYxYTY1YzNjMTQ5NjEyNDA0ZTJlMDEjMTc1NjE3NDk2NDAxMSMzMTUzNjAwMCNZV05oTXpCaE0yTXhNR1l4TkRVek5HRTVZV1UzWXpOa1pESmlZbUkxWWpnPQ=='; Hm_lpvt_1cd9bcbaae133f03a6eb19da6579aaba=1756174968; JSESSIONID=5bdf0c75-ea6a-4472-80d0-0c0250b43c2e; rememberMe=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",
        # NEW: Retry mechanism related field initialization
        "retry_count": 0,
        "retry_history": [],
        "failure_analysis": {},
        "adjustment_strategy": "",
        "original_route_info": {},
        "bypass_techniques_used": [],
        "review_count": 0,
        "d_e_can_use_dnslog": None,
        "agent_g_feedback": None,
        "c_f_last_action": None
    }

    # 3. Execute workflow
    final_state = None
    config = {"recursion_limit": 50}
    try: 
        for s in app.stream(initial_state, config=config):
            key = list(s.keys())[0]
            value = s[key]
            print(f"--- Node: {key} ---")
            print(f"--- Output: ---\n{json.dumps(value, indent=2, ensure_ascii=False)}")
            print("-" * 30)
            if END in s:
                final_state = s[END]
                break
    except GraphRecursionError:
        print("\n" + "!"*50)
        print("Error: Graph has entered infinite loop and exceeded recursion limit.")
        print("This usually indicates a flaw in the graph's routing logic, where some condition cannot reach END.")
        print("Please check the graph's conditional edges to ensure all paths can eventually terminate.")
        print("!"*50 + "\n")
        return # Exit this run
    except Exception as e:
        print(f"\nUnexpected error occurred: {e}\n")
        return # Exit this run
    # 4. Print final result
    print("\n" + "="*50)
    print("✅ Task completed!")
    print("Final result:")
    print(final_state)
    print("="*50 + "\n")


if __name__ == "__main__":
    if "YOUR_API_URL_HERE" in THIRD_PARTY_API_URL:
        print("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
        print("!!! WARNING: Please configure your API URL and KEY at the top of main.py !!!")
        print("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n")
    else:
        # --- Run scenario 1: False positive detection ---
        # run_framework(sarif_json_false_positive)
        
        # --- Run scenario 2: PoC generation ---
        # run_framework(sarif_json_poc_generation)


        parser = SarifJavaParser()
        SARIF_FILE = ''
        SARIF_FILE_1 = ''
        SARIF_FILE_FOLDER = ""
        file_entries = os.listdir(SARIF_FILE_FOLDER)
        entries = [file for file in file_entries if not file.startswith('.')]
        print(entries)
        SOURCE_CODE_BASE_DIR = ''

        for file in entries:
            print(file)
                        list_of_reports = parser.parse_sarif(os.path.join(SARIF_FILE_FOLDER, file), source_base_path=SOURCE_CODE_BASE_DIR)

            for j, report in enumerate(list_of_reports):
                # if report['vuln_id'] != "VULN-2":
                #     continue
                # ids = report['vuln_id'].split('-')
                # id = int(ids[1])
                # if id < 89:
                #     continue
                # run_framework(report, SOURCE_CODE_FOLDER=SOURCE_CODE_BASE_DIR)
                print(f"--- Starting processing vulnerability ID: {report['vuln_id']} ---")
                print(report)
                
        # list_of_reports = parser.parse_sarif(SARIF_FILE, source_base_path=SOURCE_CODE_BASE_DIR)

        # new_list_of_reports = parser.parse_sarif(SARIF_FILE_1, source_base_path=SOURCE_CODE_BASE_DIR)

        # for i, report in enumerate(list_of_reports):
        #     run_framework(report)
