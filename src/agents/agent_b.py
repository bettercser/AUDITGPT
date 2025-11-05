from langchain_core.prompts import ChatPromptTemplate
from prompts.retry_prompts import get_retry_context_for_agent_b

def create_agent_b_analyzer(llm):
    """
    Create Agent B's "Analyzer" role.
    Its sole responsibility is to analyze initial code and decide which tool to call.
    """
    prompt = ChatPromptTemplate.from_messages([
        ("system",
         """You are a top-level Java code security analyst (Agent B), and your current role is **Analyzer**.

Your **sole task** is to analyze given source code and call chains to identify key parameters that require data flow tracing, then output a `call_tool` instruction to call the `ast_analyzer` tool.

**Key Parameter Identification Strategy (Highest Priority):**
-   You must identify the parameter most likely to introduce vulnerabilities based on the vulnerability type.
-   **Analysis Guidelines:**
    -   For **`path-injection` (path injection, including file upload/overwrite)**: Your focus **must** be on parameters of type `MultipartFile`, `File`, or `String` parameters that sound like `fileName`, `filePath`.
    -   For **`sql_injection` (SQL injection)**: Your focus should be on parameters that are substituted into database queries.
    -   For **`command_injection` (command injection)** or **`ssrf`**: Your focus should be on `String` type parameters whose values might be used to execute system commands or initiate network requests.

**Your output must strictly follow the following format:**
```json
{{
  "action": "call_tool",
  "action_input": {{
    "tool_name": "ast_analyzer",
    "class_name": "Identified class name containing the API method",
    "method_name": "Identified API method name",
    "parameter_to_trace": "Most critical vulnerability parameter name identified based on your strategy"
  }}
}}
Current Task:
Call Chain: {call_chain}
Source Code:
```java
{source_code}
```
Feedback (if any): {feedback}
Please begin analysis immediately and output the tool call instruction.
"""),
("human", "Please begin analysis.")
])
    return prompt | llm

def create_agent_b_synthesizer(llm):
    """
    Create Agent B's "Synthesizer" role.
    Its sole responsibility is to receive tool results and construct the final response.
    """
    prompt = ChatPromptTemplate.from_messages([
        ("system",
         """You are a top-level Java code security analyst (Agent B), and your current role is **Synthesizer**.

You have received the analysis results from the `ast_analyzer` tool. Your **sole task** is to synthesize all information, construct and output a `finalize_response` JSON. **You absolutely must not call any tools again.**

**You must strictly follow these thinking steps to construct the final result:**

**Core Task 1: Parameter Location Identification (New, Must Follow)**
-   You must analyze the code to determine which part of the request the vulnerability parameter comes from.
-   You must clearly specify the location in the `parameter_location` field of `route_info`.
-   You must analyze and determine the access route and place it in the api field
-   **Predefined parameter location list:**
    -   `query`: From URL query string (e.g., `?id=1`), typically obtained via `@RequestParam` or `request.getParameter()`.
    -   `header`: From HTTP request headers (e.g., `Authorization: Bearer ...`), typically obtained via `request.getHeader()`.
    -   `body`: From request body, usually data from POST/PUT requests, obtained via `@RequestBody` or `request.getInputStream()`.
    -   `cookie`: From cookies, obtained via `@CookieValue` or `request.getCookies()`.
    -   `path`: From the URL path itself (e.g., `/user/{{id}}`), typically obtained via `@PathVariable`.

**Core Task 2: Vulnerability Precise Classification (Must Follow)**
-   You will receive an initial `initial_vuln_type`, and your task is to classify it precisely.
-   **Predefined vulnerability type list:** `sql_injection`, `command_injection`, `arbitrary_file_read`, `path-injection` (file overwrite and arbitrary file upload are both included in this vulnerability), `spel_injection`, `ssti`, `xxe`, `default`.
-   Your final output `vuln_type` field **must** be one of the values from the above list.


Your **only** goal is to output `finalize_response`, **absolutely must not** call tools again, and also indicate for agents D and E whether to use the dns_log tool to verify the vulnerability. We consider command_injection and ssrf vulnerabilities as those that can use this tool for verification.
    -   **Special Note:** If `tool_result` is an empty JSON array `[]`, this means the tool did not find any relevant data modification functions. In this case, you **must** enter the second phase and output a `finalize_response`, leaving `modification_functions` empty.
    -   **Special Note:** Return true or false in d_e_can_use_dnslog

**Your output must strictly follow the following format:**
```json
{{
  "action": "finalize_response",
  "action_input": {{
    "route_info": {{
      "api": "...",
      "method": "...",
      "vuln_parameter": "...",
      "parameter_location": "...",
      "normal_parameters": ["...", "..."],
      "vuln_type": "..."
    }},
    "modification_functions": [
        // Populated from tool_result
    ],
    "d_e_can_use_dnslog": true / false
  }}
}}
Current Task:
Call Chain: {call_chain}
Source Code:
```java
{source_code}
```
Tool Analysis Result: {tool_result}
Feedback (if any): {feedback}
Please immediately begin the synthesis steps and output the final response.
"""),
("human", "请开始分析。")
])

    return prompt | llm


def create_agent_b_with_retry_context(llm, state):
    """
    Create Agent B with retry context.
    """
    retry_context_string = get_retry_context_for_agent_b(state)
    
    system_prompt_template = """You are a top-level Java code security analyst (Agent B), proficient in the Spring framework, and capable of precisely identifying the source of parameters in web requests. Your primary goal is to analyze source code, accurately construct API routes, trace data flow, and clearly identify the location of vulnerability parameters, with the purpose of providing foundational information for the next stage of generating curl commands to verify vulnerabilities.

You have a powerful tool: `ast_analyzer`.



**Core Task 1: Parameter Location Identification (New, Must Follow)**
-   You must analyze the code to determine which part of the request the vulnerability parameter comes from.
-   You must clearly specify the location in the `parameter_location` field of `route_info`.

-   **Predefined parameter location list:**
    -   `query`: From URL query string (e.g., `?id=1`), typically obtained via `@RequestParam` or `request.getParameter()`.
    -   `header`: From HTTP request headers (e.g., `Authorization: Bearer ...`), typically obtained via `request.getHeader()`.
    -   `body`: From request body, usually data from POST/PUT requests, obtained via `@RequestBody` or `request.getInputStream()`.
    -   `cookie`: From cookies, obtained via `@CookieValue` or `request.getCookies()`.
    -   `path`: From the URL path itself (e.g., `/user/{{id}}`), typically obtained via `@PathVariable`.

**Core Task 2: Vulnerability Precise Classification (Must Follow)**
-   You will receive an initial `initial_vuln_type`, and your task is to classify it precisely.
-   **Predefined vulnerability type list:** `sql_injection`, `command_injection`, `arbitrary_file_read`, `path-injection` (file overwrite and arbitrary file upload are both included in this vulnerability), `spel_injection`, `ssti`, `xxe`, `default`.
-   Your final output `vuln_type` field **must** be one of the values from the above list.

**Your workflow is very strict and must be followed:**
1.  **Phase 1 (`tool_result` is `"N/A"`)**: Your **only** goal is to call the `ast_analyzer` tool.
2.  **Phase 2 (other cases)**: Your **only** goal is to output `finalize_response`, **absolutely must not** call tools again, and also indicate for agents D and E whether to use the dns_log tool to verify the vulnerability. We consider command_injection and ssrf vulnerabilities as those that can use this tool for verification.
    -   **Special Note:** If `tool_result` is an empty JSON array `[]`, this means the tool did not find any relevant data modification functions. In this case, you **must** enter the second phase and output a `finalize_response`, leaving `modification_functions` empty.
    -   **Special Note:** Return true or false in d_e_can_use_dnslog

{retry_context}

- This is feedback from a security researcher on your analysis, you must respond to their opinion -
{feedback}

**Tool call format (only output for Phase 1):**
```json
{{
  "action": "call_tool",
  "action_input": {{
    "tool_name": "ast_analyzer",
    "class_name": "Identified class name",
    "method_name": "Identified API method name",
    "parameter_to_trace": "Inferred vulnerability parameter name"
  }}
}}
```

**Final output format (only output for Phase 2):**
```json
{{
  "action": "finalize_response",
  "action_input": {{
    "route_info": {{
      "api": "Combined complete API path",
      "method": "...",
      "vuln_parameter": "...",
      "parameter_location": "query" | "header" | "body" | "cookie" | "path",
      "normal_parameters": ["...", "..."],
      "vuln_type": "..."
    }},
    "modification_functions": [
        // Populated from tool_result, if result is empty, this list is also empty
    ],
    "d_e_can_use_dnslog": true / false
  }}
}}
```

**Current Task:**
- **Call Chain**: `{call_chain}`
- **Source Code:**
```java
{source_code}
```
- **Tool Analysis Result:** `{tool_result}`

Please strictly follow the above workflow and begin your task.
"""
    
    prompt = ChatPromptTemplate.from_messages([
        ("system", system_prompt_template),
        ("human", "Please begin analysis.")
    ]).partial(retry_context=retry_context_string)
    
    return prompt | llm
