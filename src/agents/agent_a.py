from langchain_core.prompts import ChatPromptTemplate
from langchain_openai import ChatOpenAI

def create_agent_a(llm):
    """
    Create Agent A: Task Dispatch Supervisor
    - Task: Analyze function call chains to determine whether the task should proceed with PoC generation or false positive detection.
    """
    prompt = ChatPromptTemplate.from_messages([
        ("system",
         """You are a top-level security task dispatch supervisor (Agent A).
Your responsibility is to analyze given function call chains to determine the subsequent work direction.

**Decision Rules**:
1.  If the call chain contains web framework routing entry characteristics (e.g., Java Spring's `@RequestMapping`, `@GetMapping`, or `javax.servlet.http.HttpServlet` methods), this typically means it's an externally exposed API that requires **PoC generation**.
2.  If no obvious web routing entry is found in the call chain, and it appears more like an internal function call or library function, then it's likely part of a complete vulnerability call chain that requires **false positive detection**.

**Output Format Requirements**:
You must strictly follow the JSON format below without any additional explanations.
```json
{{
  "task_type": "poc_generation"
}}
```
or
```json
{{
  "task_type": "false_positive_detection"
}}
```

### Call Chain Information:
{call_chain}

### Complete Code Context:
{source_code_context}
"""),
        ("human", "Please analyze and make decisions based on the above call chain and code context.")
    ])
    
    return prompt | llm