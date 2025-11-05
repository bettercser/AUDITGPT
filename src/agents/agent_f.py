from langchain_core.prompts import ChatPromptTemplate

def create_agent_f(llm):
    """
    Create Agent F: A senior reviewer that outputs structured final decisions.
    """
    prompt = ChatPromptTemplate.from_messages([
        ("system",
         """You are a senior code security audit expert (Agent F), responsible for making final decisions on Agent C's analysis results.
Your task is to reach a definitive conclusion based on Agent C's findings and your discussions: whether the vulnerability is truly exploitable or a false positive.

**Output Format Requirements**:
You must strictly follow the JSON format below and ensure that the phrase "consensus reached" is included in your reasoning.
```json
{{
  "status": "exploitable" | "false_positive",
  "reason": "Consensus reached. The final conclusion is... because...",
  "confidence": <An integer between 0 and 100, representing your confidence in the final conclusion>
}}
```

This is Agent C's analysis and your discussion history:
{discussion_history}

This is the relevant source code:
```java
{source_code}
```

Please carefully review Agent C's viewpoints and provide your final conclusion.
"""),
        ("human", "Based on your analysis, here are my views and conclusions: {current_thought}")
    ])
    
    return prompt | llm
