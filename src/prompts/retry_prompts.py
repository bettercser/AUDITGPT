# retry_prompts.py
# Prompts and strategy configurations for the retry mechanism.

from typing import Dict, List, Any

# Bypass techniques priority configuration
BYPASS_TECHNIQUES = {
    1: {  # 1st Retry
        "encoding": ["url_encode", "html_encode"],
        "character_escape": ["backslash", "quotes"],
        "case_variation": ["lowercase", "uppercase", "mixed"],
        "space_bypass": ["url_encode", "tab", "ifs"],
        "comment_bypass": ["sql_comment", "html_comment"]
    },
    2: {  # 2nd Retry
        "double_encoding": ["double_url", "mixed_encoding"],
        "protocol_switch": ["https", "different_port"],
        "method_change": ["post", "put", "patch"],
        "parameter_position": ["body", "header", "cookie"],
        "advanced_encoding": ["unicode", "hex", "base64"]
    },
    3: {  # 3rd Retry
        "blind_techniques": ["time_based", "boolean_based"],
        "out_of_band": ["dns_exfil", "http_callback"],
        "deep_bypass": ["string_concat", "reflection"],
        "multi_vector": ["combined_payloads", "chained_attacks"],
        "extreme_encoding": ["nested_encoding", "custom_charset"]
    }
}

# Failure type to strategy mapping
FAILURE_TO_STRATEGY = {
    "permission_denied": {
        1: "auth_bypass",
        2: "privilege_escalation", 
        3: "alternative_access"
    },
    "syntax_error": {
        1: "syntax_fix",
        2: "alternative_syntax",
        3: "payload_transformation"
    },
    "filtered": {
        1: "basic_encoding",
        2: "advanced_obfuscation",
        3: "deep_bypass"
    },
    "timeout": {
        1: "simplified_payload",
        2: "async_execution",
        3: "minimal_payload"
    },
    "network_error": {
        1: "protocol_change",
        2: "connection_retry",
        3: "alternative_channel"
    },
    "server_error": {
        1: "payload_simplification",
        2: "format_adjustment",
        3: "minimal_request"
    }
}

def get_retry_context_for_agent_b(state: Dict[str, Any]) -> str:
    """Generates retry context for Agent B."""
    retry_count = state.get("retry_count", 0)
    failure_analysis = state.get("failure_analysis", {})
    bypass_techniques_used = state.get("bypass_techniques_used", [])
    adjustment_strategy = state.get("adjustment_strategy", "")
    
    if retry_count == 0:
        return ""  # No retry context needed for the first attempt
    
    return f"""
**Retry Context Handling:**
- **Current Retry Count**: {retry_count}/3
- **Previous Failure**: {failure_analysis.get('failure_type', 'unknown')} - {failure_analysis.get('details', 'N/A')}
- **Bypass Techniques Used**: {', '.join(bypass_techniques_used) if bypass_techniques_used else 'None'}
- **Adjustment Strategy**: {adjustment_strategy}

**Parameter Adjustment Rules for Retry:**
1. **1st Retry**: Try different parameter name variants (e.g., filename → file, filepath → path).
2. **2nd Retry**: Add bypass parameters (e.g., Content-Type, X-Forwarded-For).
3. **3rd Retry**: Consider using POST body instead of GET parameters, or add authentication bypass parameters.

**Output Enhancement for Retry:**
In `finalize_response`, adjust `route_info` based on retry count:
- Keep `api` and `method` unchanged.
- Adjust `vuln_parameter` based on failure analysis.
- Add `normal_parameters` based on retry strategy.
"""

def get_retry_context_for_agent_d(state: Dict[str, Any]) -> str:
    """Generates retry context for Agent D."""
    retry_count = state.get("retry_count", 0)
    failure_analysis = state.get("failure_analysis", {})
    bypass_techniques_used = state.get("bypass_techniques_used", [])
    adjustment_strategy = state.get("adjustment_strategy", "")
    retry_history = state.get("retry_history", [])
    
    if retry_count == 0:
        return ""  # No retry context needed for the first attempt
    
    technique_descriptions = []
    if retry_count == 1:
        technique_descriptions = [
            "- URL Encoding: `../` → `%2e%2e%2f`",
            "- Character Escape: `'` → `\\'`, `\"` → `\\\"`", 
            "- Space Bypass: space → `%20` or `${IFS}`",
            "- Case Variation: `SELECT` → `select` → `SeLeCt`",
            "- Comment Bypass: `--` → `#` → `/**/`"
        ]
    elif retry_count == 2:
        technique_descriptions = [
            "- Double Encoding: `%2e%2e%2f` → `%252e%252e%252f`",
            "- Mixed Encoding: `../` → `%2e%2e/` → `.%2e/`",
            "- Protocol Switch: HTTP → HTTPS",
            "- Method Change: GET → POST",
            "- Parameter Position: URL param → POST body → Header"
        ]
    elif retry_count == 3:
        technique_descriptions = [
            "- Time-based Blind: Use `sleep(5)` or `WAITFOR DELAY '00:00:05'`",
            "- Out-of-Band: Use DNS lookups or HTTP callbacks",
            "- Deep Bypass: String concatenation, reflection calls",
            "- Multi-vector: Combine multiple attack vectors"
        ]
    
    return f"""
**Retry Bypass Strategy (Based on Retry Count: {retry_count}/3)**:

**Retry #{retry_count} - {'Basic' if retry_count == 1 else 'Advanced' if retry_count == 2 else 'Extreme'} Bypass Techniques**:
{chr(10).join(technique_descriptions)}

**Handling Previous Failure Analysis**:
Adjust strategy based on previous failure reason `{failure_analysis.get('failure_type', 'unknown')}`:
- If "permission_denied": Try permission bypass techniques.
- If "syntax_error": Adjust payload syntax.
- If "filtered": Use deeper encoding bypass.
- If "timeout": Use faster payload.

**Current Retry Status**:
- Retry Count: {retry_count}/3
- Last Failure Reason: {failure_analysis.get('failure_type', 'unknown')}
- Last Failure Details: {failure_analysis.get('details', 'N/A')}
- Techniques Used: {', '.join(bypass_techniques_used) if bypass_techniques_used else 'None'}

**This Attempt's Strategy**: {adjustment_strategy}

Based on the above retry context, generate improved payload and curl command. Ensure to use bypass techniques corresponding to this retry level.
"""

def get_retry_context_for_agent_e(state: Dict[str, Any]) -> str:
    """Generates retry context for Agent E."""
    retry_count = state.get("retry_count", 0)
    retry_history = state.get("retry_history", [])
    
    return f"""
**Retry Context Analysis**:
- Current Retry Count: {retry_count}/3
- Retry History: {len(retry_history)} previous attempt(s).

**Enhanced Failure Analysis Requirements**:
In addition to determining success: true/false, also provide:
1. **Failure Type Classification** (must choose one):
   - "permission_denied": Access denied (e.g., HTTP 401, 403).
   - "syntax_error": Payload syntax or format error.
   - "filtered": Blocked by a WAF or security filter.
   - "timeout": Request timed out or no response.
   - "network_error": Network connectivity issue.
   - "server_error": Internal server error (e.g., HTTP 500, 502, or response contains 'Exception', 'Error').
   - "unexpected_response": The response was not an error but did not match the success criteria.
   - "unknown": Only use if none of the above apply.

2. **Special Rule**:
   - If the response status code is 5xx (e.g., 500), or the response body contains "java.lang.NullPointerException", "Internal Server Error" or other stack trace information, **must** classify `failure_type` as `"server_error"`.

3. **Specific Adjustment Suggestions** (for next retry):
   - For "permission_denied": Suggest trying different authentication methods or permission bypass.
   - For "syntax_error": Suggest adjusting payload syntax or encoding methods.
   - For "filtered": Suggest using deeper bypass techniques.
   - For "timeout": Suggest using simpler and faster payloads.

**If retry is needed, use this output format**:
```json
{{
  "action": "suggest_retry",
  "action_input": {{
    "success": false,
    "details": "...",
    "failure_type": "server_error",
    "adjustment_suggestions": ["..."],
    "retry_recommended": true
  }}
}}
```

**If no retry is needed or maximum retries reached, use this standard format**:
```json
{{
  "action": "finalize_response",
  "action_input": {{
    "success": false,
    "details": "..."
  }}
}}
```
"""

def get_adjustment_strategy(failure_type: str, retry_count: int) -> str:
    """Gets the adjustment strategy based on failure type and retry count."""
    strategies = FAILURE_TO_STRATEGY.get(failure_type, {})
    return strategies.get(retry_count, "general_retry")

def get_bypass_techniques_for_retry(retry_count: int) -> List[str]:
    """Gets the list of bypass techniques for a specific retry attempt."""
    techniques = BYPASS_TECHNIQUES.get(retry_count, {})
    all_techniques = []
    for category, tech_list in techniques.items():
        all_techniques.extend(tech_list)
    return all_techniques

def should_retry_based_on_failure(failure_type: str, retry_count: int) -> bool:
    """Determines if a retry should be attempted based on failure type."""
    if retry_count >= 3:
        return False
    
    non_retryable_failures = ["network_error"]
    if failure_type in non_retryable_failures and retry_count >= 2:
        return False
    
    return True
