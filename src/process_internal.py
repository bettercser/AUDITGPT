import os
import re
import time
import pandas as pd
from typing import List, Dict
import csv
import json
from openai import OpenAI
import argparse
import javalang

# --- 1. Data Structure Definition ---
class InternalApiInfo:
    def __init__(self, package: str, class_name: str, method_name: str,
                 file_name: str, full_signature: str, param_types: List[str],
                 start_line: int = 0, total_lines: int = 0, code: str = ""):
        self.package, self.class_name, self.method_name = package, class_name, method_name
        self.file_name, self.full_signature, self.param_types = file_name, full_signature, param_types
        # start_line, total_lines, and code will be precisely filled by javalang
        self.start_line, self.total_lines, self.code = start_line, total_lines, code
        self.api_type, self.classification_confidence, self.classification_reason = "unknown", 0.0, ""
    def to_dict(self) -> Dict: return self.__dict__

class InternalApiRepository:
    def __init__(self): self._apis: Dict[str, InternalApiInfo] = {}
    def add_api(self, api: InternalApiInfo): self._apis[f"{api.file_name}:{api.start_line}"] = api
    def add_apis_from_list(self, apis: List[InternalApiInfo]):
        for api in apis: self.add_api(api)
    def get_all_apis(self) -> List[InternalApiInfo]: return list(self._apis.values())

# --- 2. LLM Interaction Functions ---
def call_llm_api_for_batch(prompt: str) -> str:
   
    try:
        api_key = ""
        if not api_key: raise ValueError("OPENAI_API_KEY environment variable not set.")
        client = OpenAI(api_key=api_key, base_url="https://api.deepseek.com/v1/")
        response = client.chat.completions.create(model="deepseek-chat", response_format={"type": "json_object"}, messages=[{"role": "system", "content": "You are a world-class security expert..."}, {"role": "user", "content": prompt}], temperature=0.0)
        time.sleep(2)
        return response.choices[0].message.content.strip()
    except Exception as e:
        print(f"Error calling LLM API: {e}"); return '{"error": "API call failed"}'
    

def is_method_body_meaningful(code: str) -> bool:
    """
    A helper function to determine if a method body is just an empty "{}".
    """
    # Remove all whitespace characters (spaces, tabs, newlines)
    stripped_code = "".join(code.strip().split())
    # Find content after the first '{'
    body_content_part = stripped_code.split('{', 1)[-1]
    # Remove the last '}'
    body_content = body_content_part.rstrip('}')
    # If empty after processing, consider the method body meaningless
    return len(body_content) > 0

# ==================== LLM Classification Function for Internal APIs ====================
def classify_internal_apis_in_batches(repo: InternalApiRepository, batch_size: int = 5) -> List[InternalApiInfo]:
    """
    Traverse internal APIs, use prompts containing method bodies, let LLM perform code auditing and identify sinks.
    Since the prompt is longer, it's recommended to reduce batch size appropriately (e.g., 5).
    """
    
    prompt_template = """
You are a senior security researcher performing a code review on a batch of Java methods.
Your task is to identify which of these methods function as high-impact security sinks.

**Definition of a High-Impact Sink:**
A "sink" is a method where data, if it originates from an untrusted source, directly causes a serious vulnerability. You must analyze the **Source Code** of each method to find dangerous operations.

**Key Sink Patterns to look for inside the code:**
*   **SQL/HQL Injection:** Look for code that builds and executes database queries from string variables (e.g., calls to `entityManager.createNativeQuery`, `jdbcTemplate.query`).
*   **Command Injection:** Look for calls to `Runtime.getRuntime().exec(...)` or `ProcessBuilder`.
*   **Path Traversal:** Look for file operations (e.g., `new File(...)`, `new FileOutputStream(...)`, `Files.write(...)`) where the file path is constructed from a method parameter.
*   **Server-Side Request Forgery (SSRF):** Look for code that creates network requests to URLs constructed from method parameters (e.g., `new URL(url).openStream()`, `RestTemplate.exchange(...)`).
*   **Cross-Site Scripting (XSS):** In web contexts (e.g., a Controller method), look for raw data being written directly to an `HttpServletResponse`'s writer or output stream.

**What to IGNORE:**
*   Methods that only perform data validation, transformation (e.g., parsing dates, simple math), logging, or configuration.
*   Simple database CRUD operations that use safe, parameterized queries (e.g., via JPA's `save()`, `findById()`).
*   Methods that just call other internal service/DAO methods without performing a dangerous operation themselves.

**Your Task:**
Review the `Source Code` for each API in the batch below. For each one, decide if it matches the definition of a high-impact sink by looking for the patterns described.

**Input APIs:**
{api_batch_string}

**Output Format:**
You MUST respond with a single JSON object with a key "classifications", containing an array of objects. Each object must have:
- `id`: The integer ID of the API from the input batch.
- `classification`: Your decision, either "SINK" or "NOT_SINK".
- `vulnerability_type`: The specific vulnerability from the patterns above (e.g., "SQL Injection", "Path Traversal", "None").
- `reason`: A brief explanation for your decision, referencing the specific line of code if possible.
"""
    
    all_apis = repo.get_all_apis()
    meaningful_apis = [
        api for api in all_apis 
        if api.code and is_method_body_meaningful(api.code)
    ]
    
    total_original_apis = len(all_apis)
    total_meaningful_apis = len(meaningful_apis)
    
    print(f"\nPre-filtering complete: Found {total_meaningful_apis} methods with meaningful bodies (out of {total_original_apis} total).")

    # --- Step 2: Perform LLM classification only on meaningful methods ---
    identified_sinks: List[InternalApiInfo] = []
    if total_meaningful_apis == 0:
        print("No meaningful methods to send to LLM.")
        return identified_sinks
    
    print(f"Starting LLM classification for {total_meaningful_apis} internal methods in batches of {batch_size}...")

    for i in range(0, total_meaningful_apis, batch_size):
        batch = meaningful_apis[i:i + batch_size]
        batch_num = (i // batch_size) + 1
        total_batches = -(-total_meaningful_apis // batch_size)
        
        print(f"--- Processing Batch {batch_num}/{total_batches} ---")
        
        api_batch_string = ""
        for j, api in enumerate(batch):
            api_batch_string += f"\n--- API ID: {j} ---\n"
            api_batch_string += f"File: {api.file_name}\n"
            api_batch_string += f"Full Signature: {api.full_signature}\n"
            api_batch_string += f"```java\n{api.code.strip()}\n```\n"

        prompt = prompt_template.format(api_batch_string=api_batch_string)
        
        print("\n" + "="*25 + f" PROMPT FOR BATCH #{batch_num} " + "="*25)
        print(prompt)
        print("="*20 + " END OF PROMPT - SENDING TO LLM... " + "="*20 + "\n")

        response_json_str = call_llm_api_for_batch(prompt)
        
        print("=========================================results=========================================")
        print(response_json_str)
        print("=========================================end of results=========================================")
        try:
            results = json.loads(response_json_str)
            if 'classifications' not in results or not isinstance(results['classifications'], list):
                print(f"  -> Warning: Malformed JSON response for batch {batch_num}. Skipping."); continue

            for result in results['classifications']:
                if all(k in result for k in ['id', 'classification']) and result['classification'] == 'SINK':
                    api_index = result['id']
                    if 0 <= api_index < len(batch):
                        identified_api = batch[api_index]
                        identified_api.api_type = "sink"
                        identified_api.classification_reason = result.get('reason', 'Classified as SINK by LLM.')
                        identified_api.classification_confidence = 0.95
                        identified_sinks.append(identified_api)
                        print(f"  -> Identified SINK: {identified_api.method_name} (Reason: {identified_api.classification_reason})")

        except json.JSONDecodeError:
            print(f"  -> Error: Failed to decode JSON response for batch {batch_num}.")
            
    print("\nLLM batch classification finished.")
    return identified_sinks

def load_apis_from_csv(csv_path: str) -> InternalApiRepository:
    """
    Load API metadata from new CodeQL query results (V2 - Fixed parsing logic for 8 fields).
    Format: package|class|method|file|start_line|total_lines|full_signature|param_types
    """
    repo = InternalApiRepository()
    if not os.path.exists(csv_path):
        print(f"Error: CSV file not found at {csv_path}"); return repo
    
    try:
        df = pd.read_csv(csv_path, header=None)
        # Assume data is still in the 2nd column (index 1), modify if not correct
        data_column = df.iloc[:, 3].dropna().astype(str)
    except Exception as e:
        print(f"Error reading CSV {csv_path}: {e}"); return repo
        
    for api_data in data_column:
        try:
            parts = api_data.split('|')
            # Now we expect exactly 8 fields
            if len(parts) == 8:
                package, class_name, method_name, file_name, start_line_str, total_lines_str, full_sig, param_types_str = parts
                
                # Convert parameter type string to list
                param_types = [pt.strip() for pt in param_types_str.split(';') if pt.strip()]
                
                api = InternalApiInfo(
                    package=package,
                    class_name=class_name,
                    method_name=method_name,
                    file_name=file_name,
                    # Note: We still use javalang to get accurate line numbers, so temporarily store values from CodeQL here
                    start_line=int(start_line_str),
                    total_lines=int(total_lines_str),
                    full_signature=full_sig,
                    param_types=param_types
                )
                repo.add_api(api)
            else:
                print(f"Skipping row with incorrect number of fields ({len(parts)} found, expected 8): {api_data}")

        except (ValueError, IndexError) as e:
            print(f"Skipping malformed row: {api_data}\nError: {e}")
            
    return repo




def extract_code_for_apis_with_javalang(repo: InternalApiRepository, project_root: str):
    """
    Use javalang to parse AST, precisely locate and extract complete source code for each method.
    (V4 - Enhanced handling of body without position information, improved resilience)
    """
    print(f"\n--- Starting code extraction using javalang from root: {project_root} ---")
    
    ast_cache = {}
    file_content_cache = {}
    total_extracted = 0

    for api in repo.get_all_apis():
        try:
            full_path = os.path.join(project_root, api.file_name)
            
            if full_path not in ast_cache:
                # ... (File reading and AST parsing cache logic remains unchanged) ...
                if not os.path.exists(full_path):
                    ast_cache[full_path] = None; continue
                try:
                    with open(full_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                        file_content_cache[full_path] = content.splitlines(True)
                        ast_cache[full_path] = javalang.parse.parse(content)
                except Exception as e:
                    print(f"Warning: Failed to parse {api.file_name}. Error: {e}")
                    ast_cache[full_path] = None
            
            tree = ast_cache[full_path]
            if not tree: continue

            # --- find_method_node_in_ast call remains unchanged ---
           
            method_node = find_method_node_in_ast(tree, api.class_name, api.method_name, api.param_types)
            
            if method_node and hasattr(method_node, 'position') and method_node.position:
                start_line = method_node.position.line
                lines = file_content_cache[full_path]
                
                # --- Brand new, more resilient method body location logic ---
                body_start_line = -1
                
                # Strategy 1: First try to get position from body node
                if method_node.body and hasattr(method_node.body, 'position') and method_node.body.position:
                    body_start_line = method_node.body.position.line
                
                # Strategy 2: If body has no position, search for the first '{' from method declaration start line
                if body_start_line == -1:
                    # print(f"  [DEBUG] Method body has no position info. Searching for '{{' from line {start_line}.")
                    for i in range(start_line - 1, len(lines)):
                        if '{' in lines[i]:
                            body_start_line = i + 1
                            break
                
                # If successfully found the method body start line
                if body_start_line != -1:
                    # --- Subsequent brace matching logic remains unchanged ---
                    brace_level = 0
                    end_line = -1
                    # Start brace matching from the first line of method body
                    for i in range(body_start_line - 1, len(lines)):
                        line_content = lines[i]
                        line_content = re.sub(r'".*?"', '""', line_content) 
                        brace_level += line_content.count('{')
                        brace_level -= line_content.count('}')
                        if brace_level <= 0 and '}' in line_content:
                            end_line = i + 1
                            break
                    
                    if end_line != -1:
                        api.start_line = start_line
                        api.total_lines = end_line - start_line
                        api.code = "".join(lines[start_line - 1 : end_line])
                        total_extracted += 1
            else:
                 pass # Silently handle cases where method cannot be found, as previous debug info is sufficient

        except Exception as e:
            print(f"Error extracting code for {api.method_name} in {api.file_name}: {e}")
            
    print("\n--- Code extraction finished ---")
    print(f"Total methods with code extracted: {total_extracted}")

def find_method_node_in_ast(tree, target_class_name, target_method_name, target_param_types):
    """
    Traverse AST to find matching method node (V3 - Relaxed parameter count matching conditions)
    """
    for _, class_node in tree.filter(javalang.tree.ClassDeclaration):
        if class_node.name == target_class_name:
            candidate_methods = []
            for method_node in class_node.methods:
                if isinstance(method_node, javalang.tree.MethodDeclaration) and method_node.name == target_method_name:
                    # Key modification: Now compare parameter type lists instead of just count
                    method_param_types = [p.type.name for p in method_node.parameters]
                    if method_param_types == target_param_types:
                         return method_node # Exact match successful
                    candidate_methods.append(method_node)
            
            # If no exact match but only one method with the same name, consider it a match
            if not candidate_methods and len(class_node.methods) == 1 and class_node.methods[0].name == target_method_name:
                 return class_node.methods[0]
                 
           

    return None
# ======================================================================
# --- 4. Functions for Saving Results ---
def save_internal_repository_csv(repo: InternalApiRepository, file_path: str):
  
    try:
        with open(file_path, 'w', encoding='utf-8', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(["api_type", "confidence", "reason", "package", "class_name", "method_name", "full_signature", "param_types", "file_name", "start_line", "total_lines"])
            for api in repo.get_all_apis():
                writer.writerow([api.api_type, api.classification_confidence, api.classification_reason, api.package, api.class_name, api.method_name, api.full_signature, ','.join(api.param_types), api.file_name, api.start_line, api.total_lines])
    except IOError as e: print(f"Error writing to CSV {file_path}: {e}")

def save_internal_repository_json(repo: InternalApiRepository, file_path: str):
    
    try:
        with open(file_path, 'w', encoding='utf-8') as f:
            sinks_without_code = []
            for api in repo.get_all_apis():
                api_dict = api.to_dict(); del api_dict['code']
                sinks_without_code.append(api_dict)
            data = {"sinks": sinks_without_code, "summary": {"total_sinks": len(repo.get_all_apis())}}
            json.dump(data, f, indent=2, ensure_ascii=False)
    except IOError as e: print(f"Error writing to JSON {file_path}: {e}")



if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Load internal APIs, extract code, classify sinks using an LLM, and save results.")
    parser.add_argument("input_csv", help="Path to the input CSV file from the fetch-loc-fun.ql query.")
    parser.add_argument("project_root", help="The absolute path to the root of the Java project's source code.")
    parser.add_argument("-o", "--output_name", help="Base name for the output files. Derived from input file if not provided.")
    parser.add_argument("-b", "--batch_size", type=int, default=5, help="Batch size for LLM processing. Default is 5.")
    args = parser.parse_args()

    print(f"--- Step 1: Loading API metadata from {args.input_csv} ---")
    api_repo = load_apis_from_csv(args.input_csv)
    print(f"Successfully loaded metadata for {len(api_repo.get_all_apis())} methods.")

    if api_repo.get_all_apis():
        extract_code_for_apis_with_javalang(api_repo, args.project_root)
        print("\n--- Verification: Displaying first 5 APIs with accurately extracted code ---")
        for i, api in enumerate(api_repo.get_all_apis()[:5]):
            if api.code: # Only print those with successfully extracted code
                print(f"\n----- API #{i+1} -----")
                print(f"Method: {api.method_name} in class {api.class_name}")
                print(f"File: {api.file_name}")
                print(f"Accurate Start Line: {api.start_line}")
                print(f"Full Signature (from CodeQL): {api.full_signature}")
                print("--- Extracted Code ---")
                print(api.code.strip())
                print("----------------------")

        identified_sinks_list = classify_internal_apis_in_batches(api_repo, args.batch_size)
        
        sink_repository = InternalApiRepository()
        sink_repository.add_apis_from_list(identified_sinks_list)
        total_sinks = len(sink_repository.get_all_apis())
        print(f"\n--- Step 5: Saving {total_sinks} identified internal SINKs ---")

        if total_sinks > 0:
            output_dir = "./sink_internal"
            os.makedirs(output_dir, exist_ok=True)
            if args.output_name:
                base_name = args.output_name
            else:
                filename = os.path.basename(args.input_csv)
                base_name = os.path.splitext(filename)[0]
            
            output_csv_path = os.path.join(output_dir, f"{base_name}_sinks.csv")
            output_json_path = os.path.join(output_dir, f"{base_name}_sinks.json")
            
            
            save_internal_repository_csv(sink_repository, output_csv_path)
            save_internal_repository_json(sink_repository, output_json_path)
            
            print(f"\n✅ All done! Results saved to '{output_dir}' with base name '{base_name}'.")
        else:
            print("No internal methods were classified as SINKs by the LLM.")
