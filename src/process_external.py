import os
import time

import pandas as pd
from typing import List, Dict
import csv
import json
from openai import OpenAI
import argparse 


class ApiInfo:
    """Represents a single API's information."""
    def __init__(self, file_name: str, line_number: int, package: str, class_name: str, 
                 method_name: str, full_signature: str, string_signature: str, 
                 is_static: bool, param_types: List[str], return_type: str, javadoc: str):
        self.file_name = file_name
        self.line_number = line_number
        self.package = package
        self.class_name = class_name
        self.method_name = method_name
        self.full_signature = full_signature
        self.string_signature = string_signature
        self.is_static = is_static
        self.param_types = param_types if param_types is not None else []
        self.return_type = return_type
        self.javadoc = javadoc
        
        self.api_type: str = "sink"
        self.classification_confidence: float = 0.95
        self.classification_reason: str = "Classified as SINK by LLM."

    def to_dict(self) -> Dict:
        """Converts the object to a dictionary for JSON serialization."""
        return self.__dict__

class ApiRepository:
    """A container for managing a collection of ApiInfo objects."""
    def __init__(self):
        self._apis: Dict[str, ApiInfo] = {}

    def add_api(self, api: ApiInfo):
        self._apis[api.full_signature] = api
        
    def add_apis_from_list(self, apis: List[ApiInfo]):
        for api in apis:
            self.add_api(api)

    def get_all_apis(self) -> List[ApiInfo]:
        return list(self._apis.values())



def call_llm_api_for_batch(prompt: str) -> str:
    """
    Calls the OpenAI API with a prompt designed for batch processing.
    It expects a JSON response from the model.
    """
    try:
        api_key = ""
        if not api_key:
            raise ValueError("OPENAI_API_KEY environment variable not set.")
            
        client = OpenAI(api_key=api_key, base_url="https://api.deepseek.com/v1/")

        response = client.chat.completions.create(
            model="deepseek-chat", 
            response_format={"type": "json_object"},
            messages=[
                {"role": "system", "content": "You are a world-class security expert specializing in static analysis. You must respond with valid JSON."},
                {"role": "user", "content": prompt}
            ],
            temperature=0.0
        )
        
        # 批处理可能需要更长的等待时间，所以延迟可以稍微长一点
        time.sleep(2) 
        
        return response.choices[0].message.content.strip()

    except Exception as e:
        print(f"Error calling LLM API: {e}")
        return '{"error": "API call failed"}' # 返回一个表示错误的JSON字符串

def classify_and_filter_sinks_in_batches(repo: ApiRepository, batch_size: int = 10) -> List[ApiInfo]:
    """
    Iterates through APIs in batches, uses an LLM to classify them, and returns a list
    containing ONLY the APIs classified as SINK.
    """
    
    prompt_template = """
You are a world-class security researcher specializing in static code analysis for Java applications. 
Your task is to analyze a batch of Java APIs and accurately identify high-impact security sinks.

**Primary Goal: High Precision, Low False Positives.**

---
**1. Definition of a High-Impact Sink**
A high-impact sink is a function that, when reached by untrusted user data, directly causes or enables a severe vulnerability. The operation must cross a critical security boundary (e.g., from application to database, OS, file system, or client browser).

---
**2. Key Sink Categories (What to look for):**
*   **SQL/NoSQL Injection:** Functions that execute database queries (e.g., `Statement.execute`, `Query.getResultList`).
*   **Command Injection:** Functions that execute OS commands (e.g., `Runtime.exec`, `ProcessBuilder.start`).
*   **Path Traversal/File I/O:** Functions that write to or read from a file path determined by user input (e.g., `new FileOutputStream(path)`, `Files.write`).
*   **Server-Side Request Forgery (SSRF):** Functions that create network connections to a user-provided URL (e.g., `new URL(url).openConnection()`, `HttpClient.execute`).
*   **Unsafe Deserialization:** Functions that deserialize data from untrusted sources (e.g., `ObjectInputStream.readObject`).
*   **Cross-Site Scripting (XSS):** Functions that write raw, unencoded data directly into an HTTP response body, leading to HTML/JavaScript interpretation by the browser (e.g., `HttpServletResponse.getWriter().print(data)`, `OutputStream.write(data)` WHEN the stream is an HTTP response).

---
**3. Common False Positives (What to IGNORE):**
*   **In-Memory Operations:** Functions that manipulate data in memory without crossing a security boundary (e.g., `ByteArrayOutputStream.toByteArray`, `String.getBytes`). These are **NEVER** sinks.
*   **Data Transformation/Creation:** Functions that generate or transform data but do not execute it (e.g., `kaptcha.createText`, `Integer.parseInt`, `new BigInteger()`). These are **NEVER** sinks.


---
**4. Input Batch & Your Task**
Analyze the following list of APIs. For each API, perform a two-step thought process:
First, identify the specific high-impact vulnerability type from Section 2 that it could lead to.
Second, based on that, classify it as "SINK" or "NOT_SINK". If it falls into any category from Section 3, it is "NOT_SINK".

**Input APIs:**
{api_batch_string}

---
**5. Output Format**
You MUST respond with a single JSON object. The object must contain one key, "classifications", which is an array of objects.
Each object in the array must have these keys:
- `id`: The integer ID of the API from the input batch.
- `classification`: Your decision, either "SINK" or "NOT_SINK".
- `vulnerability_type`: The specific vulnerability from Section 2 (e.g., "SQL Injection", "Path Traversal", "None").
- `reason`: A brief explanation for your decision, especially for false positives.

Example Response:
```json
{{
  "classifications": [
    {{
      "id": 0,
      "classification": "SINK",
      "vulnerability_type": "Command Injection",
      "reason": "The method Runtime.exec directly executes OS commands."
    }},
    {{
      "id": 1,
      "classification": "NOT_SINK",
      "vulnerability_type": "None",
      "reason": "ByteArrayOutputStream.toByteArray is an in-memory operation, not a security sink."
    }}
  ]
}}
"""
    all_apis = repo.get_all_apis()
    total_apis = len(all_apis)
    identified_sinks: List[ApiInfo] = []

    print(f"\nStarting LLM classification for {total_apis} APIs in batches of {batch_size}...")

    for i in range(0, total_apis, batch_size):
        batch = all_apis[i:i + batch_size]
        batch_num = (i // batch_size) + 1
        total_batches = -(-total_apis // batch_size) 
        
        print(f"--- Processing Batch {batch_num}/{total_batches} ---")
        
        api_batch_string = ""
        for j, api in enumerate(batch):
            api_batch_string += f"\n--- API ID: {j} ---\n"
            api_batch_string += f"Full Signature: {api.full_signature}\n"
            api_batch_string += f"Package: {api.package}\n"
            api_batch_string += f"Class: {api.class_name}\n"
            api_batch_string += f"Javadoc: {api.javadoc if api.javadoc else 'Not available.'}\n"
        print(api_batch_string)  # 打印当前批次的API信息

        prompt = prompt_template.format(api_batch_string=api_batch_string)
        
        response_json_str = call_llm_api_for_batch(prompt)
        
        try:
            results = json.loads(response_json_str)
            if 'classifications' not in results or not isinstance(results['classifications'], list):
                print(f"  -> Warning: Malformed JSON response for batch {batch_num}. Skipping.")
                continue

            for result in results['classifications']:
                if all(k in result for k in ['id', 'classification', 'reason']):
                    if result['classification'] == 'SINK':
                        api_index = result['id']
                        if 0 <= api_index < len(batch):
                            identified_api = batch[api_index]
                            identified_api.classification_reason = result['reason']
                            identified_sinks.append(identified_api)
                            print(f"  -> Identified SINK: {identified_api.method_name} (Reason: {result['reason']})")

        except json.JSONDecodeError:
            print(f"  -> Error: Failed to decode JSON response for batch {batch_num}. Response was: {response_json_str}")
            
    print("\nLLM batch classification finished.")
    return identified_sinks




def load_apis_from_csv(csv_path: str, column_index: int = 3, excluded_name: str = "") -> ApiRepository:
    print(excluded_name)
    if excluded_name == 'jsherp':
        excluded_name = 'jsh'
    elif excluded_name == 'mcms':
        excluded_name = 'mingsoft'
    elif excluded_name == 'ofcms':
        excluded_name = 'ofsoft'
    repo = ApiRepository()
    if not os.path.exists(csv_path):
        print(f"Error: CSV file not found at {csv_path}")
        return repo
    try:
        df = pd.read_csv(csv_path, header=None)
        data_column = df.iloc[:, column_index].dropna().astype(str)
    except Exception as e:
        print(f"Error reading or parsing CSV file {csv_path}: {e}")
        return repo
    for api_data in data_column:
        try:
            parts = api_data.split('|')
            if len(parts) >= 9:
                package, class_name, method_name, full_sig, string_sig, is_static, param_types, return_type, *javadoc_parts = parts
                if excluded_name in package:
                    continue
                javadoc = '|'.join(javadoc_parts) if javadoc_parts else ""
                api = ApiInfo(
                    file_name="N/A", line_number=0, package=package, class_name=class_name,
                    method_name=method_name, full_signature=full_sig, string_signature=string_sig,
                    is_static=(is_static.lower() == 'true'), param_types=(param_types.split(';') if param_types else []),
                    return_type=return_type, javadoc=javadoc
                )
                repo.add_api(api)
        except Exception as e:
            print(f"Error processing data row: {api_data}\nException: {e}")
    return repo


def save_repository_csv(repo: ApiRepository, file_path: str) -> None:
    with open(file_path, 'w', encoding='utf-8', newline='') as f:
        writer = csv.writer(f)
        writer.writerow([
            "api_type", "confidence", "package", "class_name", "method_name",
            "full_signature", "is_static", "return_type", "reason"
        ])
        for api in repo.get_all_apis():
            writer.writerow([
            api.api_type, api.classification_confidence, api.package,
            api.class_name, api.method_name, api.full_signature,
            'true' if api.is_static else 'false', api.return_type,
            api.classification_reason
            ])


def save_repository_json(repo: ApiRepository, file_path: str) -> None:
    with open(file_path, 'w', encoding='utf-8') as f:
        data = {
            "sinks": [api.to_dict() for api in repo.get_all_apis()],
            "summary": {"total_sinks": len(repo.get_all_apis())}
        }
        json.dump(data, f, indent=2, ensure_ascii=False)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description="Load APIs from a CodeQL CSV, classify them as Sinks using an LLM, and save the results."
    )
    # 添加必需的位置参数：输入文件
    parser.add_argument(
        "input_csv",
        help="Path to the input CSV file from CodeQL (e.g., 'data/external/unique_Jeecg.csv')."
    )
    # 添加可选参数：输出文件名的前缀
    parser.add_argument(
        "-o", "--output_name",
        help="Base name for the output files. If not provided, it will be derived from the input file name."
    )
    args = parser.parse_args()

    INPUT_CSV_PATH = args.input_csv
    BATCH_SIZE = 10 #设置您想要的批处理大小

    base_name = args.output_name
    if args.output_name:
        base_name = args.output_name
    else:
        # 如果未提供输出名，则从输入文件名自动生成
        # 例如: "unique_Jeecg.csv" -> "Jeecg"
        filename = os.path.basename(INPUT_CSV_PATH)
        base_name = os.path.splitext(filename)[0].replace("unique_", "")

    output_dir = "./sink"

    output_csv_path = os.path.join(output_dir, f"{base_name}_identified_sinks.csv")
    output_json_path = os.path.join(output_dir, f"{base_name}_identified_sinks.json")

    # --- 执行 ---
    print("--- Step 1: Loading all potential APIs from CodeQL CSV ---")
    initial_repo = load_apis_from_csv(INPUT_CSV_PATH, excluded_name=str.lower(base_name))
    total_loaded = len(initial_repo.get_all_apis())
    print(f"Successfully loaded {total_loaded} unique external API calls for analysis.")

    if total_loaded > 0:
        print("\n--- Step 2: Filtering for SINKs using LLM in batches ---")
        identified_sinks_list = classify_and_filter_sinks_in_batches(initial_repo, BATCH_SIZE)
        
        sink_repository = ApiRepository()
        sink_repository.add_apis_from_list(identified_sinks_list)
        
        total_sinks = len(sink_repository.get_all_apis())
        print(f"\n--- Step 3: Saving {total_sinks} identified SINKs ---")

        if total_sinks > 0:
            

            save_repository_csv(sink_repository, output_csv_path)
            save_repository_json(sink_repository, output_json_path)
            
            print(f"\n✅ All done! Results for identified SINKs saved to:")
            print(f"   - CSV: {output_csv_path}")
            print(f"   - JSON: {output_json_path}")
        else:
            print("No APIs were classified as SINKs by the LLM.")
            
    else:
        print("No APIs loaded. Please check your CSV file path and content.")
