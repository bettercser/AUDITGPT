import json
import re
from typing import List, Dict, Optional, Any
import javalang
import os

class SarifJavaParser:
    """
    A robust parser using javalang library (a real Java AST parser) to parse SARIF files and extract
    Java contexts.
    This version is optimized to handle CodeQL-generated SARIF files and supports specifying source code root directories.
    """
    def __init__(self):
        self.java_lines_cache: Dict[str, List[str]] = {}
        self.java_ast_cache: Dict[str, Any] = {}

    def _get_ast(self, full_path: str) -> Optional[javalang.tree.CompilationUnit]:
        """Parse file using full path and cache AST"""
        if full_path in self.java_ast_cache:
            return self.java_ast_cache[full_path]
        
        try:
            with open(full_path, 'r', encoding='utf-8') as f:
                content = f.read()
                # Fix: Ensure line caching always preserves newline characters
                self.java_lines_cache[full_path] = content.splitlines(True) 
                ast = javalang.parse.parse(content)
                self.java_ast_cache[full_path] = ast
                return ast
        except FileNotFoundError:
            print(f"[Warning] Source file not found at: {full_path}")
            return None
        except Exception as e:
            print(f"[Error] Failed to parse {full_path} with javalang: {e}")
            return None

    def _find_node_end_line(self, lines: List[str], start_line: int) -> int:
        """Find node end line by matching curly braces starting from node start line. This is a heuristic approach."""
        brace_count = 0
        in_node = False
        # Start from the line before the start line (because line numbers are 1-based)
        for i in range(start_line - 1, len(lines)):
            line = lines[i]
            # Start counting only after finding the first '{'
            if '{' in line:
                in_node = True
            
            if in_node:
                brace_count += line.count('{')
                brace_count -= line.count('}')
            
            # Return current line number when braces are balanced and we've entered the node at least once
            if in_node and brace_count == 0:
                return i + 1
        return len(lines) # Fallback

    
    def _format_annotation_element(self, element: Any) -> str:
        """Recursively format annotation element values"""
        if element is None:
            return ""
        if isinstance(element, javalang.tree.Literal):
            return element.value
        if isinstance(element, list): # for ElementArrayValue
             return f"{{{', '.join([self._format_annotation_element(e) for e in element])}}}"
        if isinstance(element, javalang.tree.ElementValuePair):
            # Recursively process values
            return f"{element.name} = {self._format_annotation_element(element.value)}"
        if hasattr(element, 'name'): # for MemberReference
            return str(element.name)
        return "..."

    def _format_annotation(self, ann: javalang.tree.Annotation) -> str:
        """Format javalang Annotation node to string (enhanced version)"""
        name = f"@{ann.name}"
        if not ann.element:
            return name
        
        # Handle @RequestMapping({"/a", "/b"}) or @PostMapping({"/upload/file"})
        if isinstance(ann.element, javalang.tree.ElementArrayValue):
            formatted_elements = self._format_annotation_element(ann.element.values)
            return f"{name}({formatted_elements})"

        # Handle @RequestMapping(value = "/a", method = "GET")
        if isinstance(ann.element, list):
            values = [self._format_annotation_element(e) for e in ann.element]
            return f"{name}({', '.join(values)})"

        # Handle @RequestMapping("/a")
        if isinstance(ann.element, javalang.tree.Literal):
            return f'{name}({ann.element.value})'

        # Other complex cases that cannot be fully parsed
        return f"{name}(...)"
    
    def get_java_context(self, full_path: str, line_number: int) -> Optional[Dict]:
        """Precisely extract Java context from given full file path using javalang AST"""
        ast = self._get_ast(full_path)
        if not ast: return None

        all_lines = self.java_lines_cache.get(full_path)
        if not all_lines: return None

        # Find class/interface containing the alert line
        target_class = None
        declarations = list(ast.filter(javalang.tree.ClassDeclaration)) + list(ast.filter(javalang.tree.InterfaceDeclaration))
        for _, node in declarations:
            if not node.position: continue
            node_start_line = node.position.line
            node_end_line = self._find_node_end_line(all_lines, node_start_line)
            if node_start_line <= line_number <= node_end_line:
                target_class = node
                break
        
        if not target_class: return None # If class not found, return directly

        # Find method containing the alert line
        target_method = None
        # Ensure node has 'methods' attribute (interfaces may not have it)
        if hasattr(target_class, 'methods'):
            for method in target_class.methods:
                if not method.position: continue
                method_start_line = method.position.line
                method_end_line = self._find_node_end_line(all_lines, method_start_line)
                if method_start_line <= line_number <= method_end_line:
                    target_method = method
                    break
        
        if not target_method: return None # If method not found, return directly

        # --- Start extracting information ---
        class_name = target_class.name
        class_annotations = [self._format_annotation(ann) for ann in target_class.annotations]
        
        method_name = target_method.name
        method_annotations = [self._format_annotation(ann) for ann in target_method.annotations]
        
        method_start_line = target_method.position.line
        method_end_line = self._find_node_end_line(all_lines, method_start_line)
        # Get complete method body including annotations and method signature
        method_body_lines = all_lines[method_start_line - 1 : method_end_line]
        
        return_type_str = target_method.return_type.name if target_method.return_type else "void"
        
       
        params = []
        for param in target_method.parameters:
            param_annotations = ' '.join([self._format_annotation(ann) for ann in param.annotations])
            param_type = param.type.name + '[]' * len(param.type.dimensions)
            params.append(f"{param_annotations} {param_type} {param.name}".strip())
        
        throws_str = f" throws {', '.join(target_method.throws)}" if target_method.throws else ""
        
        method_signature = f"public {return_type_str} {method_name}({', '.join(params)}){throws_str}"

        return {
            'class': class_name, 'class_annotations': class_annotations,
            'class_signature': f"{' '.join(target_class.modifiers)} class {class_name}",
            'method': method_name, 'method_annotations': method_annotations,
            'method_signature': method_signature.strip(),
            # Fix: Method body now includes complete code with annotations and signature
            'method_body': [line.rstrip('\n\r') for line in method_body_lines],
            'start': method_start_line, 'end': method_end_line
        }

    # ... (parse_sarif and process_locations functions remain unchanged) ...
    def parse_sarif(self, sarif_path: str, source_base_path: str = '') -> List[Dict]:
        """
        Parse SARIF file and generate a report for each result containing call chains.
        :param sarif_path: Path to the SARIF file.
        :param source_base_path: Root directory of source code, used to concatenate relative paths in SARIF.
        """
        all_reports = []
        try:
            with open(sarif_path, 'r', encoding='utf-8') as f:
                sarif_data = json.load(f)
        except FileNotFoundError:
            print(f"[Error] SARIF file not found at: {sarif_path}")
            return []
        except json.JSONDecodeError:
            print(f"[Error] Invalid JSON in SARIF file: {sarif_path}")
            return []

        for run in sarif_data.get('runs', []):
            for result_index, result in enumerate(run.get('results', [])):
                code_flows = result.get('codeFlows', [])
                if not code_flows: continue

                # We process the first thread flow as representative
                thread_flows = code_flows[0].get('threadFlows', [])
                if not thread_flows: continue
                
                locations = thread_flows[0].get('locations', [])
                raw_detailed_chain = self.process_locations(locations, source_base_path)
                
                if not raw_detailed_chain: continue

                unique_detailed_chain = []
                added_methods_in_chain = set()
                for ctx in raw_detailed_chain:
                    method_key = (ctx['file'], ctx['method'])
                    if method_key not in added_methods_in_chain:
                        unique_detailed_chain.append(ctx)
                        added_methods_in_chain.add(method_key)
                
                if not unique_detailed_chain: continue

                vuln_id = result.get('correlationGuid', f'VULN-{result_index + 1}')
                vuln_type = result.get('ruleId', 'unknown_vulnerability')
                message_text = result.get('message', {}).get('text', '')
                param_match = re.search(r"parameter '([^']+)'", message_text, re.IGNORECASE)
                vuln_parameter = param_match.group(1) if param_match else "unknown"

                contexts_by_file = {}
                for context in unique_detailed_chain:
                    file_path = context['file']
                    if file_path not in contexts_by_file: contexts_by_file[file_path] = []
                    contexts_by_file[file_path].append(context)

                final_call_chain = [{'file': ctx['file'], 'line': ctx['line'], 'class': ctx['class'],
                                     'class_annotations': ctx['class_annotations'], 'method': ctx['method'],
                                     'method_annotations': ctx['method_annotations'],
                                     'method_signature': ctx['method_signature']} for ctx in unique_detailed_chain]

                source_code_map = {}
                for file_path, contexts in contexts_by_file.items():
                    source_code_map[file_path] = self.reconstruct_source_code(file_path, contexts, source_base_path)
                
                report = {"vuln_id": vuln_id, "vuln_type": vuln_type, "vuln_parameter": vuln_parameter,
                          "call_chain": final_call_chain, "source_code": source_code_map}
                all_reports.append(report)
        
        return all_reports

    def process_locations(self, locations: List[Dict], source_base_path: str) -> List[Dict]:
        """Process location list, concatenate base path to find source files"""
        chain = []
        for loc in locations:
            physical_location = loc.get('location', {}).get('physicalLocation', {})
            relative_uri = physical_location.get('artifactLocation', {}).get('uri', '')
            if not relative_uri: continue
            
            start_line = physical_location.get('region', {}).get('startLine', -1)
            if not relative_uri.endswith('.java') or start_line == -1: continue

            full_path = os.path.join(source_base_path, relative_uri)
            
            java_context = self.get_java_context(full_path, start_line)
            if java_context:
                java_context['file'] = relative_uri
                java_context['line'] = start_line
                chain.append(java_context)
        return chain

    def reconstruct_source_code(self, relative_uri: str, contexts: List[Dict], source_base_path: str) -> str:
        """Reconstruct source code based on context, use full path to read cache"""
        full_path = os.path.join(source_base_path, relative_uri)
        lines = self.java_lines_cache.get(full_path)
        if not lines: return f"// Source code not found for {relative_uri}"

        first_context = contexts[0]
        class_signature = first_context['class_signature'] + " {"
        builder = [ann for ann in first_context['class_annotations']]
        builder.append(class_signature)

        ast = self._get_ast(full_path)
        target_class_node = None
        if ast:
            for _, node in ast.filter(javalang.tree.ClassDeclaration):
                if node.name == first_context['class']:
                    target_class_node = node
                    break
        
        if target_class_node and hasattr(target_class_node, 'fields') and target_class_node.fields:
            builder.append('')
            for field in target_class_node.fields:
                field_start_line = field.position.line
                builder.append(lines[field_start_line - 1].strip())

        added_methods = set()
        for context in sorted(contexts, key=lambda x: x['start']):
            if context['method'] not in added_methods:
                builder.append('')
                
                leading_spaces = ' ' * 4 # Assume standard indentation is 4 spaces
                
                # Add parsed method annotations
                for annotation in context['method_annotations']:
                    builder.append(leading_spaces + annotation)
                
                # Add method body (it already contains method signature and complete implementation)
                builder.extend(context['method_body'])
                added_methods.add(context['method'])

        builder.append("}")
        return "\n".join(builder)
