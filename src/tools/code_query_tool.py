import os
import json
import re
from typing import List, Dict, Optional, Tuple
import logging
import javalang

class CodeQueryTool:
    """
    Code query tool for Agent C to query method code not included in the call chain
    """
    
    def __init__(self, project_paths: List[str], cache_file: str = "code_cache.json"):
        self.project_paths = project_paths
        self.cache_file = cache_file
        self.method_cache = {}  # Method cache: {method_key: method_info}
        self.class_cache = {}   # Class cache: {class_name: class_info}
        self.file_cache = {}    # File cache: {file_path: content}
        self.logger = logging.getLogger(__name__)
        self._build_cache()
    
    def _build_cache(self):
        """Build or load method and class cache"""
        if os.path.exists(self.cache_file):
            try:
                with open(self.cache_file, 'r', encoding='utf-8') as f:
                    cached_data = json.load(f)
                    self.method_cache = cached_data.get('methods', {})
                    self.class_cache = cached_data.get('classes', {})
                    self.file_cache = cached_data.get('files', {})
                    self.logger.info(f"Loaded {len(self.method_cache)} methods from cache")
                    return
            except Exception as e:
                self.logger.warning(f"Failed to load cache: {e}")
        
        self.logger.info("Starting to build code cache...")
        for project_path in self.project_paths:
            if os.path.exists(project_path):
                self._scan_project(project_path)
        
        self._save_cache()
        self.logger.info(f"Cache building completed, total {len(self.method_cache)} methods")
    
    def _scan_project(self, project_path: str):
        """Scan Java files in the project"""
        java_files_count = 0
        for root, dirs, files in os.walk(project_path):
            # Skip common non-source code directories
            dirs[:] = [d for d in dirs if d not in ['.git', 'target', 'build', 'node_modules', '__pycache__']]
            
            for file in files:
                if file.endswith('.java'):
                    file_path = os.path.join(root, file)
                    self._parse_java_file(file_path)
                    java_files_count += 1
        
        self.logger.info(f"Scanned {java_files_count} Java files in path: {project_path}")
    
    def _parse_java_file(self, file_path: str):
        """Parse Java file - using a combination of regex and javalang"""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            # Store file content
            relative_path = os.path.relpath(file_path)
            self.file_cache[relative_path] = content
            
            # Try to parse with javalang
            try:
                tree = javalang.parse.parse(content)
                self._extract_methods_from_ast(tree, file_path, content)
            except Exception as javalang_error:
                # If javalang parsing fails, use regex as fallback
                self.logger.warning(f"javalang parsing failed {file_path}: {javalang_error}, using regex parsing")
                self._extract_methods_with_regex(content, file_path)
                
        except Exception as e:
            self.logger.error(f"Error parsing file {file_path}: {e}")
    
    def _extract_methods_from_ast(self, tree, file_path: str, content: str):
        """Extract method information using AST"""
        lines = content.split('\n')
        
        for path, node in tree:
            if isinstance(node, javalang.tree.ClassDeclaration):
                class_name = node.name
                self.class_cache[class_name] = {
                    'file_path': file_path,
                    'class_name': class_name,
                    'content': content
                }
                
                # Extract methods from class
                for method in node.methods:
                    if isinstance(method, javalang.tree.MethodDeclaration):
                        method_info = self._extract_method_info_from_node(method, file_path, lines, class_name)
                        if method_info:
                            method_key = f"{class_name}.{method.name}"
                            # If there are methods with same name, add suffix to distinguish
                            if method_key in self.method_cache:
                                counter = 1
                                while f"{method_key}_{counter}" in self.method_cache:
                                    counter += 1
                                method_key = f"{method_key}_{counter}"
                            
                            self.method_cache[method_key] = method_info
    
    def _extract_method_info_from_node(self, method_node, file_path: str, lines: List[str], class_name: str) -> Optional[Dict]:
        """Extract method information from AST node"""
        try:
            method_name = method_node.name
            
            # Get method signature
            params = []
            if method_node.parameters:
                for param in method_node.parameters:
                    param_type = str(param.type) if param.type else "unknown"
                    params.append(f"{param_type} {param.name}")
            
            signature = f"{method_name}({', '.join(params)})"
            
            # Get method body
            if hasattr(method_node, 'position') and method_node.position:
                start_line = method_node.position.line
                method_body = self._extract_method_body_from_lines(lines, start_line - 1)
            else:
                method_body = "// Unable to locate method body"
            
            return {
                'file_path': file_path,
                'method_name': method_name,
                'class_name': class_name,
                'signature': signature,
                'body': method_body,
                'line_number': method_node.position.line if hasattr(method_node, 'position') and method_node.position else 0,
                'parameters': [param.name for param in method_node.parameters] if method_node.parameters else []
            }
        except Exception as e:
            self.logger.error(f"Failed to extract method information: {e}")
            return None
    
    def _extract_methods_with_regex(self, content: str, file_path: str):
        """Extract methods using regex as fallback method"""
        lines = content.split('\n')
        
        # Extract class name
        class_pattern = r'(?:public\s+|private\s+|protected\s+)?(?:abstract\s+)?(?:final\s+)?class\s+(\w+)'
        class_matches = re.findall(class_pattern, content)
        class_name = class_matches[0] if class_matches else "UnknownClass"
        
        # Store class information
        self.class_cache[class_name] = {
            'file_path': file_path,
            'class_name': class_name,
            'content': content
        }
        
        # Extract methods
        method_pattern = r'(?:public|private|protected)?\s*(?:static\s+)?(?:final\s+)?(?:synchronized\s+)?(?:\w+(?:<[^>]*>)?\s+)?(\w+)\s*\([^)]*\)\s*(?:throws\s+[^{]*)?{'
        
        for i, line in enumerate(lines):
            method_match = re.search(method_pattern, line)
            if method_match:
                method_name = method_match.group(1)
                
                # Skip constructors and some special methods
                if method_name == class_name or method_name in ['equals', 'hashCode', 'toString']:
                    continue
                
                method_body = self._extract_method_body_from_lines(lines, i)
                signature = self._extract_method_signature(line)
                
                method_key = f"{class_name}.{method_name}"
                if method_key in self.method_cache:
                    counter = 1
                    while f"{method_key}_{counter}" in self.method_cache:
                        counter += 1
                    method_key = f"{method_key}_{counter}"
                
                self.method_cache[method_key] = {
                    'file_path': file_path,
                    'method_name': method_name,
                    'class_name': class_name,
                    'signature': signature,
                    'body': method_body,
                    'line_number': i + 1,
                    'parameters': []  # Regex extracted parameter information is limited
                }
    
    def _extract_method_signature(self, line: str) -> str:
        """Extract method signature"""
        signature = line.strip()
        if '{' in signature:
            signature = signature[:signature.find('{')].strip()
        return signature
    
    def _extract_method_body_from_lines(self, lines: List[str], start_line: int) -> str:
        """Extract method body from line list"""
        method_lines = []
        brace_count = 0
        started = False
        
        for i in range(start_line, min(start_line + 100, len(lines))):  # Limit to maximum 100 lines
            line = lines[i]
            
            if '{' in line and not started:
                started = True
                brace_count += line.count('{')
            
            if started:
                method_lines.append(line)
                brace_count += line.count('{') - line.count('}')
                
                if brace_count <= 0:
                    break
        
        return '\n'.join(method_lines)
    
    def _save_cache(self):
        """Save cache to file"""
        try:
            cache_data = {
                'methods': self.method_cache,
                'classes': self.class_cache,
                'files': self.file_cache
            }
            with open(self.cache_file, 'w', encoding='utf-8') as f:
                json.dump(cache_data, f, ensure_ascii=False, indent=2)
            self.logger.info(f"Cache saved to {self.cache_file}")
        except Exception as e:
            self.logger.error(f"Failed to save cache: {e}")
    
    def query_method(self, method_name: str, class_name: str = None) -> Optional[Dict]:
        """Query method information"""
        # If class name is provided, try exact match
        if class_name:
            full_key = f"{class_name}.{method_name}"
            if full_key in self.method_cache:
                return self.method_cache[full_key]
        
        # Fuzzy match method name
        for key, value in self.method_cache.items():
            if value['method_name'].lower() == method_name.lower():
                if not class_name or value['class_name'].lower() == class_name.lower():
                    return value
        
        # Partial match
        candidates = []
        for key, value in self.method_cache.items():
            if method_name.lower() in value['method_name'].lower():
                candidates.append(value)
        
        # Return first candidate
        return candidates[0] if candidates else None
    
    def query_methods_by_class(self, class_name: str) -> List[Dict]:
        """Query all methods by class name"""
        results = []
        for method_info in self.method_cache.values():
            if method_info['class_name'].lower() == class_name.lower():
                results.append(method_info)
        return results
    
    def search_methods_by_pattern(self, pattern: str) -> List[Dict]:
        """Search methods by pattern"""
        results = []
        try:
            regex = re.compile(pattern, re.IGNORECASE)
            
            for method_info in self.method_cache.values():
                if (regex.search(method_info['method_name']) or 
                    regex.search(method_info['body']) or 
                    regex.search(method_info['signature'])):
                    results.append(method_info)
        except re.error as e:
            self.logger.error(f"Regex error: {e}")
        
        return results[:10]  # Limit result count
    
    def analyze_method_calls_in_body(self, method_body: str) -> List[str]:
        """Analyze method calls in method body"""
        # Simple method call extraction
        call_pattern = r'(\w+)\.(\w+)\s*\('
        calls = re.findall(call_pattern, method_body)
        
        method_calls = []
        for obj, method in calls:
            method_calls.append(f"{obj}.{method}")
        
        # Also find direct method calls
        direct_call_pattern = r'(\w+)\s*\([^)]*\)\s*[;{]'
        direct_calls = re.findall(direct_call_pattern, method_body)
        
        for call in direct_calls:
            if call not in ['if', 'for', 'while', 'switch', 'try', 'catch']:
                method_calls.append(call)
        
        return list(set(method_calls))  # Remove duplicates
    
    def get_method_context(self, method_name: str, class_name: str = None, context_lines: int = 5) -> Optional[str]:
        """Get method context code"""
        method_info = self.query_method(method_name, class_name)
        if not method_info:
            return None
        
        try:
            with open(method_info['file_path'], 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
            
            start_line = max(0, method_info['line_number'] - context_lines - 1)
            end_line = min(len(lines), method_info['line_number'] + context_lines)
            
            context = ''.join(lines[start_line:end_line])
            return context
        except Exception as e:
            self.logger.error(f"Failed to get method context: {e}")
            return method_info['body']
    
    def refresh_cache(self):
        """Refresh cache"""
        self.method_cache.clear()
        self.class_cache.clear()
        self.file_cache.clear()
        
        if os.path.exists(self.cache_file):
            os.remove(self.cache_file)
        
        self._build_cache()
    
    def get_stats(self) -> Dict:
        """Get cache statistics"""
        return {
            'total_methods': len(self.method_cache),
            'total_classes': len(self.class_cache),
            'total_files': len(self.file_cache),
            'project_paths': self.project_paths
        }
