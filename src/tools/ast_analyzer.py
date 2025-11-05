import javalang
from typing import List, Dict, Any, Set

class DataFlowTracer:
    """
    A tool for cross-file, recursive data flow tracing using AST.
    (V4 - Final fixed version with more robust class parsing and recursive logic)
    """

    def __init__(self, source_files: Dict[str, str]):
        self.source_files = source_files
        self.trees = {}
        self.class_definitions = {} # FQCN -> ClassNode
        self.class_fields = {}      # FQCN -> {fieldName: fieldTypeName}
        
        # First pass: Parse all classes and their FQCNs
        for file_path, source_code in self.source_files.items():
            try:
                tree = javalang.parse.parse(source_code)
                self.trees[file_path] = tree
                package_name = tree.package.name if tree.package else ""
                for _, class_node in tree.filter(javalang.tree.ClassDeclaration):
                    fqcn = f"{package_name}.{class_node.name}" if package_name else class_node.name
                    self.class_definitions[fqcn] = class_node
            except Exception:
                continue
        
        # Second pass: Parse fields, now we can resolve type names
        for fqcn, class_node in self.class_definitions.items():
            self.class_fields[fqcn] = {}
            for field in class_node.fields:
                field_type_name = field.type.name
                # Try to resolve field type to FQCN
                field_type_fqcn = self._resolve_type_to_fqcn(field_type_name, fqcn)
                for declarator in field.declarators:
                    self.class_fields[fqcn][declarator.name] = field_type_fqcn or field_type_name


    def trace_parameter_flow(self, start_class_name: str, start_method_name: str, parameter_to_trace: str) -> List[Dict[str, Any]]:
        print(f"--- [AST Tool] Starting recursive trace, entry: {start_class_name}.{start_method_name}, parameter: '{parameter_to_trace}' ---")
        return self._recursive_trace(start_class_name, start_method_name, parameter_to_trace, set(), 1)

    def _recursive_trace(self, class_name: str, method_name: str, param_name: str, visited: Set[str], level: int) -> List[Dict[str, Any]]:
        trace_signature = f"{class_name}.{method_name}({param_name})"
        if trace_signature in visited: return []
        visited.add(trace_signature)

        print(f"--- [AST Tool] Tracing (level {level}): {trace_signature} ---")

        class_node = self.find_class_node_by_any_name(class_name)
        if not class_node: return []
        
        fqcn = next((key for key, val in self.class_definitions.items() if val == class_node), None)
        if not fqcn: return []

        method_node = next((m for _, m in class_node.filter(javalang.tree.MethodDeclaration) if m.name == method_name), None)
        if not method_node: return []

        results = []
        
        # Step A: Find cases where parameter is the caller (e.g., file.transferTo())
        for _, invocation in method_node.filter(javalang.tree.MethodInvocation):
            if invocation.qualifier == param_name:
                results.append(self._format_invocation(invocation, fqcn, level))

        # Step B: Find cases where parameter is passed to other methods (e.g., fs.savefile(file, ...))
        for _, invocation in method_node.filter(javalang.tree.MethodInvocation):
            for i, arg in enumerate(invocation.arguments):
                # Check if argument is the variable we want to trace
                if (isinstance(arg, javalang.tree.MemberReference) and arg.member == param_name) or \
                   (isinstance(arg, javalang.tree.MethodInvocation) and arg.qualifier == param_name):
                    
                    results.append(self._format_invocation(invocation, fqcn, level))
                    
                    # --- ** Core recursive logic ** ---
                    next_class_fqcn = self.class_fields.get(fqcn, {}).get(invocation.qualifier)
                    if next_class_fqcn:
                        next_param_name = self._find_parameter_name_at_call_site(next_class_fqcn, invocation.member, i)
                        if next_param_name:
                            # Immediately recurse and merge results
                            recursive_results = self._recursive_trace(next_class_fqcn, invocation.member, next_param_name, visited, level + 1)
                            results.extend(recursive_results)
        return results

    # --- Helper functions ---

    def _resolve_type_to_fqcn(self, type_name: str, current_fqcn: str) -> str | None:
        """Try to resolve a simple type name to its fully qualified class name"""
        # 1. Check if it's already a FQCN
        if type_name in self.class_definitions: return type_name
        # 2. Check if it's a class in the same package
        current_package = ".".join(current_fqcn.split('.')[:-1])
        potential_fqcn = f"{current_package}.{type_name}"
        if potential_fqcn in self.class_definitions: return potential_fqcn
        # 3. (Simplified) Traverse all known FQCNs to see if any end with this type name
        for fqcn_key in self.class_definitions:
            if fqcn_key.endswith(f".{type_name}"):
                return fqcn_key
        return None

    def _find_parameter_name_at_call_site(self, class_name: str, method_name: str, arg_index: int) -> str | None:
        class_node = self.find_class_node_by_any_name(class_name)
        if not class_node: return None
        # Can add parameter count matching here to handle overloading
        for _, method_node in class_node.filter(javalang.tree.MethodDeclaration):
            if method_node.name == method_name and len(method_node.parameters) > arg_index:
                return method_node.parameters[arg_index].name
        return None
    
    def find_class_node_by_any_name(self, name: str) -> javalang.tree.ClassDeclaration | None:
        if name in self.class_definitions: return self.class_definitions[name]
        for fqcn, node in self.class_definitions.items():
            if fqcn.endswith(f".{name}"): return node
        return None

    def _format_invocation(self, invocation: javalang.tree.MethodInvocation, fqcn: str, level: int) -> Dict[str, Any]:
        file_path = next((fp for fp, tree in self.trees.items() if fqcn in [f"{tree.package.name if tree.package else ''}.{c.name}" for _, c in tree.filter(javalang.tree.ClassDeclaration)]), None)
        source_lines = self.source_files.get(file_path, "").splitlines()
        line_number = invocation.position.line if invocation.position else -1
        code_line = source_lines[line_number - 1].strip() if line_number > 0 and len(source_lines) >= line_number else "N/A"
        return {
            "function_name": invocation.member, "qualifier": invocation.qualifier or "static",
            "line_number": line_number, "code": code_line, "arguments_count": len(invocation.arguments), "trace_level": level
        }