"""
Vector Database RAG Tool for Code Analysis
Uses vector embeddings for semantic code search and retrieval
"""

import os
import json
import numpy as np
from pathlib import Path
from typing import Dict, List, Any, Optional
import javalang
from collections import defaultdict

# Try to import vector database and embedding libraries
try:
    import chromadb
    from chromadb.config import Settings
    from sentence_transformers import SentenceTransformer
    HAS_VECTOR_DEPS = True
except ImportError:
    HAS_VECTOR_DEPS = False
    print("Warning: Vector database dependencies not available. Using fallback mode.")


class VectorRAGTool:
    """Vector Database RAG Tool for semantic code search and retrieval"""
    
    def __init__(self, source_base_dir: str, vector_db_path: str = "./vector_db"):
        self.source_base_dir = Path(source_base_dir)
        if not self.source_base_dir.is_dir():
            raise FileNotFoundError(f"source code dir is not found: {source_base_dir}")
        
        self.vector_db_path = Path(vector_db_path)
        self.vector_db_path.mkdir(parents=True, exist_ok=True)
        
        # Initialize vector database
        self.client = None
        self.collection = None
        self.embedding_model = None
        
        if HAS_VECTOR_DEPS:
            self._initialize_vector_db()
        
        # Fallback registry for when vector DB is not available
        self.method_registry = defaultdict(dict)
        self.simple_name_index = defaultdict(list)
        self.is_parsed = False
    
    def _initialize_vector_db(self):
        """Initialize ChromaDB and embedding model"""
        try:
            # Initialize ChromaDB client
            self.client = chromadb.PersistentClient(
                path=str(self.vector_db_path),
                settings=Settings(anonymized_telemetry=False)
            )
            
            # Load or create collection
            try:
                self.collection = self.client.get_collection("code_methods")
                print("✅ Loaded existing vector database collection")
            except Exception:
                self.collection = self.client.create_collection(
                    name="code_methods",
                    metadata={"description": "Java method code embeddings"}
                )
                print("✅ Created new vector database collection")
            
            # Initialize embedding model
            self.embedding_model = SentenceTransformer('all-MiniLM-L6-v2')
            print("✅ Initialized embedding model")
            
        except Exception as e:
            print(f"⚠️ Failed to initialize vector database: {e}")
            print("⚠️ Falling back to traditional lookup")
            self.client = None
            self.collection = None
            self.embedding_model = None
    
    def _extract_method_context(self, method_node, class_decl, package_name) -> str:
        """Extract rich context for method embedding"""
        context_parts = []
        
        # Class context
        if class_decl:
            context_parts.append(f"Class: {class_decl.name}")
            if hasattr(class_decl, 'implements') and class_decl.implements:
                interfaces = [impl.name for impl in class_decl.implements]
                context_parts.append(f"Implements: {', '.join(interfaces)}")
            if hasattr(class_decl, 'extends') and class_decl.extends:
                context_parts.append(f"Extends: {class_decl.extends.name}")
        
        # Method signature
        return_type = method_node.return_type.name if method_node.return_type else "void"
        params = []
        for param in method_node.parameters:
            param_type = param.type.name if param.type else "Object"
            param_name = param.name
            params.append(f"{param_type} {param_name}")
        
        signature = f"{return_type} {method_node.name}({', '.join(params)})"
        context_parts.append(f"Method: {signature}")
        
        # Package context
        if package_name:
            context_parts.append(f"Package: {package_name}")
        
        # Method body (first few lines for context)
        if method_node.body:
            body_lines = []
            for stmt in method_node.body:
                if hasattr(stmt, 'position') and stmt.position:
                    body_lines.append(str(stmt))
                    if len(body_lines) >= 3:  # Limit context size
                        break
            if body_lines:
                context_parts.append("Body preview: " + " ".join(body_lines))
        
        return " | ".join(context_parts)
    
    def _parse_and_index_files(self):
        """Parse Java files and index methods in vector database"""
        if self.is_parsed:
            return
        
        print("\n[VectorRAGTool]...")
        
        java_files = list(self.source_base_dir.rglob('*.java'))
        print(f"找到 {len(java_files)} 个Java文件")
        
        all_methods = []
        
        for file_path in java_files:
            try:
                content = file_path.read_text(encoding='utf-8', errors='ignore')
                tree = javalang.parse.parse(content)
                code_lines = content.splitlines()
                package_name = tree.package.name if tree.package else ""
                
                for class_decl in tree.types:
                    if isinstance(class_decl, javalang.tree.ClassDeclaration):
                        simple_name = class_decl.name
                        fqcn = f"{package_name}.{simple_name}" if package_name else simple_name
                        
                        # Index in traditional registry
                        if fqcn not in self.simple_name_index[simple_name]:
                            self.simple_name_index[simple_name].append(fqcn)
                        
                        for _, method_node in class_decl.filter(javalang.tree.MethodDeclaration):
                            method_name = method_node.name
                            param_count = len(method_node.parameters)
                            start_line = method_node.position.line if method_node.position else 1
                            
                            # Extract method code
                            method_body = self._get_source_segment(code_lines, start_line)
                            
                            # Store in traditional registry
                            self.method_registry[fqcn][(method_name, param_count)] = {
                                "code": method_body,
                                "file_path": file_path,
                                "fqcn": fqcn
                            }
                            
                            # Prepare for vector indexing
                            method_context = self._extract_method_context(method_node, class_decl, package_name)
                            
                            all_methods.append({
                                "fqcn": fqcn,
                                "method_name": method_name,
                                "param_count": param_count,
                                "context": method_context,
                                "code": method_body,
                                "file_path": str(file_path)
                            })
                            
            except Exception as e:
                print(f"解析文件 {file_path} 时出错: {e}")
                continue
        
        # Index in vector database if available
        if self.collection and self.embedding_model and all_methods:
            self._index_in_vector_db(all_methods)
        
        self.is_parsed = True
        print(f"[VectorRAGTool] 索引构建完成。共索引 {len(all_methods)} 个方法")
    
    def _index_in_vector_db(self, methods: List[Dict[str, Any]]):
        """Index methods in vector database"""
        print("正在向量数据库中索引方法...")
        
        documents = []
        metadatas = []
        ids = []
        
        for i, method in enumerate(methods):
            # Create document for embedding
            doc_text = f"{method['context']} | Code: {method['code'][:500]}"  # Limit code length
            
            documents.append(doc_text)
            metadatas.append({
                "fqcn": method["fqcn"],
                "method_name": method["method_name"],
                "param_count": method["param_count"],
                "file_path": method["file_path"]
            })
            ids.append(f"method_{i}")
        
        # Generate embeddings and add to collection
        embeddings = self.embedding_model.encode(documents).tolist()
        
        self.collection.add(
            embeddings=embeddings,
            documents=documents,
            metadatas=metadatas,
            ids=ids
        )
        
        print(f"✅ {len(methods)} ")
    
    def _get_source_segment(self, code_lines: list, start_line: int) -> str:
        """Extract method source code segment"""
        method_lines, search_start_line = [], max(0, start_line - 5)
        method_declaration_line_index = -1
        
        for i in range(search_start_line, len(code_lines)):
            if '{' in code_lines[i]:
                method_declaration_line_index = i
                break
        
        if method_declaration_line_index == -1:
            return ""
        
        brace_count, method_started = 0, False
        for i in range(start_line - 1, len(code_lines)):
            line = code_lines[i]
            open_braces, close_braces = line.count('{'), line.count('}')
            
            if open_braces > 0 and not method_started:
                method_started = True
            
            if method_started or i >= method_declaration_line_index:
                method_lines.append(line)
                brace_count += open_braces
                brace_count -= close_braces
                if brace_count == 0 and method_started:
                    break
        
        return "\n".join(method_lines).strip()
    
    def semantic_search_methods(self, query: str, top_k: int = 5) -> List[Dict[str, Any]]:
        """Perform semantic search for methods using vector database"""
        if not self.collection or not self.embedding_model:
            print("⚠️ Vector database not available, falling back to traditional search")
            return self._fallback_search(query, top_k)
        
        self._parse_and_index_files()
        
        try:
            # Generate query embedding
            query_embedding = self.embedding_model.encode([query]).tolist()[0]
            
            # Search in vector database
            results = self.collection.query(
                query_embeddings=[query_embedding],
                n_results=top_k,
                include=["metadatas", "documents", "distances"]
            )
            
            # Format results
            formatted_results = []
            for i, (metadata, document, distance) in enumerate(zip(
                results['metadatas'][0], 
                results['documents'][0], 
                results['distances'][0]
            )):
                # Get full method code from registry
                fqcn = metadata['fqcn']
                method_name = metadata['method_name']
                param_count = metadata['param_count']
                
                method_details = self.method_registry[fqcn].get((method_name, param_count))
                
                formatted_results.append({
                    "rank": i + 1,
                    "similarity_score": 1.0 - distance,  # Convert distance to similarity
                    "fqcn": fqcn,
                    "method_name": method_name,
                    "param_count": param_count,
                    "context": document,
                    "code": method_details["code"] if method_details else "Code not available",
                    "file_path": metadata["file_path"]
                })
            
            return formatted_results
            
        except Exception as e:
            print(f"⚠️ Vector search failed: {e}")
            return self._fallback_search(query, top_k)
    
    def _fallback_search(self, query: str, top_k: int) -> List[Dict[str, Any]]:
        """Fallback search using traditional registry"""
        self._parse_and_index_files()
        
        results = []
        query_lower = query.lower()
        
        # Simple keyword-based search
        for fqcn, methods in self.method_registry.items():
            for (method_name, param_count), details in methods.items():
                # Check if query matches method name, class name, or code
                code_lower = details["code"].lower()
                
                score = 0
                if query_lower in method_name.lower():
                    score += 3
                if query_lower in fqcn.lower():
                    score += 2
                if query_lower in code_lower:
                    score += 1
                
                if score > 0:
                    results.append({
                        "rank": len(results) + 1,
                        "similarity_score": score / 6.0,  # Normalize to 0-1
                        "fqcn": fqcn,
                        "method_name": method_name,
                        "param_count": param_count,
                        "context": f"Class: {fqcn} | Method: {method_name}",
                        "code": details["code"],
                        "file_path": str(details["file_path"])
                    })
        
        # Sort by score and limit results
        results.sort(key=lambda x: x["similarity_score"], reverse=True)
        return results[:top_k]
    
    def get_method_by_signature(self, class_name: str, method_name: str, param_count: int) -> Dict[str, Any]:
        """Get method by exact signature (traditional lookup)"""
        self._parse_and_index_files()
        
        # Find FQCN
        target_fqcn = None
        if '.' in class_name:
            target_fqcn = class_name
        else:
            possible_fqcns = self.simple_name_index.get(class_name)
            if not possible_fqcns:
                return {"error": f"cannot found '{class_name}' "}
            if len(possible_fqcns) > 1:
                return {"error": f"exist many '{class_name}' \n please use {possible_fqcns}"}
            target_fqcn = possible_fqcns[0]
        
        if not target_fqcn:
            return {"error": f"cannot '{class_name}' FQCN。"}
        
        class_methods = self.method_registry.get(target_fqcn)
        if not class_methods:
            return {"error": f"cannot found '{target_fqcn}'"}
        
        method_details = class_methods.get((method_name, param_count))
        if not method_details:
            return {"error": f"cannot in '{target_fqcn}' found  '{method_name}' which have {param_count} parameters"}
        
        method_details['fqcn'] = target_fqcn
        return method_details


class VectorMethodTracer:
    """Method tracer using vector database for enhanced context"""
    
    def __init__(self, rag_tool: VectorRAGTool, max_depth: int = 5):
        self.rag_tool = rag_tool
        self.max_depth = max_depth
    
    def trace_method_with_context(self, class_name: str, method_name: str, param_count: int, 
                                 semantic_context: str = None) -> Dict[str, Any]:
        """Trace method logic with semantic context"""
        
        # Get method details
        method_details = self.rag_tool.get_method_by_signature(class_name, method_name, param_count)
        if "error" in method_details:
            return {"status": "ERROR", "details": method_details["error"]}
        
        fqcn = method_details['fqcn']
        
        # Perform semantic search for related methods if context provided
        related_methods = []
        if semantic_context:
            query = f"{semantic_context} {method_name} {class_name}"
            related_methods = self.rag_tool.semantic_search_methods(query, top_k=3)
        
        # Traditional tracing
        trace_history = []
        self._trace_recursive(fqcn, method_name, param_count, 1, trace_history)
        
        return {
            "status": "COMPLETE",
            "trace": trace_history,
            "semantic_context": {
                "query": semantic_context,
                "related_methods": related_methods
            },
            "method_details": {
                "fqcn": fqcn,
                "method_name": method_name,
                "param_count": param_count,
                "code": method_details["code"],
                "file_path": method_details["file_path"]
            }
        }
    
    def _trace_recursive(self, fqcn: str, method_name: str, param_count: int, 
                        current_depth: int, trace_history: list):
        """Recursive method tracing"""
        if current_depth > self.max_depth:
            trace_history.append({"status": "STOPPED", "reason": "max depth reached"})
            return
        
        # Get current method details
        method_details = self.rag_tool.get_method_by_signature(fqcn, method_name, param_count)
        if isinstance(method_details, dict) and "error" in method_details:
            trace_history.append({"status": "ERROR", "details": method_details["error"]})
            return
        
        method_code = method_details['code']
        trace_history.append({
            "status": "FOUND",
            "class": fqcn,
            "method": method_name,
            "param_count": param_count,
            "code": method_code
        })
        
        # Parse method body for internal calls
        try:
            wrapper_code = f"class DummyWrapper {{ {method_code} }}"
            tree = javalang.parse.parse(wrapper_code)
            
            for _, node in tree.filter(javalang.tree.MethodInvocation):
                is_internal_call = (node.qualifier is None or node.qualifier == 'this')
                
                if node.member == method_name and is_internal_call:
                    next_param_count = len(node.arguments)
                    if next_param_count != param_count:
                        # Found overload call! Recursive trace
                        self._trace_recursive(fqcn, method_name, next_param_count, 
                                            current_depth + 1, trace_history)
                        return
        except Exception:
            # If method body cannot be parsed, stop tracing
            return


def create_vector_rag_tool(source_base_dir: str, vector_db_path: str = "./vector_db") -> VectorRAGTool:
    """Factory function to create VectorRAGTool"""
    return VectorRAGTool(source_base_dir, vector_db_path)


def create_vector_method_tracer(rag_tool: VectorRAGTool, max_depth: int = 5) -> VectorMethodTracer:
    """Factory function to create VectorMethodTracer"""
    return VectorMethodTracer(rag_tool, max_depth)
