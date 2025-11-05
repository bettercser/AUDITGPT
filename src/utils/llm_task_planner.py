"""
LLM-based Task Planner for Dynamic TODOLIST Generation
Integrates with DeepSeek API to intelligently analyze vulnerabilities and generate task lists
"""

import json
import re
from typing import Dict, List, Any, Optional
from langchain_openai import ChatOpenAI
from utils.interactive_todo import InteractiveTodoManager, TaskStatus


class LLMTaskPlanner:
    """LLM-based task planner that dynamically generates TODOLIST based on vulnerability analysis"""
    
    def __init__(self, api_url: str, api_key: str, model_name: str = "deepseek-chat"):
        self.api_url = api_url
        self.api_key = api_key
        self.model_name = model_name
        self.todo_manager = InteractiveTodoManager()
        
    def _create_llm_client(self) -> ChatOpenAI:
        """Create LLM client for task planning"""
        return ChatOpenAI(
            model=self.model_name,
            temperature=0.1,  # Low temperature for consistent task planning
            base_url=self.api_url,
            api_key=self.api_key,
            max_tokens=4000
        )
    
    def analyze_vulnerability_and_plan_tasks(self, vulnerability_data: Dict[str, Any]) -> InteractiveTodoManager:
        """Analyze vulnerability using LLM and generate intelligent task plan"""
        
        # Prepare prompt for LLM analysis
        prompt = self._create_task_planning_prompt(vulnerability_data)
        
        # Call LLM for task planning
        llm_client = self._create_llm_client()
        response = llm_client.invoke(prompt)
        
        # Parse LLM response and generate tasks
        tasks_data = self._parse_llm_response(response.content)
        
        # Create tasks in TODOLIST manager
        self._create_tasks_from_analysis(tasks_data, vulnerability_data)
        
        return self.todo_manager
    
    def _create_task_planning_prompt(self, vulnerability_data: Dict[str, Any]) -> str:
        """Create intelligent prompt for vulnerability analysis and task planning"""
        
        vuln_id = vulnerability_data.get('vuln_id', 'unknown')
        call_chain = vulnerability_data.get('call_chain', [])
        source_code_files = list(vulnerability_data.get('source_code', {}).keys())
        vuln_type = vulnerability_data.get('vuln_type', 'unknown')
        
        # Extract key information for analysis
        call_chain_summary = self._summarize_call_chain(call_chain)
        
        prompt = f"""
You are an expert vulnerability analysis and task planning system. Your role is to analyze vulnerability information and generate an intelligent task plan for multi-agent validation.

## Vulnerability Information:
- **Vulnerability ID**: {vuln_id}
- **Vulnerability Type**: {vuln_type}
- **Source Code Files**: {source_code_files}
- **Call Chain Summary**: {call_chain_summary}

## Available Agents:
- **agent_a**: Call chain analysis and task type determination
- **agent_b**: Routing information analysis and modification functions
- **agent_c**: Vulnerability exploitability assessment
- **agent_d**: PoC payload generation and curl command creation
- **agent_e**: PoC execution and result verification
- **agent_f**: Final decision making and result review
- **agent_g**: Routing analysis review and exploitability assessment

## Task Planning Instructions:
1. Analyze the vulnerability complexity and create appropriate tasks
2. Consider dependencies between tasks (earlier tasks must complete before dependent tasks)
3. Assign tasks to appropriate agents based on their expertise
4. Include specific analysis steps based on the vulnerability type
5. Consider if additional deep analysis tasks are needed

## Output Format (JSON):
{{
  "analysis_summary": "Brief analysis of the vulnerability",
  "complexity_level": "low|medium|high",
  "tasks": [
    {{
      "description": "Specific task description",
      "assigned_agent": "agent_x",
      "dependencies": ["previous_task_id"],
      "priority": "low|medium|high",
      "estimated_difficulty": "low|medium|high"
    }}
  ]
}}

Please generate a comprehensive task plan for this vulnerability validation:
"""
        
        return prompt
    
    def _summarize_call_chain(self, call_chain: List[Dict[str, Any]]) -> str:
        """Summarize call chain for LLM analysis"""
        if not call_chain:
            return "No call chain information available"
        
        summary_parts = []
        for i, call in enumerate(call_chain):
            file = call.get('file', 'unknown')
            method = call.get('method', 'unknown')
            line = call.get('line', 'unknown')
            summary_parts.append(f"{i+1}. {file}:{method} (line {line})")
        
        return "; ".join(summary_parts)
    
    def _parse_llm_response(self, response_text: str) -> Dict[str, Any]:
        """Parse LLM response and extract task planning data"""
        
        # Try to extract JSON from response
        json_match = re.search(r'\{.*\}', response_text, re.DOTALL)
        
        if json_match:
            try:
                return json.loads(json_match.group())
            except json.JSONDecodeError:
                # Fallback to structured parsing
                return self._fallback_parse_response(response_text)
        else:
            # Use fallback parsing
            return self._fallback_parse_response(response_text)
    
    def _fallback_parse_response(self, response_text: str) -> Dict[str, Any]:
        """Fallback parsing when JSON extraction fails"""
        
        # Extract analysis summary
        analysis_match = re.search(r'analysis_summary[\s\:"]*([^"]+)', response_text, re.IGNORECASE)
        analysis_summary = analysis_match.group(1).strip() if analysis_match else "Vulnerability analysis completed"
        
        # Extract complexity
        complexity_match = re.search(r'complexity_level[\s\:"]*([^\s\"\,]+)', response_text, re.IGNORECASE)
        complexity_level = complexity_match.group(1).strip() if complexity_match else "medium"
        
        # Extract tasks using pattern matching
        tasks = []
        task_patterns = re.finditer(r'"?description"?[\s\:"]*([^"]+)[\s\,\]]*"?assigned_agent"?[\s\:"]*([^\s\"\,]+)', response_text, re.IGNORECASE)
        
        for match in task_patterns:
            description = match.group(1).strip()
            agent = match.group(2).strip()
            
            tasks.append({
                "description": description,
                "assigned_agent": agent,
                "dependencies": [],
                "priority": "medium",
                "estimated_difficulty": "medium"
            })
        
        # If no tasks found, create default tasks
        if not tasks:
            tasks = self._create_default_tasks(complexity_level)
        
        return {
            "analysis_summary": analysis_summary,
            "complexity_level": complexity_level,
            "tasks": tasks
        }
    
    def _create_default_tasks(self, complexity_level: str) -> List[Dict[str, Any]]:
        """Create default tasks based on complexity level"""
        
        base_tasks = [
            {
                "description": "Analyze function call chain and determine task type",
                "assigned_agent": "agent_a",
                "dependencies": [],
                "priority": "high",
                "estimated_difficulty": "medium"
            },
            {
                "description": "Assess vulnerability exploitability and authenticity",
                "assigned_agent": "agent_c",
                "dependencies": ["task_001"],
                "priority": "high",
                "estimated_difficulty": "medium"
            },
            {
                "description": "Review analysis results and make final decision",
                "assigned_agent": "agent_f",
                "dependencies": ["task_002"],
                "priority": "high",
                "estimated_difficulty": "low"
            }
        ]
        
        if complexity_level == "high":
            # Add additional tasks for complex vulnerabilities
            base_tasks.extend([
                {
                    "description": "Deep analysis of routing information and modification functions",
                    "assigned_agent": "agent_b",
                    "dependencies": ["task_003"],
                    "priority": "medium",
                    "estimated_difficulty": "high"
                },
                {
                    "description": "Comprehensive review of routing analysis and exploitability assessment",
                    "assigned_agent": "agent_g",
                    "dependencies": ["task_004"],
                    "priority": "medium",
                    "estimated_difficulty": "medium"
                }
            ])
        
        # Always include PoC generation and verification
        base_tasks.extend([
            {
                "description": "Generate PoC payload and curl command for validation",
                "assigned_agent": "agent_d",
                "dependencies": ["task_003"],
                "priority": "high",
                "estimated_difficulty": "medium"
            },
            {
                "description": "Execute and verify PoC results",
                "assigned_agent": "agent_e",
                "dependencies": ["task_005"],
                "priority": "high",
                "estimated_difficulty": "medium"
            }
        ])
        
        return base_tasks
    
    def _create_tasks_from_analysis(self, tasks_data: Dict[str, Any], vulnerability_data: Dict[str, Any]) -> None:
        """Create tasks in TODOLIST manager based on LLM analysis"""
        
        vuln_id = vulnerability_data.get('vuln_id', 'unknown')
        complexity_level = tasks_data.get('complexity_level', 'medium')
        analysis_summary = tasks_data.get('analysis_summary', 'Vulnerability analysis')
        
        # Add analysis summary as header
        self.todo_manager.display_header = f"TODOS - {vuln_id} ({complexity_level.upper()})"
        
        # Create tasks with proper dependencies
        task_ids = []
        tasks = tasks_data.get('tasks', [])
        
        for i, task_info in enumerate(tasks):
            description = task_info.get('description', f"Task {i+1}")
            agent = task_info.get('assigned_agent', f"agent_{chr(97+i)}")
            dependencies = task_info.get('dependencies', [])
            
            # Convert dependency indices to actual task IDs
            actual_dependencies = []
            for dep in dependencies:
                if isinstance(dep, str) and dep.startswith("task_"):
                    dep_index = int(dep.split("_")[1]) - 1
                    if 0 <= dep_index < len(task_ids):
                        actual_dependencies.append(task_ids[dep_index])
                elif isinstance(dep, int) and 0 <= dep < len(task_ids):
                    actual_dependencies.append(task_ids[dep])
            
            # Create task with vulnerability context
            task_content = f"[{vuln_id}] {description}"
            task_id = self.todo_manager.create_task(
                content=task_content,
                agent_assigned=agent,
                dependencies=actual_dependencies
            )
            
            task_ids.append(task_id)
        
        print(f"✅ Generated {len(task_ids)} tasks for {vuln_id} ({complexity_level} complexity)")
        print(f"📋 Analysis: {analysis_summary}")


class AdaptiveTaskPlanner:
    """Adaptive task planner that can update tasks based on runtime context"""
    
    def __init__(self, llm_planner: LLMTaskPlanner):
        self.llm_planner = llm_planner
        self.execution_context = {}
    
    def generate_initial_plan(self, vulnerability_data: Dict[str, Any]) -> InteractiveTodoManager:
        """Generate initial task plan using LLM analysis"""
        return self.llm_planner.analyze_vulnerability_and_plan_tasks(vulnerability_data)
    
    def adapt_plan_based_on_progress(self, todo_manager: InteractiveTodoManager, context: Dict[str, Any]) -> None:
        """Adapt task plan based on execution progress and context"""
        
        # Update execution context
        self.execution_context.update(context)
        
        # Check if we need to add additional tasks based on failures
        retry_count = context.get('retry_count', 0)
        failure_type = context.get('failure_analysis', {}).get('failure_type', '')
        
        if retry_count >= 2:
            # Add deep analysis task for persistent failures
            self._add_deep_analysis_task(todo_manager, failure_type)
        
        # Check if we need to modify priorities based on progress
        progress = todo_manager.get_overall_progress()
        if progress['progress'] < 30 and context.get('time_elapsed', 0) > 300:  # 5 minutes
            self._adjust_priorities_for_slow_progress(todo_manager)
    
    def _add_deep_analysis_task(self, todo_manager: InteractiveTodoManager, failure_type: str) -> None:
        """Add deep analysis task for persistent failures"""
        
        # Find the last completed task
        completed_tasks = todo_manager.get_completed_tasks()
        if not completed_tasks:
            return
        
        last_task = completed_tasks[-1]
        
        # Create deep analysis task
        analysis_description = f"Perform deep analysis of {failure_type} failure patterns"
        
        todo_manager.create_task(
            content=analysis_description,
            agent_assigned="agent_c",  # Assign to analysis expert
            dependencies=[last_task.task_id]
        )
        
        print(f"🔍 Added deep analysis task for {failure_type} failures")
    
    def _adjust_priorities_for_slow_progress(self, todo_manager: InteractiveTodoManager) -> None:
        """Adjust task priorities for slow progress scenarios"""
        
        pending_tasks = todo_manager.get_pending_tasks()
        for task in pending_tasks:
            # Increase priority for critical path tasks
            if "PoC" in task.content or "verification" in task.content:
                print(f"🚀 Increased priority for: {task.content}")
                # In a real implementation, we would update task priority here


def create_llm_task_planner(api_url: str, api_key: str, model_name: str = "deepseek-chat") -> LLMTaskPlanner:
    """Factory function to create LLM task planner"""
    return LLMTaskPlanner(api_url, api_key, model_name)


def create_adaptive_planner(api_url: str, api_key: str, model_name: str = "deepseek-chat") -> AdaptiveTaskPlanner:
    """Factory function to create adaptive task planner"""
    llm_planner = create_llm_task_planner(api_url, api_key, model_name)
    return AdaptiveTaskPlanner(llm_planner)