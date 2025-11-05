"""
Interactive TODOLIST Manager
Mimics Claude Code style with dynamic updates and status display
"""

import json
from typing import Dict, List, Any, Optional
from enum import Enum
from datetime import datetime


class TaskStatus(Enum):
    """Task status enumeration"""
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"


class Task:
    """Task class representing individual todo items"""
    
    def __init__(self, 
                 task_id: str,
                 content: str,
                 agent_assigned: str = None,
                 dependencies: List[str] = None):
        self.task_id = task_id
        self.content = content
        self.agent_assigned = agent_assigned
        self.status = TaskStatus.PENDING
        self.dependencies = dependencies or []
        self.created_at = datetime.now()
        self.started_at = None
        self.completed_at = None
        self.result = None
        self.error_message = None
    
    def get_status_symbol(self) -> str:
        """Get status symbol mimicking Claude Code style"""
        if self.status == TaskStatus.COMPLETED:
            return "☒"
        elif self.status == TaskStatus.IN_PROGRESS:
            return "☐"
        else:  # PENDING or FAILED
            return "☐"
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert task to dictionary format"""
        return {
            "task_id": self.task_id,
            "content": self.content,
            "agent_assigned": self.agent_assigned,
            "status": self.status.value,
            "dependencies": self.dependencies,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "result": self.result,
            "error_message": self.error_message
        }


class InteractiveTodoManager:
    """Interactive TODOLIST manager with Claude Code style display"""
    
    def __init__(self):
        self.tasks: Dict[str, Task] = {}
        self.task_counter = 0
        self.display_header = "Todos"
    
    def create_task(self, content: str, agent_assigned: str = None, dependencies: List[str] = None) -> str:
        """Create a new task"""
        self.task_counter += 1
        task_id = f"task_{self.task_counter:03d}"
        
        task = Task(
            task_id=task_id,
            content=content,
            agent_assigned=agent_assigned,
            dependencies=dependencies
        )
        
        self.tasks[task_id] = task
        return task_id
    
    def start_task(self, task_id: str) -> bool:
        """Start executing a task"""
        task = self.tasks.get(task_id)
        if not task or task.status != TaskStatus.PENDING:
            return False
        
        # Check if dependencies are completed
        for dep_id in task.dependencies:
            dep_task = self.tasks.get(dep_id)
            if dep_task and dep_task.status != TaskStatus.COMPLETED:
                return False
        
        task.status = TaskStatus.IN_PROGRESS
        task.started_at = datetime.now()
        return True
    
    def complete_task(self, task_id: str, result: Any = None) -> bool:
        """Mark a task as completed"""
        task = self.tasks.get(task_id)
        if not task or task.status != TaskStatus.IN_PROGRESS:
            return False
        
        task.status = TaskStatus.COMPLETED
        task.completed_at = datetime.now()
        task.result = result
        return True
    
    def fail_task(self, task_id: str, error_message: str = None) -> bool:
        """Mark a task as failed"""
        task = self.tasks.get(task_id)
        if not task or task.status != TaskStatus.IN_PROGRESS:
            return False
        
        task.status = TaskStatus.FAILED
        task.completed_at = datetime.now()
        task.error_message = error_message
        return True
    
    def get_pending_tasks(self) -> List[Task]:
        """Get all pending tasks"""
        return [task for task in self.tasks.values() if task.status == TaskStatus.PENDING]
    
    def get_in_progress_tasks(self) -> List[Task]:
        """Get all in-progress tasks"""
        return [task for task in self.tasks.values() if task.status == TaskStatus.IN_PROGRESS]
    
    def get_completed_tasks(self) -> List[Task]:
        """Get all completed tasks"""
        return [task for task in self.tasks.values() if task.status == TaskStatus.COMPLETED]
    
    def get_overall_progress(self) -> Dict[str, Any]:
        """Get overall progress statistics"""
        total_tasks = len(self.tasks)
        if total_tasks == 0:
            return {"total": 0, "completed": 0, "progress": 100.0}
        
        completed_tasks = len(self.get_completed_tasks())
        progress = (completed_tasks / total_tasks) * 100
        
        return {
            "total": total_tasks,
            "completed": completed_tasks,
            "in_progress": len(self.get_in_progress_tasks()),
            "pending": len(self.get_pending_tasks()),
            "progress": round(progress, 2)
        }
    
    def display_todo_list(self) -> str:
        """Display TODOLIST in Claude Code style"""
        if not self.tasks:
            return ""
        
        lines = [self.display_header]
        
        # Display all tasks in creation order
        sorted_tasks = sorted(self.tasks.values(), key=lambda t: t.created_at)
        
        for task in sorted_tasks:
            status_symbol = task.get_status_symbol()
            line = f"  {status_symbol} {task.content}"
            
            # Show assigned agent in parentheses if available
            if task.agent_assigned:
                line += f" ({task.agent_assigned})"
            
            lines.append(line)
        
        # Add progress information
        progress = self.get_overall_progress()
        lines.append(f"\nProgress: {progress['progress']}% ({progress['completed']}/{progress['total']} tasks completed)")
        
        return "\n".join(lines)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert manager to dictionary format"""
        return {
            "tasks": {task_id: task.to_dict() for task_id, task in self.tasks.items()},
            "task_counter": self.task_counter,
            "display_header": self.display_header,
            "overall_progress": self.get_overall_progress()
        }
    
    def from_dict(self, data: Dict[str, Any]) -> None:
        """Load data from dictionary"""
        self.tasks = {}
        
        # Restore tasks
        for task_id, task_data in data.get("tasks", {}).items():
            task = Task(
                task_id=task_data["task_id"],
                content=task_data["content"],
                agent_assigned=task_data.get("agent_assigned"),
                dependencies=task_data.get("dependencies", [])
            )
            task.status = TaskStatus(task_data["status"])
            
            if task_data.get("created_at"):
                task.created_at = datetime.fromisoformat(task_data["created_at"])
            if task_data.get("started_at"):
                task.started_at = datetime.fromisoformat(task_data["started_at"])
            if task_data.get("completed_at"):
                task.completed_at = datetime.fromisoformat(task_data["completed_at"])
            
            task.result = task_data.get("result")
            task.error_message = task_data.get("error_message")
            
            self.tasks[task_id] = task
        
        # Restore counter
        self.task_counter = data.get("task_counter", 0)
        self.display_header = data.get("display_header", "Todos")


class TaskAnalyzer:
    """Task analyzer - analyzes multi-agent framework and generates initial TODOLIST"""
    
    def __init__(self):
        self.todo_manager = InteractiveTodoManager()
    
    def analyze_multi_agent_framework(self, framework_description: str = None) -> InteractiveTodoManager:
        """Analyze multi-agent framework and generate initial TODOLIST"""
        
        # Based on analysis of multi-agent vulnerability validation framework
        tasks = [
            "Analyze current code structure, understand multi-agent framework organization",
            "Design TODOLIST distribution and synchronization mechanism",
            "Implement TODOLIST data structure and management module",
            "Integrate TODOLIST into existing agent system",
            "Test TODOLIST distribution and synchronization functionality"
        ]
        
        # Create tasks
        task_ids = []
        for task_content in tasks:
            task_id = self.todo_manager.create_task(task_content)
            task_ids.append(task_id)
        
        return self.todo_manager
    
    def analyze_vulnerability_workflow(self) -> InteractiveTodoManager:
        """Analyze vulnerability validation workflow and generate agent tasks"""
        
        # Typical tasks in vulnerability validation workflow
        workflow_tasks = [
            ("Analyze function call chain, determine task type", "agent_a"),
            ("Analyze vulnerability exploitability, assess vulnerability authenticity", "agent_c"),
            ("Review analysis results, make final decision", "agent_f"),
            ("Analyze routing information and modification functions", "agent_b"),
            ("Review routing information and exploitability assessment", "agent_g"),
            ("Generate PoC payload and curl command", "agent_d"),
            ("Verify PoC execution results", "agent_e")
        ]
        
        # Create tasks with dependencies
        task_ids = []
        dependencies = []
        
        for i, (task_content, agent) in enumerate(workflow_tasks):
            task_id = self.todo_manager.create_task(
                content=task_content,
                agent_assigned=agent,
                dependencies=dependencies.copy()
            )
            task_ids.append(task_id)
            
            # Each task depends on the previous one
            if i < len(workflow_tasks) - 1:
                dependencies = [task_id]
        
        return self.todo_manager


class ModelBasedTaskGenerator:
    """Model-based task generator that analyzes vulnerability context and generates TODOLIST"""
    
    def __init__(self, llm_client=None):
        self.todo_manager = InteractiveTodoManager()
        self.llm_client = llm_client
    
    def generate_tasks_from_vulnerability(self, vulnerability_data: Dict[str, Any]) -> InteractiveTodoManager:
        """Generate TODOLIST based on vulnerability analysis using model"""
        
        # Extract key information from vulnerability data
        vuln_id = vulnerability_data.get('vuln_id', 'unknown')
        call_chain = vulnerability_data.get('call_chain', [])
        source_code = vulnerability_data.get('source_code', {})
        
        # Use model to analyze and generate appropriate tasks
        if self.llm_client:
            # If LLM client is available, use it for intelligent task generation
            return self._generate_tasks_with_llm(vulnerability_data)
        else:
            # Fallback to rule-based task generation
            return self._generate_tasks_rule_based(vulnerability_data)
    
    def _generate_tasks_rule_based(self, vulnerability_data: Dict[str, Any]) -> InteractiveTodoManager:
        """Generate tasks based on predefined rules for vulnerability validation"""
        
        vuln_id = vulnerability_data.get('vuln_id', 'unknown')
        
        # Define tasks based on vulnerability validation workflow
        tasks = [
            ("Analyze function call chain structure and determine task type", "agent_a", []),
            ("Assess vulnerability exploitability and authenticity", "agent_c", ["task_001"]),
            ("Review analysis results and make final decision", "agent_f", ["task_002"]),
            ("Analyze routing information and identify modification functions", "agent_b", ["task_003"]),
            ("Review routing analysis and exploitability assessment", "agent_g", ["task_004"]),
            ("Generate PoC payload and curl command for validation", "agent_d", ["task_005"]),
            ("Execute and verify PoC results", "agent_e", ["task_006"])
        ]
        
        # Create tasks with proper dependencies
        task_ids = []
        for i, (content, agent, _) in enumerate(tasks):
            task_id = f"task_{i+1:03d}"
            dependencies = task_ids[-1:] if task_ids else []
            
            self.todo_manager.create_task(
                content=f"[{vuln_id}] {content}",
                agent_assigned=agent,
                dependencies=dependencies
            )
            task_ids.append(task_id)
        
        return self.todo_manager
    
    def _generate_tasks_with_llm(self, vulnerability_data: Dict[str, Any]) -> InteractiveTodoManager:
        """Generate tasks using LLM for intelligent analysis"""
        # This would be implemented when LLM integration is available
        # For now, fall back to rule-based generation
        return self._generate_tasks_rule_based(vulnerability_data)
    
    def update_tasks_based_on_context(self, context: Dict[str, Any]) -> None:
        """Update existing tasks based on runtime context and progress"""
        
        # Check if any tasks need to be modified based on current context
        current_progress = self.todo_manager.get_overall_progress()
        
        # Example: If retry count is high, add additional analysis tasks
        retry_count = context.get('retry_count', 0)
        if retry_count > 2:
            # Add deep analysis task for persistent failures
            self.todo_manager.create_task(
                content="Perform deep analysis of persistent failure patterns",
                agent_assigned="agent_c",
                dependencies=list(self.todo_manager.tasks.keys())[-1:]
            )


class DynamicTodoManager:
    """Dynamic TODOLIST manager that integrates with multi-agent framework and LLM-based task planning"""
    
    def __init__(self, llm_planner=None):
        self.todo_manager = InteractiveTodoManager()
        self.llm_planner = llm_planner
        self.agent_task_map = {
            "agent_a": "Analyze function call chain and determine task type",
            "agent_b": "Analyze routing information and modification functions",
            "agent_c": "Assess vulnerability exploitability and authenticity",
            "agent_d": "Generate PoC payload and curl command",
            "agent_e": "Execute and verify PoC results",
            "agent_f": "Review analysis results and make final decision",
            "agent_g": "Review routing analysis and exploitability assessment"
        }
    
    def initialize_for_vulnerability(self, vulnerability_data: Dict[str, Any]) -> None:
        """Initialize TODOLIST for a specific vulnerability using LLM-based planning when available"""
        if self.llm_planner:
            # Use LLM-based intelligent task planning
            self.todo_manager = self.llm_planner.analyze_vulnerability_and_plan_tasks(vulnerability_data)
        else:
            # Fallback to rule-based task generation
            task_generator = ModelBasedTaskGenerator()
            self.todo_manager = task_generator.generate_tasks_from_vulnerability(vulnerability_data)
    
    def get_agent_todo_status(self, agent_name: str) -> str:
        """Get TODOLIST status for specific agent in Claude Code style"""
        agent_tasks = [task for task in self.todo_manager.tasks.values() 
                      if task.agent_assigned == agent_name]
        
        if not agent_tasks:
            return f"{agent_name}: No tasks assigned"
        
        lines = [f"{agent_name} Tasks:"]
        for task in sorted(agent_tasks, key=lambda t: t.created_at):
            status_symbol = task.get_status_symbol()
            lines.append(f"  {status_symbol} {task.content}")
        
        return "\n".join(lines)
    
    def mark_agent_task_complete(self, agent_name: str, result: Any = None) -> bool:
        """Mark the current in-progress task for an agent as complete"""
        agent_tasks = [task for task in self.todo_manager.tasks.values() 
                      if task.agent_assigned == agent_name and task.status == TaskStatus.IN_PROGRESS]
        
        if agent_tasks:
            return self.todo_manager.complete_task(agent_tasks[0].task_id, result)
        return False
    
    def start_agent_task(self, agent_name: str) -> bool:
        """Start the next pending task for an agent"""
        pending_tasks = [task for task in self.todo_manager.tasks.values() 
                        if task.agent_assigned == agent_name and task.status == TaskStatus.PENDING]
        
        if pending_tasks:
            # Check if dependencies are satisfied
            task = pending_tasks[0]
            for dep_id in task.dependencies:
                dep_task = self.todo_manager.tasks.get(dep_id)
                if dep_task and dep_task.status != TaskStatus.COMPLETED:
                    return False
            
            return self.todo_manager.start_task(task.task_id)
        return False
    
    def get_overall_display(self) -> str:
        """Get complete TODOLIST display in Claude Code style"""
        return self.todo_manager.display_todo_list()
    
    def get_progress_summary(self) -> Dict[str, Any]:
        """Get detailed progress summary"""
        progress = self.todo_manager.get_overall_progress()
        
        # Add per-agent progress
        agent_progress = {}
        for agent_name in self.agent_task_map.keys():
            agent_tasks = [task for task in self.todo_manager.tasks.values() 
                          if task.agent_assigned == agent_name]
            if agent_tasks:
                completed = sum(1 for task in agent_tasks if task.status == TaskStatus.COMPLETED)
                total = len(agent_tasks)
                agent_progress[agent_name] = {
                    "completed": completed,
                    "total": total,
                    "progress": round((completed / total) * 100, 2) if total > 0 else 100.0
                }
        
        progress["agent_progress"] = agent_progress
        return progress