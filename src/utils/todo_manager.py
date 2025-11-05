"""
TODOLIST 管理模块
负责在多智能体框架中分发和同步任务列表
"""
import json
from typing import Dict, List, Any, Optional
from enum import Enum
from datetime import datetime


class TaskStatus(Enum):
    """任务状态枚举"""
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"


class TaskPriority(Enum):
    """任务优先级枚举"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Task:
    """任务类"""
    
    def __init__(self, 
                 task_id: str,
                 content: str,
                 agent_assigned: str,
                 priority: TaskPriority = TaskPriority.MEDIUM,
                 dependencies: List[str] = None,
                 timeout_seconds: int = 300):
        self.task_id = task_id
        self.content = content
        self.agent_assigned = agent_assigned
        self.priority = priority
        self.status = TaskStatus.PENDING
        self.dependencies = dependencies or []
        self.timeout_seconds = timeout_seconds
        self.created_at = datetime.now()
        self.started_at = None
        self.completed_at = None
        self.result = None
        self.error_message = None
    
    def to_dict(self) -> Dict[str, Any]:
        """转换为字典格式"""
        return {
            "task_id": self.task_id,
            "content": self.content,
            "agent_assigned": self.agent_assigned,
            "priority": self.priority.value,
            "status": self.status.value,
            "dependencies": self.dependencies,
            "timeout_seconds": self.timeout_seconds,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "result": self.result,
            "error_message": self.error_message
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Task':
        """从字典创建任务"""
        task = cls(
            task_id=data["task_id"],
            content=data["content"],
            agent_assigned=data["agent_assigned"],
            priority=TaskPriority(data["priority"]),
            dependencies=data.get("dependencies", []),
            timeout_seconds=data.get("timeout_seconds", 300)
        )
        task.status = TaskStatus(data["status"])
        
        if data.get("created_at"):
            task.created_at = datetime.fromisoformat(data["created_at"])
        if data.get("started_at"):
            task.started_at = datetime.fromisoformat(data["started_at"])
        if data.get("completed_at"):
            task.completed_at = datetime.fromisoformat(data["completed_at"])
        
        task.result = data.get("result")
        task.error_message = data.get("error_message")
        
        return task


class TodoManager:
    """TODOLIST 管理器"""
    
    def __init__(self):
        self.tasks: Dict[str, Task] = {}
        self.agent_tasks: Dict[str, List[str]] = {}  # agent_name -> list of task_ids
        self.task_counter = 0
    
    def create_task(self, 
                   content: str, 
                   agent_assigned: str,
                   priority: TaskPriority = TaskPriority.MEDIUM,
                   dependencies: List[str] = None,
                   timeout_seconds: int = 300) -> str:
        """创建新任务"""
        self.task_counter += 1
        task_id = f"task_{self.task_counter:06d}"
        
        task = Task(
            task_id=task_id,
            content=content,
            agent_assigned=agent_assigned,
            priority=priority,
            dependencies=dependencies,
            timeout_seconds=timeout_seconds
        )
        
        self.tasks[task_id] = task
        
        # 添加到智能体的任务列表
        if agent_assigned not in self.agent_tasks:
            self.agent_tasks[agent_assigned] = []
        self.agent_tasks[agent_assigned].append(task_id)
        
        return task_id
    
    def get_agent_tasks(self, agent_name: str, include_completed: bool = False) -> List[Task]:
        """获取指定智能体的任务列表"""
        if agent_name not in self.agent_tasks:
            return []
        
        tasks = []
        for task_id in self.agent_tasks[agent_name]:
            task = self.tasks.get(task_id)
            if task and (include_completed or task.status != TaskStatus.COMPLETED):
                tasks.append(task)
        
        return tasks
    
    def get_pending_tasks(self, agent_name: str) -> List[Task]:
        """获取指定智能体的待处理任务"""
        tasks = self.get_agent_tasks(agent_name)
        return [task for task in tasks if task.status == TaskStatus.PENDING]
    
    def start_task(self, task_id: str) -> bool:
        """开始执行任务"""
        task = self.tasks.get(task_id)
        if not task or task.status != TaskStatus.PENDING:
            return False
        
        # 检查依赖任务是否完成
        for dep_id in task.dependencies:
            dep_task = self.tasks.get(dep_id)
            if dep_task and dep_task.status != TaskStatus.COMPLETED:
                return False
        
        task.status = TaskStatus.IN_PROGRESS
        task.started_at = datetime.now()
        return True
    
    def complete_task(self, task_id: str, result: Any = None) -> bool:
        """完成任务"""
        task = self.tasks.get(task_id)
        if not task or task.status != TaskStatus.IN_PROGRESS:
            return False
        
        task.status = TaskStatus.COMPLETED
        task.completed_at = datetime.now()
        task.result = result
        return True
    
    def fail_task(self, task_id: str, error_message: str = None) -> bool:
        """标记任务失败"""
        task = self.tasks.get(task_id)
        if not task or task.status != TaskStatus.IN_PROGRESS:
            return False
        
        task.status = TaskStatus.FAILED
        task.completed_at = datetime.now()
        task.error_message = error_message
        return True
    
    def get_task_status(self, task_id: str) -> Optional[TaskStatus]:
        """获取任务状态"""
        task = self.tasks.get(task_id)
        return task.status if task else None
    
    def get_overall_progress(self) -> Dict[str, Any]:
        """获取整体进度"""
        total_tasks = len(self.tasks)
        if total_tasks == 0:
            return {"total": 0, "completed": 0, "progress": 100.0}
        
        completed_tasks = sum(1 for task in self.tasks.values() 
                            if task.status == TaskStatus.COMPLETED)
        
        progress = (completed_tasks / total_tasks) * 100
        
        return {
            "total": total_tasks,
            "completed": completed_tasks,
            "in_progress": sum(1 for task in self.tasks.values() 
                              if task.status == TaskStatus.IN_PROGRESS),
            "pending": sum(1 for task in self.tasks.values() 
                          if task.status == TaskStatus.PENDING),
            "progress": round(progress, 2)
        }
    
    def to_dict(self) -> Dict[str, Any]:
        """转换为字典格式"""
        return {
            "tasks": {task_id: task.to_dict() for task_id, task in self.tasks.items()},
            "agent_tasks": self.agent_tasks,
            "task_counter": self.task_counter,
            "overall_progress": self.get_overall_progress()
        }
    
    def from_dict(self, data: Dict[str, Any]) -> None:
        """从字典加载数据"""
        self.tasks = {}
        self.agent_tasks = {}
        
        # 恢复任务
        for task_id, task_data in data.get("tasks", {}).items():
            self.tasks[task_id] = Task.from_dict(task_data)
        
        # 恢复智能体任务映射
        self.agent_tasks = data.get("agent_tasks", {})
        
        # 恢复计数器
        self.task_counter = data.get("task_counter", 0)
    
    def clear_completed_tasks(self) -> None:
        """清理已完成的任务"""
        completed_task_ids = [task_id for task_id, task in self.tasks.items() 
                            if task.status == TaskStatus.COMPLETED]
        
        for task_id in completed_task_ids:
            # 从智能体任务列表中移除
            for agent_name, task_ids in self.agent_tasks.items():
                if task_id in task_ids:
                    task_ids.remove(task_id)
            # 从主任务字典中移除
            del self.tasks[task_id]
    
    def get_task_summary(self) -> str:
        """获取任务摘要"""
        progress = self.get_overall_progress()
        summary = f"总体进度: {progress['progress']}% ({progress['completed']}/{progress['total']})\n"
        
        for agent_name in sorted(self.agent_tasks.keys()):
            agent_tasks = self.get_agent_tasks(agent_name)
            pending = sum(1 for task in agent_tasks if task.status == TaskStatus.PENDING)
            in_progress = sum(1 for task in agent_tasks if task.status == TaskStatus.IN_PROGRESS)
            completed = sum(1 for task in agent_tasks if task.status == TaskStatus.COMPLETED)
            
            summary += f"{agent_name}: 待处理 {pending}, 进行中 {in_progress}, 已完成 {completed}\n"
        
        return summary