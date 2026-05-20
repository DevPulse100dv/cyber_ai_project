"""
Agent Orchestrator for the Agentic Cyber Security System.

Manages multi-agent coordination, message passing, and workflow execution.
"""

import asyncio
import logging
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any
from uuid import uuid4

from src.config import AppConfig


class WorkflowStatus(Enum):
    """Status of a workflow execution."""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


@dataclass
class WorkflowStep:
    """A step in a workflow."""
    agent_name: str
    action: str
    parameters: dict[str, Any] = field(default_factory=dict)
    depends_on: list[str] = field(default_factory=list)
    result: Any = None
    status: WorkflowStatus = WorkflowStatus.PENDING


@dataclass
class Workflow:
    """A workflow definition."""
    workflow_id: str
    name: str
    steps: list[WorkflowStep]
    status: WorkflowStatus = WorkflowStatus.PENDING
    created_at: datetime = field(default_factory=datetime.now)
    completed_at: datetime | None = None
    results: dict[str, Any] = field(default_factory=dict)


@dataclass
class AgentMessage:
    """Message passed between agents."""
    message_id: str
    from_agent: str
    to_agent: str
    message_type: str  # 'request', 'response', 'notification', 'handoff'
    content: dict[str, Any]
    timestamp: datetime = field(default_factory=datetime.now)


class KnowledgeBase:
    """
    Shared knowledge base for agents.
    
    Stores findings, IOCs, incidents, and other shared data.
    """
    
    def __init__(self):
        self._store: dict[str, dict[str, Any]] = {
            "threats": {},
            "incidents": {},
            "vulnerabilities": {},
            "iocs": {},
            "assets": {},
        }
        self._lock = asyncio.Lock()
    
    async def store(self, category: str, key: str, data: Any) -> None:
        """Store data in the knowledge base."""
        async with self._lock:
            if category not in self._store:
                self._store[category] = {}
            self._store[category][key] = {
                "data": data,
                "updated_at": datetime.now().isoformat(),
            }
    
    async def retrieve(self, category: str, key: str) -> Any | None:
        """Retrieve data from the knowledge base."""
        async with self._lock:
            if category in self._store and key in self._store[category]:
                return self._store[category][key]["data"]
            return None
    
    async def list_keys(self, category: str) -> list[str]:
        """List all keys in a category."""
        async with self._lock:
            if category in self._store:
                return list(self._store[category].keys())
            return []
    
    async def search(self, category: str, filter_fn: Any = None) -> list[Any]:
        """Search for data matching a filter function."""
        async with self._lock:
            if category not in self._store:
                return []
            
            results = []
            for key, item in self._store[category].items():
                if filter_fn is None or filter_fn(item["data"]):
                    results.append({"key": key, **item})
            return results


class AgentOrchestrator:
    """
    Orchestrates multiple security agents.
    
    Responsibilities:
    - Agent lifecycle management
    - Inter-agent communication
    - Workflow execution
    - Shared knowledge base management
    """
    
    def __init__(self, config: AppConfig):
        """
        Initialize the orchestrator.
        
        Args:
            config: Application configuration.
        """
        self.config = config
        self.orchestrator_id = str(uuid4())
        self.logger = logging.getLogger("orchestrator")
        
        # Agent registry
        self._agents: dict[str, Any] = {}  # Will hold BaseAgent instances
        
        # Communication
        self._message_queue: asyncio.Queue[AgentMessage] = asyncio.Queue()
        self._message_handlers: dict[str, list[Any]] = {}
        
        # Knowledge base
        self.knowledge_base = KnowledgeBase()
        
        # Workflows
        self._workflows: dict[str, Workflow] = {}
        
        # Semaphore for concurrent agent limit
        self._semaphore = asyncio.Semaphore(config.orchestration.max_concurrent_agents)
        
        self.logger.info(f"Orchestrator initialized with ID: {self.orchestrator_id}")
    
    def register_agent(self, agent_name: str, agent: Any) -> None:
        """
        Register an agent with the orchestrator.
        
        Args:
            agent_name: Unique name for the agent.
            agent: The agent instance.
        """
        self._agents[agent_name] = agent
        self.logger.info(f"Registered agent: {agent_name}")
    
    def get_agent(self, agent_name: str) -> Any | None:
        """Get a registered agent by name."""
        return self._agents.get(agent_name)
    
    def list_agents(self) -> list[str]:
        """List all registered agent names."""
        return list(self._agents.keys())
    
    async def send_message(
        self,
        from_agent: str,
        to_agent: str,
        message_type: str,
        content: dict[str, Any],
    ) -> str:
        """
        Send a message from one agent to another.
        
        Args:
            from_agent: Sending agent name.
            to_agent: Receiving agent name.
            message_type: Type of message.
            content: Message content.
            
        Returns:
            str: Message ID.
        """
        message = AgentMessage(
            message_id=str(uuid4()),
            from_agent=from_agent,
            to_agent=to_agent,
            message_type=message_type,
            content=content,
        )
        
        await self._message_queue.put(message)
        self.logger.debug(f"Message queued: {from_agent} -> {to_agent} ({message_type})")
        
        return message.message_id
    
    async def process_messages(self) -> None:
        """Process messages in the queue."""
        while True:
            try:
                message = await asyncio.wait_for(
                    self._message_queue.get(),
                    timeout=1.0,
                )
                
                # Find handlers for the target agent
                if message.to_agent in self._message_handlers:
                    for handler in self._message_handlers[message.to_agent]:
                        try:
                            await handler(message)
                        except Exception as e:
                            self.logger.error(f"Message handler error: {e}")
                
                self._message_queue.task_done()
                
            except asyncio.TimeoutError:
                continue
            except asyncio.CancelledError:
                break
    
    async def handoff(
        self,
        from_agent: str,
        to_agent: str,
        context: dict[str, Any],
    ) -> Any:
        """
        Hand off work from one agent to another.
        
        Args:
            from_agent: Current agent.
            to_agent: Target agent.
            context: Context to pass to target agent.
            
        Returns:
            Response from target agent.
        """
        target = self.get_agent(to_agent)
        if target is None:
            raise ValueError(f"Agent '{to_agent}' not registered")
        
        self.logger.info(f"Handoff: {from_agent} -> {to_agent}")
        
        # Store handoff in knowledge base
        await self.knowledge_base.store(
            "handoffs",
            str(uuid4()),
            {
                "from": from_agent,
                "to": to_agent,
                "context": context,
                "timestamp": datetime.now().isoformat(),
            }
        )
        
        # Create prompt for target agent
        handoff_prompt = (
            f"[HANDOFF from {from_agent}]\n"
            f"Context: {context.get('summary', 'No summary provided')}\n"
            f"Data: {context.get('data', {})}\n"
            f"Please continue the analysis and take appropriate action."
        )
        
        async with self._semaphore:
            return await target.process(handoff_prompt)
    
    async def run_workflow(self, workflow: Workflow) -> Workflow:
        """
        Execute a workflow.
        
        Args:
            workflow: The workflow to execute.
            
        Returns:
            Workflow: Updated workflow with results.
        """
        self._workflows[workflow.workflow_id] = workflow
        workflow.status = WorkflowStatus.RUNNING
        
        self.logger.info(f"Starting workflow: {workflow.name}")
        
        try:
            # Simple sequential execution for now
            # TODO: Implement parallel execution based on dependencies
            for step in workflow.steps:
                agent = self.get_agent(step.agent_name)
                if agent is None:
                    self.logger.error(f"Agent not found: {step.agent_name}")
                    step.status = WorkflowStatus.FAILED
                    continue
                
                step.status = WorkflowStatus.RUNNING
                
                try:
                    async with self._semaphore:
                        prompt = f"Execute action: {step.action}\nParameters: {step.parameters}"
                        result = await agent.process(prompt)
                        step.result = result
                        step.status = WorkflowStatus.COMPLETED
                        workflow.results[step.action] = result
                except Exception as e:
                    self.logger.error(f"Step failed: {step.action} - {e}")
                    step.status = WorkflowStatus.FAILED
                    step.result = {"error": str(e)}
            
            # Check overall workflow status
            failed_steps = [s for s in workflow.steps if s.status == WorkflowStatus.FAILED]
            if failed_steps:
                workflow.status = WorkflowStatus.FAILED
            else:
                workflow.status = WorkflowStatus.COMPLETED
            
            workflow.completed_at = datetime.now()
            
        except Exception as e:
            self.logger.error(f"Workflow failed: {e}")
            workflow.status = WorkflowStatus.FAILED
        
        return workflow
    
    async def analyze_threat(self, description: str) -> dict[str, Any]:
        """
        Run a threat analysis using the threat detection agent.
        
        Args:
            description: Description of the potential threat.
            
        Returns:
            dict: Analysis results.
        """
        agent = self.get_agent("threat_detection")
        if agent is None:
            return {"error": "Threat detection agent not registered"}
        
        async with self._semaphore:
            response = await agent.process(
                f"Analyze the following potential threat:\n{description}"
            )
            
            # Store in knowledge base
            await self.knowledge_base.store(
                "threats",
                str(uuid4()),
                {
                    "description": description,
                    "analysis": response.to_dict(),
                    "timestamp": datetime.now().isoformat(),
                }
            )
            
            return response.to_dict()
    
    async def triage_incident(
        self,
        severity: str,
        description: str,
        evidence: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """
        Triage an incident using the incident response agent.
        
        Args:
            severity: Incident severity level.
            description: Incident description.
            evidence: Optional evidence data.
            
        Returns:
            dict: Triage results.
        """
        agent = self.get_agent("incident_response")
        if agent is None:
            return {"error": "Incident response agent not registered"}
        
        prompt = f"""
        Triage the following incident:
        Severity: {severity}
        Description: {description}
        Evidence: {evidence or 'None provided'}
        
        Please classify the incident and recommend immediate actions.
        """
        
        async with self._semaphore:
            response = await agent.process(prompt)
            
            # Store incident in knowledge base
            incident_id = str(uuid4())
            await self.knowledge_base.store(
                "incidents",
                incident_id,
                {
                    "severity": severity,
                    "description": description,
                    "evidence": evidence,
                    "triage": response.to_dict(),
                    "status": "triaged",
                    "created_at": datetime.now().isoformat(),
                }
            )
            
            result = response.to_dict()
            result["incident_id"] = incident_id
            return result
    
    async def scan_vulnerabilities(self, target: str) -> dict[str, Any]:
        """
        Scan for vulnerabilities using the vulnerability management agent.
        
        Args:
            target: Scan target (IP, hostname, or range).
            
        Returns:
            dict: Scan results.
        """
        agent = self.get_agent("vulnerability_management")
        if agent is None:
            return {"error": "Vulnerability management agent not registered"}
        
        async with self._semaphore:
            response = await agent.process(
                f"Scan the following target for vulnerabilities:\n{target}"
            )
            
            # Store results in knowledge base
            await self.knowledge_base.store(
                "vulnerabilities",
                str(uuid4()),
                {
                    "target": target,
                    "scan_results": response.to_dict(),
                    "timestamp": datetime.now().isoformat(),
                }
            )
            
            return response.to_dict()
    
    async def close(self) -> None:
        """Clean up all agents and resources."""
        for name, agent in self._agents.items():
            try:
                await agent.close()
                self.logger.info(f"Closed agent: {name}")
            except Exception as e:
                self.logger.error(f"Error closing agent {name}: {e}")
        
        self._agents.clear()
        self.logger.info("Orchestrator closed")
