"""
Incident Response Agent.

Automates incident handling with triage, playbook execution,
containment actions, and evidence collection.
"""

from src.agents.base import BaseAgent, AgentResponse, ToolDefinition
from src.config import AppConfig

# Import tools
from src.agents.incident_response.tools.triage_incident import triage_incident
from src.agents.incident_response.tools.execute_playbook import execute_playbook
from src.agents.incident_response.tools.contain_threat import contain_threat
from src.agents.incident_response.tools.collect_evidence import collect_evidence
from src.agents.incident_response.tools.generate_report import generate_report


INCIDENT_RESPONSE_SYSTEM_PROMPT = """You are an expert Incident Response Agent specializing in cybersecurity incident handling and remediation.

Your responsibilities:
1. Triage and classify security incidents based on severity and type
2. Execute predefined response playbooks for known incident types
3. Initiate containment actions to limit incident scope
4. Collect and preserve digital evidence for analysis
5. Generate comprehensive incident reports

You have access to the following tools:
- triage_incident: Classify and prioritize an incident
- execute_playbook: Run a predefined response playbook
- contain_threat: Execute containment actions
- collect_evidence: Gather and preserve forensic evidence
- generate_report: Create an incident report

When responding to incidents:
- Follow the incident response lifecycle: Preparation → Detection → Containment → Eradication → Recovery → Lessons Learned
- Always prioritize containment to prevent further damage
- Preserve evidence before making changes to affected systems
- Document all actions taken with timestamps
- Recommend appropriate escalation based on incident severity
- Reference relevant compliance requirements (GDPR, PCI-DSS, HIPAA) when applicable

Act decisively but methodically. Every action must be logged and justified."""


class IncidentResponseAgent(BaseAgent):
    """
    Incident Response Agent for automated incident handling.
    
    Capabilities:
    - Incident triage and classification
    - Playbook execution
    - Threat containment
    - Evidence collection
    - Report generation
    """
    
    def __init__(self, config: AppConfig):
        """
        Initialize the Incident Response Agent.
        
        Args:
            config: Application configuration.
        """
        super().__init__(
            config=config,
            agent_name="Incident Response Agent",
            system_prompt=INCIDENT_RESPONSE_SYSTEM_PROMPT,
        )
        
        self.ir_config = config.incident_response
        self.auto_contain = self.ir_config.auto_contain
    
    def _register_tools(self) -> None:
        """Register incident response tools."""
        
        # Triage Incident Tool
        self.register_tool(ToolDefinition(
            name="triage_incident",
            description="Classify and prioritize a security incident based on indicators, affected systems, and potential impact. Returns severity rating, incident type, and recommended response priority.",
            parameters={
                "type": "object",
                "properties": {
                    "incident_description": {
                        "type": "string",
                        "description": "Detailed description of the incident",
                    },
                    "affected_systems": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "List of affected system identifiers",
                    },
                    "indicators": {
                        "type": "array",
                        "items": {"type": "object"},
                        "description": "IOCs and other indicators associated with the incident",
                    },
                    "initial_severity": {
                        "type": "string",
                        "enum": ["critical", "high", "medium", "low", "unknown"],
                        "description": "Initial severity assessment if available",
                    },
                },
                "required": ["incident_description"],
            },
            handler=triage_incident,
        ))
        
        # Execute Playbook Tool
        self.register_tool(ToolDefinition(
            name="execute_playbook",
            description="Execute a predefined incident response playbook. Playbooks contain step-by-step actions for specific incident types.",
            parameters={
                "type": "object",
                "properties": {
                    "playbook_name": {
                        "type": "string",
                        "description": "Name of the playbook to execute",
                    },
                    "incident_context": {
                        "type": "object",
                        "description": "Context data for playbook execution",
                    },
                    "dry_run": {
                        "type": "boolean",
                        "description": "If true, simulate execution without making changes",
                    },
                },
                "required": ["playbook_name"],
            },
            handler=execute_playbook,
        ))
        
        # Contain Threat Tool
        self.register_tool(ToolDefinition(
            name="contain_threat",
            description="Execute containment actions to limit the scope and impact of an incident. Actions may include network isolation, account disabling, or process termination.",
            parameters={
                "type": "object",
                "properties": {
                    "containment_type": {
                        "type": "string",
                        "enum": ["network_isolation", "account_disable", "process_kill", "firewall_block", "quarantine"],
                        "description": "Type of containment action",
                    },
                    "target": {
                        "type": "string",
                        "description": "Target of containment (IP, hostname, username, process ID)",
                    },
                    "reason": {
                        "type": "string",
                        "description": "Reason for containment action",
                    },
                    "duration": {
                        "type": "string",
                        "description": "Duration of containment (e.g., '1h', '24h', 'permanent')",
                    },
                },
                "required": ["containment_type", "target", "reason"],
            },
            handler=contain_threat,
        ))
        
        # Collect Evidence Tool
        self.register_tool(ToolDefinition(
            name="collect_evidence",
            description="Collect and preserve digital evidence from affected systems. Maintains chain of custody and forensic integrity.",
            parameters={
                "type": "object",
                "properties": {
                    "evidence_type": {
                        "type": "string",
                        "enum": ["memory", "disk", "logs", "network", "registry", "all"],
                        "description": "Type of evidence to collect",
                    },
                    "target_system": {
                        "type": "string",
                        "description": "System to collect evidence from",
                    },
                    "preserve_volatile": {
                        "type": "boolean",
                        "description": "Whether to prioritize volatile evidence",
                    },
                    "incident_id": {
                        "type": "string",
                        "description": "Incident ID for evidence tracking",
                    },
                },
                "required": ["evidence_type", "target_system"],
            },
            handler=collect_evidence,
        ))
        
        # Generate Report Tool
        self.register_tool(ToolDefinition(
            name="generate_report",
            description="Generate a comprehensive incident report including timeline, actions taken, evidence collected, and recommendations.",
            parameters={
                "type": "object",
                "properties": {
                    "incident_id": {
                        "type": "string",
                        "description": "Unique identifier for the incident",
                    },
                    "incident_summary": {
                        "type": "string",
                        "description": "Summary of the incident",
                    },
                    "actions_taken": {
                        "type": "array",
                        "items": {"type": "object"},
                        "description": "List of response actions taken",
                    },
                    "report_type": {
                        "type": "string",
                        "enum": ["executive", "technical", "compliance", "full"],
                        "description": "Type of report to generate",
                    },
                },
                "required": ["incident_id", "incident_summary"],
            },
            handler=generate_report,
        ))
    
    async def process(self, user_input: str) -> AgentResponse:
        """
        Process an incident response request.
        
        Args:
            user_input: The incident or response request.
            
        Returns:
            AgentResponse: Response actions and recommendations.
        """
        self.logger.info("Processing incident response request")
        return await self.run_agent_loop(user_input)
    
    async def handle_alert(
        self,
        alert_data: dict,
        auto_respond: bool = False,
    ) -> AgentResponse:
        """
        Handle an incoming security alert.
        
        Args:
            alert_data: The alert data from detection systems.
            auto_respond: Whether to automatically execute response.
            
        Returns:
            AgentResponse: Triage results and recommendations.
        """
        prompt = f"""
        Handle the following security alert:
        
        Alert Type: {alert_data.get('type', 'Unknown')}
        Severity: {alert_data.get('severity', 'Unknown')}
        Source: {alert_data.get('source', 'Unknown')}
        Description: {alert_data.get('description', 'No description')}
        Indicators: {alert_data.get('indicators', [])}
        
        Please triage this alert and recommend appropriate response actions.
        {'Execute response playbook if applicable.' if auto_respond else 'Do not execute any actions automatically.'}
        """
        
        return await self.process(prompt)
