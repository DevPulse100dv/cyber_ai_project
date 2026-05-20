"""
Threat Detection Agent.

Monitors security events and detects potential threats using
network analysis, log correlation, and IOC detection.
"""

from src.agents.base import BaseAgent, AgentResponse, ToolDefinition, AgentStatus
from src.config import AppConfig

# Import tools
from src.agents.threat_detection.tools.analyze_network_traffic import analyze_network_traffic
from src.agents.threat_detection.tools.analyze_logs import analyze_logs
from src.agents.threat_detection.tools.detect_ioc import detect_ioc
from src.agents.threat_detection.tools.correlate_events import correlate_events

# ... (rest of file)




THREAT_DETECTION_SYSTEM_PROMPT = """You are an expert Threat Detection Agent specializing in cybersecurity threat analysis and detection.

Your responsibilities:
1. Analyze network traffic patterns for anomalies and potential threats
2. Examine security logs to identify suspicious activities
3. Detect Indicators of Compromise (IOCs) in system data
4. Correlate events across multiple sources to identify attack patterns
5. Generate alerts and recommendations for detected threats

You have access to the following tools:
- analyze_network_traffic: Analyze network traffic data for anomalies
- analyze_logs: Parse and analyze security logs for suspicious patterns
- detect_ioc: Scan data for known Indicators of Compromise
- correlate_events: Cross-correlate events from multiple sources

When analyzing threats:
- Always provide severity ratings (critical, high, medium, low)
- Include specific evidence supporting your findings
- Reference MITRE ATT&CK techniques when applicable
- Recommend immediate actions for confirmed threats
- Suggest which security team should be notified

Be thorough but concise. Focus on actionable intelligence."""


class ThreatDetectionAgent(BaseAgent):
    """
    Threat Detection Agent for real-time security monitoring.
    
    Capabilities:
    - Network traffic analysis
    - Log analysis and correlation
    - IOC detection
    - Event correlation
    - Alert generation
    """
    
    def __init__(self, config: AppConfig):
        """
        Initialize the Threat Detection Agent.
        
        Args:
            config: Application configuration.
        """
        super().__init__(
            config=config,
            agent_name="Threat Detection Agent",
            system_prompt=THREAT_DETECTION_SYSTEM_PROMPT,
        )
        
        self.threat_config = config.threat_detection
        self.alert_threshold = self.threat_config.alert_threshold
    
    def _register_tools(self) -> None:
        """Register threat detection tools."""
        
        # Network Traffic Analysis Tool
        self.register_tool(ToolDefinition(
            name="analyze_network_traffic",
            description="Analyze network traffic data for anomalies, suspicious patterns, and potential threats. Can detect port scanning, data exfiltration, C2 communication, and more.",
            parameters={
                "type": "object",
                "properties": {
                    "traffic_data": {
                        "type": "string",
                        "description": "Network traffic data to analyze (PCAP summary, NetFlow, or log format)",
                    },
                    "analysis_type": {
                        "type": "string",
                        "enum": ["full", "anomaly", "signature", "behavioral"],
                        "description": "Type of analysis to perform",
                    },
                    "time_window": {
                        "type": "string",
                        "description": "Time window for analysis (e.g., '1h', '24h', '7d')",
                    },
                },
                "required": ["traffic_data"],
            },
            handler=analyze_network_traffic,
        ))
        
        # Log Analysis Tool
        self.register_tool(ToolDefinition(
            name="analyze_logs",
            description="Parse and analyze security logs to identify suspicious activities, failed authentications, privilege escalation attempts, and other security events.",
            parameters={
                "type": "object",
                "properties": {
                    "log_content": {
                        "type": "string",
                        "description": "Log content to analyze",
                    },
                    "log_type": {
                        "type": "string",
                        "enum": ["syslog", "auth", "web", "firewall", "windows_event", "generic"],
                        "description": "Type of log being analyzed",
                    },
                    "focus_areas": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Specific areas to focus on (e.g., 'authentication', 'privilege_escalation')",
                    },
                },
                "required": ["log_content"],
            },
            handler=analyze_logs,
        ))
        
        # IOC Detection Tool
        self.register_tool(ToolDefinition(
            name="detect_ioc",
            description="Scan provided data for known Indicators of Compromise including malicious IPs, domains, file hashes, and patterns associated with known threats.",
            parameters={
                "type": "object",
                "properties": {
                    "data": {
                        "type": "string",
                        "description": "Data to scan for IOCs",
                    },
                    "ioc_types": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Types of IOCs to look for: 'ip', 'domain', 'hash', 'url', 'email', 'all'",
                    },
                    "threat_feeds": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Specific threat feeds to check against",
                    },
                },
                "required": ["data"],
            },
            handler=detect_ioc,
        ))
        
        # Event Correlation Tool
        self.register_tool(ToolDefinition(
            name="correlate_events",
            description="Cross-correlate security events from multiple sources to identify attack patterns, campaigns, or coordinated activities.",
            parameters={
                "type": "object",
                "properties": {
                    "events": {
                        "type": "array",
                        "items": {"type": "object"},
                        "description": "List of events to correlate",
                    },
                    "correlation_rules": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Specific correlation rules to apply",
                    },
                    "time_window": {
                        "type": "string",
                        "description": "Time window for correlation",
                    },
                },
                "required": ["events"],
            },
            handler=correlate_events,
        ))
    
    async def process(self, user_input: str) -> AgentResponse:
        """
        Process a threat detection request.
        
        Args:
            user_input: The security analysis request.
            
        Returns:
            AgentResponse: Analysis results and recommendations.
        """
        self.logger.info(f"Processing threat detection request")
        return await self.run_agent_loop(user_input)
    
    async def monitor_log_stream(self, source: str):
        """
        Monitor a log stream for threats in real-time.
        
        Args:
            source: Path to the log file to monitor.
            
        Yields:
            AgentResponse: Analysis results for detected threats.
        """
        import asyncio
        import aiofiles
        import os
        
        self.status = AgentStatus.RUNNING
        self.logger.info(f"Starting real-time monitoring of {source}")
        
        if not os.path.exists(source):
            self.status = AgentStatus.IDLE
            raise FileNotFoundError(f"Log source not found: {source}")
            
        buffer = []
        BATCH_SIZE = 10
        TIMEOUT = 30  # seconds
        last_analysis_time = asyncio.get_event_loop().time()
        
        try:
            async with aiofiles.open(source, mode='r') as f:
                # Move to the end of the file
                await f.seek(0, 2)
                
                while self.status == AgentStatus.RUNNING:
                    line = await f.readline()
                    config_pol_interval = getattr(self.threat_config, 'polling_interval', 1.0)
                    
                    if line:
                        buffer.append(line.strip())
                    else:
                        await asyncio.sleep(config_pol_interval)
                        
                    current_time = asyncio.get_event_loop().time()
                    time_elapsed = current_time - last_analysis_time
                    
                    # Analyze if buffer is full or timeout reached (and buffer not empty)
                    if (len(buffer) >= BATCH_SIZE) or (time_elapsed >= TIMEOUT and buffer):
                        logs_to_analyze = "\n".join(buffer)
                        buffer = []
                        last_analysis_time = current_time
                        
                        # Only analyze if there's actual content
                        if logs_to_analyze.strip():
                            self.logger.info(f"Analyzing batch of {len(logs_to_analyze.splitlines())} logs")
                            
                            prompt = f"""
                            Analyze the following Real-Time Log Stream batch for immediate threats:
                            
                            {logs_to_analyze}
                            
                            Identify any suspicious activity, anomalies, or IOCs.
                            If benign, simply state "No threats detected."
                            If suspicious, provide severity, type, and immediate recommendation.
                            """
                            
                            # We use process() but suppress standard logging if needed
                            # Here we just await it.
                            response = await self.process(prompt)
                            yield response
        finally:
            self.status = AgentStatus.IDLE
