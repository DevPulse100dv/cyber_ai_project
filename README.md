# Agentic Cybersecurity System

An AI-powered multi-agent cybersecurity platform that automates threat detection, incident response, and vulnerability management using large language models.

![Python](https://img.shields.io/badge/Python-3.11+-blue.svg)
![License](https://img.shields.io/badge/License-MIT-green.svg)

## Overview

This system leverages AI agents to perform complex security operations autonomously. Each agent specializes in a specific domain and can work independently or coordinate with other agents for comprehensive security coverage.

### Key Features

- **Multi-Agent Architecture** - Three specialized agents working in coordination
- **14 Security Tools** - Purpose-built tools for various security operations
- **BYOK (Bring Your Own Key)** - Works with Groq (default), OpenAI, or Anthropic APIs
- **CLI Interface** - Easy-to-use command-line interface
- **Interactive Mode** - Conversational interface for iterative analysis and data input
- **Extensible Design** - Add new agents and tools easily

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Agent Orchestrator                        │
│    (Coordinates agents, manages workflows, knowledge base)   │
└───────────────────────────┬─────────────────────────────────┘
                            │
        ┌───────────────────┼───────────────────┐
        │                   │                   │
        ▼                   ▼                   ▼
┌───────────────┐   ┌───────────────┐   ┌───────────────┐
│    Threat     │   │   Incident    │   │ Vulnerability │
│   Detection   │   │   Response    │   │  Management   │
│     Agent     │   │     Agent     │   │     Agent     │
├───────────────┤   ├───────────────┤   ├───────────────┤
│ • Network     │   │ • Triage      │   │ • Scanner     │
│   Analysis    │   │ • Playbooks   │   │ • Risk Score  │
│ • Log Analysis│   │ • Containment │   │ • Remediation │
│ • IOC Detect  │   │ • Evidence    │   │ • Verify Patch│
│ • Correlation │   │ • Reporting   │   │ • Reporting   │
└───────────────┘   └───────────────┘   └───────────────┘
```

---

## Installation

### Prerequisites

- Python 3.11 or higher
- pip package manager
- **GitHub Copilot CLI** - Required for the SDK to communicate with LLM providers
  - Install via: [Copilot CLI installation guide](https://docs.github.com/en/copilot/how-tos/set-up/install-copilot-cli)
  - Verify installation: `copilot --version`
  - Follow steps to use copilot cli: [How to use Copilot CLI](https://docs.github.com/en/copilot/how-tos/use-copilot-cli)

### Quick Install

```bash
# Clone the repository
git clone https://github.com/yourusername/agentic-cyber-security.git
cd agentic-cyber-security

# Create and activate virtual environment
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Install in development mode
pip install -e .

# Copy and configure environment variables
cp .env.example .env
```

> **Note**: Always activate the virtual environment (`source .venv/bin/activate`) before running commands.

### Configuration

Edit `.env` and add your API key:

```bash
# For Groq (default)
GROQ_API_KEY=gsk-your-groq-key-here

# OR for OpenAI
# OPENAI_API_KEY=sk-your-openai-key-here

# OR for Anthropic
# ANTHROPIC_API_KEY=sk-ant-your-anthropic-key-here
```

**Optional settings in `.env`:**
```bash
LOG_LEVEL=INFO
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/xxx
```

---

## Quick Start

### List Available Agents

```bash
cyberagent agents
```

> **Note**: All CLI commands start an interactive session. You can provide additional context, logs, or file paths when prompted by the agent. To exit the session, type `exit` or `quit`.

### Analyze Security Data

```bash
# Threat analysis
cyberagent analyze "Suspicious login from IP 192.168.1.100 at 3am" -a threat

# Incident analysis
cyberagent analyze "User reported ransomware popup" -a incident

# Vulnerability analysis
cyberagent analyze "CVE-2024-21762 found on firewall" -a vuln
```

### Run Vulnerability Scan

```bash
# Quick scan
cyberagent scan 192.168.1.0/24 -t quick

# Full scan
cyberagent scan web-server-01 -t full

# Web application scan
cyberagent scan app.example.com -t web_app
```

### Triage an Incident

```bash
cyberagent triage "Multiple failed SSH attempts from external IPs" -s high
```

### Autonomous Monitoring

Continuously monitor a log file for threats.

```bash
cyberagent monitor --source /var/log/auth.log
```

### Run Orchestrated Workflow

```bash
# Multi-agent threat analysis
cyberagent orchestrate threat_analysis -t "Analyze suspicious network activity"

# Vulnerability scanning workflow
cyberagent orchestrate vuln_scan -t "Production servers"
```

---

## Agents & Tools

### 1. Threat Detection Agent

Identifies and analyzes security threats across your infrastructure.

| Tool | Description |
|------|-------------|
| `analyze_network_traffic` | Detects anomalies, C2 communication, port scans, and malicious IPs |
| `analyze_logs` | Parses auth/syslog/web logs for brute force, privilege escalation |
| `detect_ioc` | Scans for known malicious IPs, domains, hashes, URLs, and emails |
| `correlate_events` | Links related events to identify multi-stage attack patterns |

**Example:**
```python
from src.agents import ThreatDetectionAgent
from src.config import load_config

config = load_config()
agent = ThreatDetectionAgent(config)

response = await agent.process(
    "Analyze these logs for suspicious activity: [log data here]"
)
print(response.content)
```

---

### 2. Incident Response Agent

Automates incident handling from triage to remediation.

| Tool | Description |
|------|-------------|
| `triage_incident` | Classifies severity, assigns priority, calculates SLA |
| `execute_playbook` | Runs predefined response playbooks (ransomware, phishing, etc.) |
| `contain_threat` | Network isolation, account disable, firewall blocks |
| `collect_evidence` | Forensic collection (memory, disk, logs, network) |
| `generate_report` | Creates executive, technical, or compliance reports |

**Available Playbooks:**
- `ransomware_response`
- `phishing_response`
- `malware_response`
- `unauthorized_access`
- `data_breach`

**Example:**
```python
from src.agents import IncidentResponseAgent

agent = IncidentResponseAgent(config)
response = await agent.handle_alert({
    "type": "ransomware",
    "severity": "critical",
    "description": "Encrypted files detected on workstation",
    "indicators": ["evil.exe", "192.168.1.50"]
})
```

---

### 3. Vulnerability Management Agent

Coordinates vulnerability scanning, prioritization, and remediation.

| Tool | Description |
|------|-------------|
| `scan_vulnerabilities` | Runs CVE-based vulnerability scans |
| `prioritize_risk` | CVSS + threat intel + asset context scoring |
| `recommend_remediation` | Patch guidance, workarounds, effort estimation |
| `verify_patch` | Confirms remediation was successful |
| `generate_vuln_report` | Executive, technical, compliance, or trending reports |

**Risk Prioritization Factors:**
- CVSS base score
- Exploit availability (public PoC)
- Active exploitation in the wild
- Asset criticality (critical/high/medium/low)
- Network exposure (internet-facing vs internal)

**Example:**
```python
from src.agents import VulnerabilityManagementAgent

agent = VulnerabilityManagementAgent(config)
response = await agent.run_scheduled_scan(
    targets=["192.168.1.0/24", "10.0.0.0/8"]
)
```

---

## Configuration

### Main Config File: `config/default.yaml`

```yaml
general:
  log_level: INFO
  max_retries: 3

copilot:
  byok_provider: groq           # Options: groq, openai, anthropic, azure
  model: llama-3.3-70b-versatile  # Groq model (auto-mapped if using gpt-4)
  temperature: 0.7
  max_tokens: 4096

threat_detection:
  enabled: true
  alert_threshold: high

incident_response:
  enabled: true
  auto_contain: false       # Set to true for automatic containment

vulnerability_management:
  enabled: true
  scan_schedule: "0 2 * * *"  # Daily at 2 AM
  risk_thresholds:
    critical: 9.0
    high: 7.0
    medium: 4.0

orchestration:
  max_concurrent_agents: 3
  default_timeout_seconds: 300
```

---

### Using Ollama (Local LLM)

1.  **Install Ollama**: Download and install from [ollama.com](https://ollama.com/).
2.  **Pull a Model**: Run `ollama pull llama3` (or your preferred model).
3.  **Configure**: Update `config/default.yaml` to use the `ollama` provider:
    ```yaml
    copilot:
      byok_provider: ollama
      model: llama3
      # base_url: http://localhost:11434/v1  # Default, change if running remotely
    ```
4.  **Run**: Ensure Ollama is running (`ollama serve`), then use `cyberagent` commands as usual.

---

## Project Structure

```
agentic-cyber-security/
├── src/
│   ├── __init__.py
│   ├── config.py                 # Configuration management
│   ├── cli.py                    # Command-line interface
│   └── agents/
│       ├── __init__.py
│       ├── base.py               # Base agent class
│       ├── orchestrator.py       # Multi-agent orchestrator
│       ├── threat_detection/
│       │   ├── agent.py
│       │   └── tools/
│       │       ├── analyze_network_traffic.py
│       │       ├── analyze_logs.py
│       │       ├── detect_ioc.py
│       │       └── correlate_events.py
│       ├── incident_response/
│       │   ├── agent.py
│       │   └── tools/
│       │       ├── triage_incident.py
│       │       ├── execute_playbook.py
│       │       ├── contain_threat.py
│       │       ├── collect_evidence.py
│       │       └── generate_report.py
│       └── vulnerability_management/
│           ├── agent.py
│           └── tools/
│               ├── scan_vulnerabilities.py
│               ├── prioritize_risk.py
│               ├── recommend_remediation.py
│               ├── verify_patch.py
│               └── generate_vuln_report.py
├── config/
│   └── default.yaml
├── tests/
├── .env.example
├── pyproject.toml
└── README.md
```

---

## Programmatic Usage

### Basic Agent Usage

```python
import asyncio
from src.config import load_config
from src.agents import (
    ThreatDetectionAgent,
    IncidentResponseAgent,
    VulnerabilityManagementAgent,
)

async def main():
    config = load_config()
    
    # Initialize agents
    threat_agent = ThreatDetectionAgent(config)
    ir_agent = IncidentResponseAgent(config)
    vuln_agent = VulnerabilityManagementAgent(config)
    
    # Run threat analysis
    result = await threat_agent.process(
        "Analyze network traffic for C2 communication patterns"
    )
    print(result.content)

asyncio.run(main())
```

### Using the Orchestrator

```python
from src.agents import AgentOrchestrator

async def orchestrated_workflow():
    config = load_config()
    orchestrator = AgentOrchestrator(config)
    
    # Register agents
    orchestrator.register_agent("threat", ThreatDetectionAgent(config))
    orchestrator.register_agent("incident", IncidentResponseAgent(config))
    orchestrator.register_agent("vuln", VulnerabilityManagementAgent(config))
    
    # Run coordinated analysis
    result = await orchestrator.analyze_threat(
        "Suspicious outbound connections detected from server-01"
    )
    print(result)

asyncio.run(orchestrated_workflow())
```

### Direct Tool Usage

```python
from src.agents.threat_detection.tools import analyze_logs, detect_ioc
from src.agents.vulnerability_management.tools import scan_vulnerabilities

async def use_tools_directly():
    # Analyze logs
    log_result = await analyze_logs(
        log_content="May 15 10:23:45 server sshd: Failed password for root",
        log_type="auth"
    )
    print(f"Found {len(log_result['findings'])} suspicious patterns")
    
    # Detect IOCs
    ioc_result = await detect_ioc(
        data="Check this domain: malware.evil.com and IP: 45.33.32.156"
    )
    print(f"Detected {ioc_result['summary']['total_detections']} IOCs")
    
    # Scan for vulnerabilities
    scan_result = await scan_vulnerabilities(
        target="192.168.1.100",
        scan_type="quick"
    )
    print(f"Found {len(scan_result['vulnerabilities'])} vulnerabilities")

asyncio.run(use_tools_directly())
```

---

## Testing

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=src

# Run specific test file
pytest tests/test_threat_detection.py -v
```

---

## Security Considerations

- **API Keys**: Never commit API keys. Use environment variables.
- **Containment Actions**: Set `auto_contain: false` in production until tested.
- **Evidence Handling**: Collected evidence should be stored securely.
- **Audit Logging**: All agent actions are logged for accountability.

---

## Roadmap

- [ ] Real SIEM/SOAR integrations (Splunk, QRadar, Sentinel)
- [ ] Slack/Teams notification integration
- [ ] Web dashboard UI
- [ ] Custom playbook builder
- [ ] Threat intelligence feed integrations
- [ ] Container/Kubernetes security agent

---

## License

MIT License - See [LICENSE](LICENSE) for details.

---

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit changes (`git commit -m 'Add amazing feature'`)
4. Push to branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

---

## Support

- **Issues**: [GitHub Issues](https://github.com/DevPulse100dv/cyber_ai_project/issues)
- **Discussions**: [GitHub Discussions](https://github.com/DevPulse100dv/cyber_ai_project/discussions)

---

Built with love for the cybersecurity community
