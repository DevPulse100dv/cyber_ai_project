"""
Cybersecurity Agents CLI.

Command-line interface for running and managing security agents.
"""

import asyncio
from typing import Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.markdown import Markdown
from rich.prompt import Prompt

from src.config import load_config, AppConfig
from src.agents import (
    AgentOrchestrator,
    ThreatDetectionAgent,
    IncidentResponseAgent,
    VulnerabilityManagementAgent,
)

app = typer.Typer(
    name="cyberagent",
    help="Agentic Cybersecurity System - AI-powered security operations",
    add_completion=False,
)

console = Console()


def get_config(config_path: Optional[str] = None) -> AppConfig:
    """Load configuration."""
    if config_path:
        return load_config(config_path)
    return load_config()


async def run_interactive_session(
    agent_instance,
    initial_response=None,
    title_suffix: str = "Results",
    border_style: str = "green",
):
    """Run an interactive session with an agent."""
    
    # Display initial response if provided
    if initial_response:
        content = ""
        # Handle dict response (from orchestrator)
        if isinstance(initial_response, dict):
            content = initial_response.get("content", str(initial_response))
            tool_calls = initial_response.get("tool_calls", [])
            error = initial_response.get("error", False)
        # Handle AgentResponse object
        else:
            content = getattr(initial_response, "content", str(initial_response))
            tool_calls = getattr(initial_response, "tool_calls", [])
            error = getattr(initial_response, "error", False)
            
        console.print(Panel(
            Markdown(content),
            title=f"{agent_instance.name} {title_suffix}",
            border_style="red" if error else border_style,
        ))
        
        # Display tool usage if any
        if tool_calls:
            table = Table(title="Tools Used")
            table.add_column("Tool", style="cyan")
            table.add_column("Status", style="green")
            for tool in tool_calls:
                name = tool.get("name", "Unknown") if isinstance(tool, dict) else tool.name
                table.add_row(name, "✓ Completed")
            console.print(table)

    # Interactive Loop
    while True:
        user_input = Prompt.ask("\n[bold yellow]Provide input (or type 'exit' to finish)[/bold yellow]")
        
        if user_input.lower() in ("exit", "quit", "q"):
            break
            
        with console.status(f"[bold blue]Processing with {agent_instance.name}..."):
            try:
                response = await agent_instance.process(user_input)
                
                console.print(Panel(
                    Markdown(response.content),
                    title=f"{agent_instance.name} Results",
                    border_style="green" if not response.error else "red",
                ))
                
                if response.tool_calls:
                    table = Table(title="Tools Used")
                    table.add_column("Tool", style="cyan")
                    table.add_column("Status", style="green")
                    for tool in response.tool_calls:
                         # Handle possibly different tool formats
                         name = tool.get("name", "Unknown") if isinstance(tool, dict) else getattr(tool, "name", "Unknown")
                         table.add_row(name, "✓ Completed")
                    console.print(table)
                    
            except Exception as e:
                console.print(f"[red]Error processing input: {e}[/red]")


@app.command()
def analyze(
    input_data: str = typer.Argument(..., help="Data to analyze or path to file"),
    agent: str = typer.Option("threat", "--agent", "-a", help="Agent to use: threat, incident, vuln"),
    config_path: Optional[str] = typer.Option(None, "--config", "-c", help="Path to config file"),
):
    """
    Analyze data using a security agent.
    
    Examples:
        cyberagent analyze "Suspicious login from IP 192.168.1.100" -a threat
        cyberagent analyze incident_data.json -a incident
    """
    config = get_config(config_path)
    
    async def run_analysis():
        agent_map = {
            "threat": ThreatDetectionAgent,
            "incident": IncidentResponseAgent,
            "vuln": VulnerabilityManagementAgent,
        }
        
        if agent not in agent_map:
            console.print(f"[red]Unknown agent: {agent}[/red]")
            console.print(f"Available agents: {', '.join(agent_map.keys())}")
            raise typer.Exit(1)
        
        agent_cls = agent_map[agent]
        agent_instance = agent_cls(config)
        
        with console.status(f"[bold green]Running {agent} analysis..."):
            initial_response = await agent_instance.process(input_data)
        
        await run_interactive_session(agent_instance, initial_response)
    
    asyncio.run(run_analysis())


@app.command()
def scan(
    target: str = typer.Argument(..., help="Scan target (IP, hostname, CIDR, or 'all')"),
    scan_type: str = typer.Option("full", "--type", "-t", help="Scan type: quick, full, compliance, web_app"),
    config_path: Optional[str] = typer.Option(None, "--config", "-c", help="Path to config file"),
):
    """
    Run a vulnerability scan on specified targets.
    
    Examples:
        cyberagent scan 192.168.1.0/24 -t quick
        cyberagent scan web-server-01 -t web_app
    """
    config = get_config(config_path)
    
    async def run_scan():
        agent = VulnerabilityManagementAgent(config)
        
        with console.status(f"[bold green]Scanning {target}..."):
            initial_response = await agent.process(
                f"Run a {scan_type} vulnerability scan on {target} and provide remediation priorities"
            )
        
        await run_interactive_session(agent, initial_response, title_suffix="Scan Results", border_style="yellow")
    
    asyncio.run(run_scan())


@app.command()
def triage(
    description: str = typer.Argument(..., help="Incident description"),
    severity: str = typer.Option("unknown", "--severity", "-s", help="Initial severity assessment"),
    config_path: Optional[str] = typer.Option(None, "--config", "-c", help="Path to config file"),
):
    """
    Triage a security incident.
    
    Examples:
        cyberagent triage "Multiple failed login attempts from external IP" -s high
        cyberagent triage "Suspicious process detected on workstation"
    """
    config = get_config(config_path)
    
    async def run_triage():
        agent = IncidentResponseAgent(config)
        
        with console.status("[bold red]Triaging incident..."):
            initial_response = await agent.process(
                f"Triage the following incident (initial severity: {severity}): {description}"
            )
        
        await run_interactive_session(agent, initial_response, title_suffix="Triage Results", border_style="red")
    
    asyncio.run(run_triage())


@app.command()
def orchestrate(
    workflow: str = typer.Argument(..., help="Workflow to run: threat_analysis, incident_response, vuln_scan"),
    target: str = typer.Option("", "--target", "-t", help="Target for the workflow"),
    config_path: Optional[str] = typer.Option(None, "--config", "-c", help="Path to config file"),
):
    """
    Run an orchestrated multi-agent workflow.
    
    Examples:
        cyberagent orchestrate threat_analysis -t "Analyze recent alerts"
        cyberagent orchestrate vuln_scan -t "Production servers"
    """
    config = get_config(config_path)
    
    async def run_workflow():
        orchestrator = AgentOrchestrator(config)
        
        # Register all agents
        orchestrator.register_agent("threat_detection", ThreatDetectionAgent(config))
        orchestrator.register_agent("incident_response", IncidentResponseAgent(config))
        orchestrator.register_agent("vulnerability_management", VulnerabilityManagementAgent(config))
        
        # Determine the agent for this workflow
        workflow_agent_map = {
            "threat_analysis": "threat_detection",
            "incident_response": "incident_response",
            "vuln_scan": "vulnerability_management",
        }
        agent_name = workflow_agent_map.get(workflow)
        
        # Initial execution
        with console.status(f"[bold blue]Running {workflow} workflow..."):
            if workflow == "threat_analysis":
                result = await orchestrator.analyze_threat(target or "Analyze all recent security events")
            elif workflow == "incident_response":
                result = await orchestrator.triage_incident(target or "General security incident")
            elif workflow == "vuln_scan":
                result = await orchestrator.scan_vulnerabilities(target or "all")
            else:
                console.print(f"[red]Unknown workflow: {workflow}[/red]")
                raise typer.Exit(1)
        
        agent = orchestrator.get_agent(agent_name)
        if not agent:
             console.print(f"[red]Agent {agent_name} not available for interaction[/red]")
             # Display result anyway
             content = result.get("content", str(result)) if isinstance(result, dict) else str(result)
             console.print(Panel(Markdown(content), title=f"Workflow: {workflow}", border_style="blue"))
             return
             
        await run_interactive_session(agent, result, title_suffix=f"({workflow})", border_style="blue")
    
    asyncio.run(run_workflow())


@app.command()
def agents():
    """List available agents and their capabilities."""
    table = Table(title="Available Security Agents")
    table.add_column("Agent", style="cyan", no_wrap=True)
    table.add_column("Description", style="white")
    table.add_column("Tools", style="green")
    
    table.add_row(
        "Threat Detection",
        "Identifies and analyzes security threats",
        "analyze_network_traffic, analyze_logs, detect_ioc, correlate_events",
    )
    table.add_row(
        "Incident Response",
        "Handles security incidents and response",
        "triage_incident, execute_playbook, contain_threat, collect_evidence, generate_report",
    )
    table.add_row(
        "Vulnerability Management",
        "Scans and manages vulnerabilities",
        "scan_vulnerabilities, prioritize_risk, recommend_remediation, verify_patch, generate_vuln_report",
    )
    
    console.print(table)


@app.command()
def version():
    """Show version information."""
    from src import __version__
    console.print(f"Cyberagent version: [bold]{__version__}[/bold]")


def main():
    """Main entry point."""
    app()


@app.command()
def monitor(
    source: str = typer.Option(..., "--source", "-s", help="Path to log file to monitor"),
    config_path: Optional[str] = typer.Option(None, "--config", "-c", help="Path to config file"),
):
    """
    Monitor a log file for threats in real-time.
    
    Examples:
        cyberagent monitor --source /var/log/auth.log
    """
    config = get_config(config_path)
    
    async def run_monitor():
        agent = ThreatDetectionAgent(config)
        import os
        if not os.path.exists(source):
            console.print(f"[red]Log file not found: {source}[/red]")
            return

        console.print(Panel(
            f"Monitoring [bold]{source}[/bold] for threats...",
            title="Autonomous Threat Monitor",
            border_style="blue",
        ))
        
        try:
            async for response in agent.monitor_log_stream(source):
                # Format timestamp
                from datetime import datetime
                timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                
                # Check provided content severity/alert status (simple heuristic for border color)
                # Ideally response.metadata would have severity
                border_style = "green"
                if "critical" in response.content.lower():
                    border_style = "red"
                elif "high" in response.content.lower():
                    border_style = "orange1"
                elif "medium" in response.content.lower():
                    border_style = "yellow"
                elif "No threats detected" in response.content:
                    border_style = "green"
                    
                console.print(Panel(
                    Markdown(response.content),
                    title=f"Alert @ {timestamp}",
                    border_style=border_style,
                ))
        except KeyboardInterrupt:
            console.print("\n[yellow]Monitoring stopped.[/yellow]")
        except Exception as e:
            console.print(f"[red]Monitoring error: {e}[/red]")

    try:
        asyncio.run(run_monitor())
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
