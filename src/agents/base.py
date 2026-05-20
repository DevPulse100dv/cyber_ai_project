"""
Base Agent class for the Agentic Cyber Security System.

Provides common functionality for all security agents including
LLM client management via GitHub Copilot SDK, tool registration, and message handling.
"""

import json
import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Callable, Awaitable
from uuid import uuid4

from pydantic import BaseModel, Field

import os
from groq import AsyncGroq

# Copilot objects mocked for compatibility
class Tool: pass
class ToolInvocation: pass
def define_tool(): pass
class CopilotClient: pass
class CopilotSession: pass
class SessionConfig: pass
class ProviderConfig: pass

from src.config import AppConfig, get_api_key, EnvSettings, PROVIDER_BASE_URLS


class AgentStatus(Enum):
    """Agent operational status."""
    IDLE = "idle"
    RUNNING = "running"
    ERROR = "error"
    STOPPED = "stopped"


@dataclass
class ToolDefinition:
    """Definition of a tool that can be used by an agent."""
    name: str
    description: str
    parameters: dict[str, Any]
    handler: Callable[..., Awaitable[Any]]
    
    def to_openai_format(self) -> dict[str, Any]:
        """Convert to OpenAI function calling format."""
        return {
            "type": "function",
            "function": {
                "name": self.name,
                "description": self.description,
                "parameters": self.parameters,
            }
        }
    
    def to_copilot_tool(self) -> Tool:
        """Convert to Copilot SDK Tool format."""
        # Create a sync wrapper for the async handler
        async_handler = self.handler
        
        def sync_handler(params: dict, invocation: ToolInvocation) -> str:
            """Synchronous wrapper for tool handler."""
            import asyncio
            try:
                # Try to get the running loop
                loop = asyncio.get_running_loop()
                # Create a new task in the running loop
                future = asyncio.ensure_future(async_handler(**params))
                return str(future.result())
            except RuntimeError:
                # No running loop, create a new one
                result = asyncio.run(async_handler(**params))
                return str(result) if result else ""
        
        return Tool(
            name=self.name,
            description=self.description,
            handler=sync_handler,
            parameters=self.parameters,
        )


@dataclass
class Message:
    """A message in the conversation."""
    role: str  # 'system', 'user', 'assistant', 'tool'
    content: str
    tool_call_id: str | None = None
    tool_calls: list[dict[str, Any]] | None = None
    timestamp: datetime = field(default_factory=datetime.now)


@dataclass
class AgentResponse:
    """Response from an agent."""
    agent_id: str
    agent_name: str
    content: str
    tool_calls: list[dict[str, Any]] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=datetime.now)
    error: bool = False
    
    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "agent_id": self.agent_id,
            "agent_name": self.agent_name,
            "content": self.content,
            "tool_calls": self.tool_calls,
            "metadata": self.metadata,
            "timestamp": self.timestamp.isoformat(),
            "error": self.error,
        }


class BaseAgent(ABC):
    """
    Abstract base class for all security agents.
    
    Provides common functionality including:
    - GitHub Copilot SDK client initialization with BYOK support
    - Tool registration and execution
    - Conversation history management
    - Logging and error handling
    """
    
    def __init__(
        self,
        config: AppConfig,
        agent_name: str,
        system_prompt: str,
    ):
        """
        Initialize the base agent.
        
        Args:
            config: Application configuration.
            agent_name: Human-readable name for this agent.
            system_prompt: System prompt defining agent behavior.
        """
        self.config = config
        self.agent_name = agent_name
        self.name = agent_name  # Alias for CLI compatibility
        self.agent_id = str(uuid4())
        self.system_prompt = system_prompt
        self.status = AgentStatus.IDLE
        
        # Initialize logging
        self.logger = logging.getLogger(f"agent.{agent_name.lower().replace(' ', '_')}")
        
        # Initialize tools and conversation
        self.tools: dict[str, ToolDefinition] = {}
        self.conversation_history: list[Message] = []
        
        # Environment settings
        self._env_settings = EnvSettings()
        
        # Copilot SDK client and session (lazy initialization)
        self._copilot_client: CopilotClient | None = None
        self._copilot_session: CopilotSession | None = None
        
        # Register agent-specific tools
        self._register_tools()
        
        self.logger.info(f"Agent '{agent_name}' initialized with ID: {self.agent_id}")
    
    def _get_provider_config(self) -> ProviderConfig:
        """
        Create provider configuration for the Copilot SDK.
        
        Returns:
            ProviderConfig: Configuration for the BYOK provider.
        """
        provider = self.config.copilot.byok_provider.lower()
        api_key = get_api_key(self.config, self._env_settings)
        
        # Get base URL from config or default mapping
        base_url = self.config.copilot.base_url
        if not base_url:
            base_url = PROVIDER_BASE_URLS.get(provider, "")
        
        if not base_url:
            raise ValueError(
                f"No base URL configured for provider '{provider}'. "
                f"Set 'base_url' in config or use a supported provider."
            )
        
        # Map provider to SDK-supported types
        # Groq uses OpenAI-compatible API
        provider_type: str
        if provider in ("openai", "groq", "ollama"):
            provider_type = "openai"
        elif provider == "anthropic":
            provider_type = "anthropic"
        elif provider == "azure":
            provider_type = "azure"
        else:
            raise ValueError(f"Unsupported provider: {provider}")
        
        return ProviderConfig(
            type=provider_type,  # type: ignore
            base_url=base_url,
            api_key=api_key,
        )
    
    def _get_session_config(self) -> SessionConfig:
        """
        Create session configuration for the Copilot SDK.
        
        Returns:
            SessionConfig: Configuration for the session.
        """
        # Convert tools to Copilot SDK format
        copilot_tools = [tool.to_copilot_tool() for tool in self.tools.values()]
        
        return SessionConfig(
            model=self.config.copilot.model,
            provider=self._get_provider_config(),
            tools=copilot_tools if copilot_tools else None,
            system_message={
                "type": "text",
                "content": self.system_prompt,
            },
        )
    
    async def _ensure_client(self) -> CopilotClient:
        """
        Get or create the Copilot SDK client.
        
        Returns:
            CopilotClient: The initialized Copilot client.
        """
        if self._copilot_client is None:
            self._copilot_client = CopilotClient()
            await self._copilot_client.start()
            self.logger.debug("Started Copilot client")
        return self._copilot_client
    
    async def _ensure_session(self) -> CopilotSession:
        """
        Get or create the Copilot session.
        
        Returns:
            CopilotSession: The active Copilot session.
        """
        if self._copilot_session is None:
            client = await self._ensure_client()
            session_config = self._get_session_config()
            self._copilot_session = await client.create_session(session_config)
            self.logger.debug(
                f"Created Copilot session with provider: {self.config.copilot.byok_provider}"
            )
        return self._copilot_session
        return self._copilot_session
    
    @abstractmethod
    def _register_tools(self) -> None:
        """Register tools specific to this agent. Must be implemented by subclasses."""
        pass
    
    @abstractmethod
    async def process(self, user_input: str) -> AgentResponse:
        """
        Process user input and return a response.
        
        Args:
            user_input: The user's input message.
            
        Returns:
            AgentResponse: The agent's response.
        """
        pass
    
    def register_tool(self, tool: ToolDefinition) -> None:
        """
        Register a tool with this agent.
        
        Args:
            tool: The tool definition to register.
        """
        self.tools[tool.name] = tool
        self.logger.debug(f"Registered tool: {tool.name}")
    
    async def _call_llm(
        self,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        """
        Call the LLM API via Groq.
        """
        api_key = get_api_key(self.config, self._env_settings)
        client = AsyncGroq(api_key=api_key)
        
        try:
            # We don't strictly need tool calls for this simple Telegram bot response.
            # Just do a standard chat completion.
            completion = await client.chat.completions.create(
                model=self.config.copilot.model,
                messages=messages,
                temperature=self.config.copilot.temperature,
                max_tokens=self.config.copilot.max_tokens,
            )
            
            content = completion.choices[0].message.content
            
            message: dict[str, Any] = {
                "role": "assistant",
                "content": content,
            }
            
            return {"choices": [{"message": message}]}
            
        except Exception as e:
            self.logger.error(f"LLM call failed: {e}")
            raise
    
    async def execute_tool(self, tool_name: str, arguments: dict[str, Any]) -> Any:
        """
        Execute a registered tool.
        
        Args:
            tool_name: Name of the tool to execute.
            arguments: Arguments to pass to the tool.
            
        Returns:
            The tool's return value.
            
        Raises:
            ValueError: If the tool is not registered.
        """
        if tool_name not in self.tools:
            raise ValueError(f"Tool '{tool_name}' is not registered")
        
        tool = self.tools[tool_name]
        self.logger.info(f"Executing tool: {tool_name}")
        
        try:
            result = await tool.handler(**arguments)
            self.logger.debug(f"Tool '{tool_name}' completed successfully")
            return result
        except Exception as e:
            self.logger.error(f"Tool '{tool_name}' failed: {e}")
            raise
    
    def add_message(self, role: str, content: str, **kwargs: Any) -> None:
        """Add a message to conversation history."""
        self.conversation_history.append(Message(role=role, content=content, **kwargs))
    
    def get_messages_for_api(self) -> list[dict[str, Any]]:
        """Get conversation history in API format."""
        messages = [{"role": "system", "content": self.system_prompt}]
        
        for msg in self.conversation_history:
            message: dict[str, Any] = {"role": msg.role, "content": msg.content}
            if msg.tool_call_id:
                message["tool_call_id"] = msg.tool_call_id
            if msg.tool_calls:
                message["tool_calls"] = msg.tool_calls
            messages.append(message)
        
        return messages
    
    def get_tools_for_api(self) -> list[dict[str, Any]]:
        """Get registered tools in API format."""
        return [tool.to_openai_format() for tool in self.tools.values()]
    
    async def run_agent_loop(self, user_input: str, max_iterations: int = 10) -> AgentResponse:
        """
        Run the agent loop with tool execution.
        
        Args:
            user_input: The user's input.
            max_iterations: Maximum number of tool call iterations.
            
        Returns:
            AgentResponse: The final response.
        """
        self.status = AgentStatus.RUNNING
        self.add_message("user", user_input)
        
        try:
            for iteration in range(max_iterations):
                self.logger.debug(f"Agent loop iteration {iteration + 1}")
                
                # Call LLM via Copilot SDK
                response = await self._call_llm(
                    messages=self.get_messages_for_api(),
                    tools=self.get_tools_for_api() if self.tools else None,
                )
                
                assistant_message = response["choices"][0]["message"]
                content = assistant_message.get("content", "")
                tool_calls = assistant_message.get("tool_calls", [])
                
                # Add assistant message to history
                self.add_message(
                    "assistant",
                    content or "",
                    tool_calls=tool_calls if tool_calls else None,
                )
                
                # If no tool calls, we're done
                if not tool_calls:
                    self.status = AgentStatus.IDLE
                    return AgentResponse(
                        agent_id=self.agent_id,
                        agent_name=self.agent_name,
                        content=content,
                        metadata={"iterations": iteration + 1},
                    )
                
                # Execute tool calls
                for tool_call in tool_calls:
                    tool_name = tool_call["function"]["name"]
                    arguments = json.loads(tool_call["function"]["arguments"])
                    
                    try:
                        result = await self.execute_tool(tool_name, arguments)
                        result_str = json.dumps(result) if not isinstance(result, str) else result
                    except Exception as e:
                        result_str = f"Error: {str(e)}"
                    
                    # Add tool result to history
                    self.add_message(
                        "tool",
                        result_str,
                        tool_call_id=tool_call["id"],
                    )
            
            # Max iterations reached
            self.status = AgentStatus.IDLE
            return AgentResponse(
                agent_id=self.agent_id,
                agent_name=self.agent_name,
                content="Maximum iterations reached. Please try a more specific request.",
                metadata={"iterations": max_iterations, "max_reached": True},
            )
            
        except Exception as e:
            self.status = AgentStatus.ERROR
            self.logger.error(f"Agent loop failed: {e}")
            return AgentResponse(
                agent_id=self.agent_id,
                agent_name=self.agent_name,
                content=f"An error occurred: {str(e)}",
                metadata={"error": str(e)},
                error=True,
            )
    
    async def close(self) -> None:
        """Clean up resources."""
        if self._copilot_session:
            try:
                self._copilot_session.destroy()
            except Exception as e:
                self.logger.warning(f"Error destroying session: {e}")
            self._copilot_session = None
        
        if self._copilot_client:
            try:
                await self._copilot_client.stop()
            except Exception as e:
                self.logger.warning(f"Error stopping client: {e}")
            self._copilot_client = None
        
        self.status = AgentStatus.STOPPED
        self.logger.info(f"Agent '{self.agent_name}' closed")
