"""
Configuration management for Agentic Cyber Security System.

Loads configuration from YAML files and environment variables.
"""

import os
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field
from pydantic_settings import BaseSettings


# Provider base URLs for BYOK configuration
PROVIDER_BASE_URLS: dict[str, str] = {
    "openai": "https://api.openai.com/v1",
    "groq": "https://api.groq.com/openai/v1",
    "anthropic": "https://api.anthropic.com",
    "azure": "",  # Azure requires custom endpoint
    "ollama": "http://localhost:11434/v1",
}


class CopilotConfig(BaseModel):
    """GitHub Copilot SDK configuration."""
    auth_mode: str = "byok"
    byok_provider: str = "groq"  # openai, anthropic, groq, azure, ollama
    base_url: str = ""  # Provider-specific base URL (auto-set from PROVIDER_BASE_URLS if empty)
    model: str = "llama-3.3-70b-versatile"
    temperature: float = 0.7
    max_tokens: int = 4096


class GeneralConfig(BaseModel):
    log_level: str = "INFO"
    max_retries: int = 3

class ThreatConfig(BaseModel):
    enabled: bool = True
    alert_threshold: str = "high"

class IncidentConfig(BaseModel):
    enabled: bool = True
    auto_contain: bool = False

class AppConfig(BaseModel):
    general: GeneralConfig = Field(default_factory=GeneralConfig)
    copilot: CopilotConfig = Field(default_factory=CopilotConfig)
    threat_detection: ThreatConfig = Field(default_factory=ThreatConfig)
    incident_response: IncidentConfig = Field(default_factory=IncidentConfig)

class EnvSettings(BaseSettings):
    openai_api_key: str = ""
    anthropic_api_key: str = ""
    groq_api_key: str = ""
    azure_openai_api_key: str = ""
    telegram_bot_token: str = ""

    class Config:
        env_file = ".env"
        extra = "ignore"

def load_config(config_path: str = "config/default.yaml") -> AppConfig:
    return AppConfig()

def get_api_key(config: AppConfig, env_settings: EnvSettings | None = None) -> str:
    """
    Get the appropriate API key based on configuration.
    
    Args:
        config: Application configuration.
        env_settings: Environment settings (loaded if not provided).
        
    Returns:
        str: API key for the configured provider.
        
    Raises:
        ValueError: If no API key is found for the configured provider.
    """
    if env_settings is None:
        env_settings = EnvSettings()
    
    provider = config.copilot.byok_provider.lower()
    
    key_mapping = {
        "openai": env_settings.openai_api_key,
        "anthropic": env_settings.anthropic_api_key,
        "groq": env_settings.groq_api_key,
        "azure": env_settings.azure_openai_api_key,
        "ollama": "ollama",  # Ollama usually doesn't require a key, but SDK expects non-empty string
    }
    
    api_key = key_mapping.get(provider, "")
    
    if not api_key:
        raise ValueError(
            f"No API key found for provider '{provider}'. "
            f"Set the corresponding environment variable."
        )
    
    return api_key
