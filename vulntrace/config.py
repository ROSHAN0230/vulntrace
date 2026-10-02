"""
VulnTrace Configuration & Credential Management
Loads credentials securely from environment variables or local .env.
Never logs or exposes secret values.
"""

import os
from pathlib import Path
from typing import Optional
from pydantic import BaseModel

class Settings(BaseModel):
    nebius_api_key: Optional[str] = None
    nebius_project_id: Optional[str] = None
    tavily_api_key: Optional[str] = None
    host: str = "127.0.0.1"
    port: int = 8000
    
    @property
    def has_nebius(self) -> bool:
        return bool(self.nebius_api_key and len(self.nebius_api_key) > 10)
        
    @property
    def has_nebius_project(self) -> bool:
        return bool(self.nebius_project_id and len(self.nebius_project_id) > 2)

    @property
    def has_tavily(self) -> bool:
        return bool(self.tavily_api_key and len(self.tavily_api_key) > 5)

def load_settings(base_dir: Optional[Path] = None) -> Settings:
    if base_dir is None:
        base_dir = Path(__file__).resolve().parent.parent
        
    # Check project-level .env
    env_file = base_dir / ".env"
    env_vars = {}
    if env_file.exists():
        for line in env_file.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                env_vars[k.strip()] = v.strip().strip("'\"")
                
    # Environment variables take precedence
    nebius_key = os.environ.get("NEBIUS_API_KEY", env_vars.get("NEBIUS_API_KEY"))
    nebius_proj = os.environ.get("NEBIUS_PROJECT_ID", env_vars.get("NEBIUS_PROJECT_ID"))
    tavily_key = os.environ.get("TAVILY_API_KEY", env_vars.get("TAVILY_API_KEY"))
    host = os.environ.get("VULNTRACE_HOST", env_vars.get("VULNTRACE_HOST", "127.0.0.1"))
    port = int(os.environ.get("VULNTRACE_PORT", env_vars.get("VULNTRACE_PORT", 8000)))
    
    return Settings(
        nebius_api_key=nebius_key,
        nebius_project_id=nebius_proj,
        tavily_api_key=tavily_key,
        host=host,
        port=port
    )

settings = load_settings()
