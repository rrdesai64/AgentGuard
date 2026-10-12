from enum import Enum
from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field
import time

class TrustLevel(str, Enum):
    SYSTEM_CORE = "SYSTEM_CORE"
    AUTHENTICATED_USER = "AUTHENTICATED_USER"
    EXTERNAL_UNTRUSTED = "EXTERNAL_UNTRUSTED"

class InterceptStatus(str, Enum):
    ALLOWED = "ALLOWED"
    BLOCKED = "BLOCKED"

class EnforcementRing(str, Enum):
    RING1_MCP = "RING1_MCP"
    RING2_OS = "RING2_OS"

class IngestSource(BaseModel):
    source_id: str
    trust_level: TrustLevel
    content_summary: str
    timestamp: float = Field(default_factory=time.time)

class ToolCallRequest(BaseModel):
    session_id: str
    user_initial_intent: str
    tool_name: str
    parameters: Dict[str, Any]

class InterceptDecision(BaseModel):
    status: InterceptStatus
    ring: EnforcementRing
    reason: str
    latency_ms: float
    metadata: Dict[str, Any] = Field(default_factory=dict)

class SyscallAlert(BaseModel):
    pid: int
    syscall: str
    target: str
    action_taken: str