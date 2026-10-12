import time
import re
import yaml
import numpy as np
from typing import Dict, Any, List
from core.schemas import ToolCallRequest, InterceptDecision, InterceptStatus, EnforcementRing
from core.taint_graph import SessionTaintGraph

class SemanticMCPInterceptor:
    """Layer 7 Interceptor: Evaluates Causal Taint, Parameter Invariants, and Intent Alignment."""
    def __init__(self, policy_path: str):
        with open(policy_path, "r") as f:
            self.policy = yaml.safe_load(f)["policies"]["ring1_mcp"]
        self.sessions: Dict[str, SessionTaintGraph] = {}

    def get_or_create_session(self, session_id: str) -> SessionTaintGraph:
        if session_id not in self.sessions:
            self.sessions[session_id] = SessionTaintGraph(session_id)
        return self.sessions[session_id]

    def _compute_semantic_drift(self, prompt: str, tool_name: str, args: Dict[str, Any]) -> float:
        """
        Fast sub-millisecond intent distance calculation using character-n-gram hashing vectors.
        (Can be swapped with an ONNX/SentenceTransformer embedding runtime without changing the signature).
        """
        def hash_vectorizer(text: str, dim: int = 128) -> np.ndarray:
            vec = np.zeros(dim, dtype=np.float32)
            tokens = re.findall(r"\w+", text.lower())
            for t in tokens:
                idx = hash(t) % dim
                vec[idx] += 1.0
            norm = np.linalg.norm(vec)
            return vec / (norm + 1e-7)

        v1 = hash_vectorizer(prompt)
        payload_str = f"{tool_name} " + " ".join(f"{k}:{v}" for k, v in args.items())
        v2 = hash_vectorizer(payload_str)
        
        # Cosine distance: 1 - cosine_similarity
        similarity = float(np.dot(v1, v2))
        return round(1.0 - max(0.0, similarity), 3)

    def evaluate(self, request: ToolCallRequest) -> InterceptDecision:
        start_time = time.perf_counter()
        session = self.get_or_create_session(request.session_id)

        # Gate 1: Check Causal Taint Policy
        if session.get_taint_status():
            if request.tool_name in self.policy["tainted_forbidden_tools"]:
                latency = (time.perf_counter() - start_time) * 1000.0
                return InterceptDecision(
                    status=InterceptStatus.BLOCKED,
                    ring=EnforcementRing.RING1_MCP,
                    reason=(
                        f"Policy Violation: Session '{request.session_id}' is TAINTED by untrusted external data. "
                        f"State-mutating tool '{request.tool_name}' execution is forbidden."
                    ),
                    latency_ms=round(latency, 2),
                    metadata={"taint_lineage": session.get_lineage()}
                )

        # Gate 2: Parameter Invariant Inspection
        serialized_args = str(request.parameters)
        for pattern in self.policy["suspicious_argument_patterns"]:
            if re.search(pattern, serialized_args):
                latency = (time.perf_counter() - start_time) * 1000.0
                return InterceptDecision(
                    status=InterceptStatus.BLOCKED,
                    ring=EnforcementRing.RING1_MCP,
                    reason=f"Parameter Invariant Breach: Argument payload matches restricted signature: {pattern}",
                    latency_ms=round(latency, 2),
                    metadata={"pattern": pattern}
                )

        # Gate 3: Semantic Intent Alignment Drift
        drift = self._compute_semantic_drift(
            request.user_initial_intent, request.tool_name, request.parameters
        )
        if drift > self.policy["max_semantic_drift_threshold"]:
            latency = (time.perf_counter() - start_time) * 1000.0
            return InterceptDecision(
                status=InterceptStatus.BLOCKED,
                ring=EnforcementRing.RING1_MCP,
                reason=(
                    f"Semantic Drift Anomaly: Intent drift score {drift} exceeds threshold "
                    f"{self.policy['max_semantic_drift_threshold']}. Tool parameters diverge from initial objective."
                ),
                latency_ms=round(latency, 2),
                metadata={"drift_score": drift, "threshold": self.policy["max_semantic_drift_threshold"]}
            )

        latency = (time.perf_counter() - start_time) * 1000.0
        return InterceptDecision(
            status=InterceptStatus.ALLOWED,
            ring=EnforcementRing.RING1_MCP,
            reason="Tool call validated against Ring 1 invariants.",
            latency_ms=round(latency, 2),
            metadata={"drift_score": drift}
        )