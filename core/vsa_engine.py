import re
import zlib
import numpy as np
from typing import Dict, Any


class HolographicIntentEngine:
    """
    Holographic Reduced Representation (HRR) Engine for Ring 1.
    Uses Fast Fourier Transform (FFT) circular convolution to algebraically bind
    structural semantic roles (ACTION, TARGET, CONTEXT) to fillers in D=512 space.
    Strictly isolates ROLE::ACTION from untrusted tool arguments so keyword-stuffing
    cannot dilute or hijack action alignment.
    """

    def __init__(self, dim: int = 512):
        self.dim = dim
        self.synonym_map = {
            "summarize": "read", "summary": "read", "fetch": "read",
            "get": "read", "lookup": "read", "check": "read", "view": "read",
            "export": "exfil", "dump": "exfil", "upload": "exfil", "send": "exfil",
            "details": "ticket", "onboarding": "ticket", "id": "ticket", "issue": "ticket",
            "database": "records", "table": "records", "users": "records", "archive": "records"
        }
        self.action_verbs = {"read", "exfil", "delete", "update", "write", "exec"}
        self.stopwords = {"please", "the", "for", "and", "with", "from", "into", "true", "false"}

        self.role_action = self._deterministic_gaussian_vector("ROLE::ACTION")
        self.role_target = self._deterministic_gaussian_vector("ROLE::TARGET")
        self.role_context = self._deterministic_gaussian_vector("ROLE::CONTEXT")

    def _deterministic_gaussian_vector(self, token: str) -> np.ndarray:
        seed = zlib.crc32(token.encode("utf-8")) & 0xFFFFFFFF
        rng = np.random.default_rng(seed)
        vec = rng.normal(0.0, 1.0 / np.sqrt(self.dim), size=self.dim).astype(np.float32)
        norm = np.linalg.norm(vec)
        return vec / (norm + 1e-7)

    @staticmethod
    def _unit(v: np.ndarray) -> np.ndarray:
        n = np.linalg.norm(v)
        return v / n if n > 1e-7 else v

    @staticmethod
    def _circular_convolution(a: np.ndarray, b: np.ndarray) -> np.ndarray:
        return np.fft.irfft(np.fft.rfft(a) * np.fft.rfft(b), n=len(a)).astype(np.float32)

    def encode_objective(self, user_objective: str) -> np.ndarray:
        clean = user_objective.lower().replace("_", " ")
        tokens = re.findall(r"[a-z0-9]+", clean)

        act_v = np.zeros(self.dim, dtype=np.float32)
        tgt_v = np.zeros(self.dim, dtype=np.float32)
        ctx_v = np.zeros(self.dim, dtype=np.float32)

        for t in tokens:
            if t in self.stopwords:
                continue
            c = self.synonym_map.get(t, t[:6])
            v = self._deterministic_gaussian_vector(c)
            if c in self.action_verbs:
                act_v += v
            elif c.isdigit() or c in {"ticket", "records", "shadow", "ssh"}:
                tgt_v += v
            else:
                ctx_v += v

        state = (
            0.75 * self._circular_convolution(self.role_action, self._unit(act_v))
            + 0.60 * self._circular_convolution(self.role_target, self._unit(tgt_v))
            + 0.15 * self._circular_convolution(self.role_context, self._unit(ctx_v))
        )
        return self._unit(state)

    def encode_tool_call(self, tool_name: str, tool_args: Dict[str, Any]) -> np.ndarray:
        """
        Strictly binds ROLE::ACTION from tool_name ONLY.
        Tool arguments are bound exclusively to ROLE::TARGET and ROLE::CONTEXT,
        preventing parameter keyword-stuffing from spoofing the tool's action verb.
        """
        name_tokens = re.findall(r"[a-z0-9]+", tool_name.lower().replace("_", " "))
        act_v = np.zeros(self.dim, dtype=np.float32)
        tgt_v = np.zeros(self.dim, dtype=np.float32)
        ctx_v = np.zeros(self.dim, dtype=np.float32)

        for t in name_tokens:
            c = self.synonym_map.get(t, t[:6])
            v = self._deterministic_gaussian_vector(c)
            if c in self.action_verbs:
                act_v += v
            else:
                tgt_v += v

        arg_str = " ".join([f"{k} {v}" for k, v in tool_args.items()]).lower().replace("_", " ")
        for t in re.findall(r"[a-z0-9]+", arg_str):
            if t in self.stopwords:
                continue
            c = self.synonym_map.get(t, t[:6])
            # Ignore action verbs stuffed inside parameters so they cannot hijack ROLE::ACTION
            if c in self.action_verbs:
                continue
            v = self._deterministic_gaussian_vector(c)
            if c.isdigit() or c in {"ticket", "records", "shadow", "ssh"}:
                tgt_v += v
            else:
                ctx_v += v

        state = (
            0.75 * self._circular_convolution(self.role_action, self._unit(act_v))
            + 0.60 * self._circular_convolution(self.role_target, self._unit(tgt_v))
            + 0.15 * self._circular_convolution(self.role_context, self._unit(ctx_v))
        )
        return self._unit(state)

    def compute_hrr_drift(self, user_objective: str, tool_name: str, tool_args: Dict[str, Any]) -> float:
        v_obj = self.encode_objective(user_objective)
        v_tool = self.encode_tool_call(tool_name, tool_args)
        cosine_sim = float(np.dot(v_obj, v_tool))
        drift = max(0.0, min(1.0, 1.0 - cosine_sim))
        return round(drift, 3)
