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
        camel_split = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", user_objective)
        clean = camel_split.lower().replace("_", " ")
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
        camel_split = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", tool_name)
        name_tokens = re.findall(r"[a-z0-9]+", camel_split.lower().replace("_", " "))
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

        if np.linalg.norm(act_v) < 1e-6 and name_tokens:
            first_c = self.synonym_map.get(name_tokens[0], name_tokens[0][:6])
            act_v += self._deterministic_gaussian_vector(first_c)

        arg_str = " ".join([f"{k} {v}" for k, v in (tool_args or {}).items()]).lower().replace("_", " ")
        for t in re.findall(r"[a-z0-9]+", arg_str):
            if t in self.stopwords:
                continue
            c = self.synonym_map.get(t, t[:6])
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
        if not user_objective or not user_objective.strip() or not tool_name or not tool_name.strip():
            return 1.0
        v_obj = self.encode_objective(user_objective)
        v_tool = self.encode_tool_call(tool_name, tool_args or {})
        if np.linalg.norm(v_obj) < 1e-6 or np.linalg.norm(v_tool) < 1e-6:
            return 1.0
        cosine_sim = float(np.dot(v_obj, v_tool))
        if np.isnan(cosine_sim):
            return 1.0
        drift = max(0.0, min(1.0, 1.0 - cosine_sim))

        # Entity/Numeric ID Pinning: If user specifies explicit IDs (e.g. 4092),
        # penalize tool arguments that target unauthorized IDs (e.g. 9999)
        obj_ids = set(re.findall(r"[0-9]{2,}", user_objective))
        arg_str = " ".join([f"{k} {v}" for k, v in (tool_args or {}).items()])
        arg_ids = set(re.findall(r"[0-9]{2,}", arg_str))
        if obj_ids and arg_ids and not arg_ids.issubset(obj_ids):
            drift = min(1.0, drift + 0.55)

        return round(drift, 3)
