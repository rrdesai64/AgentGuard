import os
import shutil
import subprocess
import time
import yaml
from typing import Dict, Any, List
from core.schemas import InterceptDecision, InterceptStatus, EnforcementRing

class OSSandboxGuardian:
    """Layer 3/4 Linux Guardian: Sandboxes subshell processes and traces file/network syscalls."""
    def __init__(self, policy_path: str):
        with open(policy_path, "r") as f:
            self.policy = yaml.safe_load(f)["policies"]["ring2_os"]

    def execute_monitored_command(self, command: str, working_dir: str = "/tmp") -> InterceptDecision:
        start_time = time.perf_counter()
        has_strace = shutil.which("strace") is not None
        has_unshare = shutil.which("unshare") is not None

        # Build execution wrapper
        # Uses unshare -n (network namespace) if requested to drop external networking
        base_cmd: List[str] = []
        if self.policy.get("enforce_network_isolation", True) and has_unshare and os.geteuid() == 0:
            base_cmd.extend(["unshare", "-n"])

        trace_log = f"/tmp/agentguard_trace_{os.getpid()}_{int(time.time()*1000)}.log"

        if has_strace:
            # Trace file open and network connection syscalls
            wrapper_cmd = base_cmd + [
                "strace",
                "-f",
                "-e", "trace=open,openat,connect",
                "-o", trace_log,
                "bash", "-c", command
            ]
        else:
            wrapper_cmd = base_cmd + ["bash", "-c", command]

        proc = None
        try:
            proc = subprocess.Popen(
                wrapper_cmd,
                cwd=working_dir,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            stdout, stderr = proc.communicate(timeout=self.policy.get("max_execution_timeout_sec", 10))
            returncode = proc.returncode
        except subprocess.TimeoutExpired:
            if proc:
                proc.kill()
            latency = (time.perf_counter() - start_time) * 1000.0
            return InterceptDecision(
                status=InterceptStatus.BLOCKED,
                ring=EnforcementRing.RING2_OS,
                reason="Execution Terminated: Subprocess exceeded maximum execution timeout limit.",
                latency_ms=round(latency, 2),
                metadata={"command": command}
            )

        # Inspect syscall traces for security policy breaches
        if os.path.exists(trace_log):
            with open(trace_log, "r", errors="ignore") as f:
                trace_output = f.read()
            os.remove(trace_log)

            # Check 1: Sensitive File Reads
            for blocked_path in self.policy["blocked_read_paths"]:
                if blocked_path in trace_output:
                    latency = (time.perf_counter() - start_time) * 1000.0
                    return InterceptDecision(
                        status=InterceptStatus.BLOCKED,
                        ring=EnforcementRing.RING2_OS,
                        reason=f"Kernel Syscall Intercept: Process attempted unauthorized access to '{blocked_path}'.",
                        latency_ms=round(latency, 2),
                        metadata={"syscall": "openat", "target_path": blocked_path}
                    )

            # Check 2: Network Sockets
            if "connect(" in trace_output and self.policy.get("enforce_network_isolation"):
                # If non-local connection attempted
                if not ("127.0.0.1" in trace_output or "AF_UNIX" in trace_output):
                    latency = (time.perf_counter() - start_time) * 1000.0
                    return InterceptDecision(
                        status=InterceptStatus.BLOCKED,
                        ring=EnforcementRing.RING2_OS,
                        reason="Kernel Syscall Intercept: Process attempted outbound network socket connection.",
                        latency_ms=round(latency, 2),
                        metadata={"syscall": "connect"}
                    )

        latency = (time.perf_counter() - start_time) * 1000.0
        return InterceptDecision(
            status=InterceptStatus.ALLOWED if returncode == 0 else InterceptStatus.BLOCKED,
            ring=EnforcementRing.RING2_OS,
            reason=f"Execution completed with exit code {returncode}.",
            latency_ms=round(latency, 2),
            metadata={"returncode": returncode, "stdout": stdout, "stderr": stderr}
        )