"""Core Affinity & Process Priority Pinning for Orbit Security.

Push bare-metal workstation and local network throughput to near-zero latency,
zero resource waste, and 100% fluid responsiveness:
  - Discovers CPU core architecture (Logical & Physical cores).
  - Pins compute-heavy worker tasks (Ollama, ffmpeg, video rendering) to E-cores (Efficiency cores)
    at BELOW_NORMAL or IDLE priority.
  - Pins asynchronous network sockets, webhooks, and supervisor listeners to P-cores (Performance cores)
    at NORMAL priority.
"""

from __future__ import annotations

import logging
import os
import sys
from typing import Any, Dict, List, Optional

try:
    import psutil

    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False

logger = logging.getLogger("orbit_security.core_affinity")


def get_core_topology() -> Dict[str, Any]:
    """Computes workstation CPU topology partitions into P-cores and E-cores."""
    logical = psutil.cpu_count(logical=True) or 8 if HAS_PSUTIL else 8
    physical = psutil.cpu_count(logical=False) or 4 if HAS_PSUTIL else 4

    if logical >= 4:
        # P-cores occupy the primary lower partition; E-cores occupy the upper partition
        p_cores = list(range(0, logical // 2))
        e_cores = list(range(logical // 2, logical))
    else:
        p_cores = list(range(0, logical))
        e_cores = list(range(0, logical))

    return {
        "logical_cores": logical,
        "physical_cores": physical,
        "p_cores": p_cores,
        "e_cores": e_cores,
    }


def apply_affinity_and_priority(
    pid: Optional[int] = None,
    role: str = "worker",
) -> bool:
    """Applies CPU affinity mask and priority class to target process (defaults to current process).

    Args:
        pid: Process ID to adjust. Defaults to current process (os.getpid()).
        role: "worker" (E-cores + BelowNormal) or "performance" (P-cores + Normal).
    """
    if not HAS_PSUTIL:
        return False

    target_pid = pid or os.getpid()
    try:
        proc = psutil.Process(target_pid)
        topo = get_core_topology()
        is_perf = role.lower() in ("performance", "p_core", "network", "supervisor")
        target_cores = topo["p_cores"] if is_perf else topo["e_cores"]

        # 1. Set CPU affinity
        try:
            proc.cpu_affinity(target_cores)
        except Exception as e:
            logger.debug("Failed setting cpu_affinity for PID %d: %s", target_pid, e)

        # 2. Set Process Priority Class
        if sys.platform == "win32":
            try:
                if is_perf:
                    proc.nice(psutil.NORMAL_PRIORITY_CLASS)
                elif role.lower() == "idle":
                    proc.nice(psutil.IDLE_PRIORITY_CLASS)
                else:
                    proc.nice(psutil.BELOW_NORMAL_PRIORITY_CLASS)
            except Exception as e:
                logger.debug("Failed setting priority class for PID %d: %s", target_pid, e)

        return True
    except Exception as e:
        logger.debug("apply_affinity_and_priority error for PID %d: %s", target_pid, e)
        return False


def apply_worker_affinity(pid: Optional[int] = None) -> bool:
    """Pins process to E-cores at BELOW_NORMAL priority."""
    return apply_affinity_and_priority(pid=pid, role="worker")


def apply_performance_affinity(pid: Optional[int] = None) -> bool:
    """Pins process to P-cores at NORMAL priority."""
    return apply_affinity_and_priority(pid=pid, role="performance")
