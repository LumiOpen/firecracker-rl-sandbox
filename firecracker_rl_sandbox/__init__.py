"""Python API for Firecracker RL sandbox experiments.

LocalPool runs real Firecracker microVMs in-process. ServiceClient talks to a
standalone service that owns Firecracker pools.
"""

from .client import CommandResult, ProcessHandle, Sandbox, ServiceClient, ServicePool
from .local import LocalPool, SubprocessPool

__all__ = [
    "CommandResult",
    "LocalPool",
    "ProcessHandle",
    "Sandbox",
    "ServiceClient",
    "ServicePool",
    "SubprocessPool",
]
