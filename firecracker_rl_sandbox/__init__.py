"""Python API for Firecracker RL sandbox experiments.

The service-backed classes are the production direction. LocalPool is a
subprocess-backed development helper and is not an isolation boundary.
"""

from .client import CommandResult, ProcessHandle, Sandbox, ServiceClient, ServicePool
from .local import LocalPool

__all__ = [
    "CommandResult",
    "LocalPool",
    "ProcessHandle",
    "Sandbox",
    "ServiceClient",
    "ServicePool",
]
