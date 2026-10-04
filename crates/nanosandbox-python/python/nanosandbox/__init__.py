"""
Nanosandbox - Lightweight cross-platform sandbox for secure code execution.

Supported platforms:
- Linux: namespaces, cgroups v2, seccomp, Landlock
- macOS: sandbox-exec (Seatbelt)
- Windows: Job Objects (memory/CPU limits only, no filesystem/network isolation)

Example:
    >>> from nanosandbox import Sandbox, MB
    >>> sandbox = (Sandbox.builder()
    ...     .read_only("/data/input")
    ...     .memory_limit(512 * MB)
    ...     .build())
    >>> result = sandbox.run("python3", ["-c", "print('hello')"])
    >>> print(result.stdout)
    hello
"""

from ._nanosandbox import (
    Sandbox,
    SandboxBuilder,
    ExecutionResult,
    is_platform_supported,
    platform_name,
    KB,
    MB,
    GB,
)

__version__ = "0.2.0"

__all__ = [
    "Sandbox",
    "SandboxBuilder",
    "ExecutionResult",
    "is_platform_supported",
    "platform_name",
    "KB",
    "MB",
    "GB",
]

try:
    from ._nanosandbox import Permission

    __all__.append("Permission")
except ImportError:
    # Linux only -- used with SandboxBuilder.bind().
    pass
