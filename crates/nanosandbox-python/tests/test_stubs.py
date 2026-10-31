"""The type stubs name what the native module has, and nothing it hasn't."""

import ast
import pathlib
import sys

import nanosandbox._nanosandbox as native

STUB = pathlib.Path(__file__).resolve().parents[1] / "python" / "nanosandbox" / "_nanosandbox.pyi"

# Stub-only types for the dicts the getters return.
STUB_ONLY = {"NetworkRefusal", "DeniedPath"}
# Only built on one platform; the stub lists them for every platform.
LINUX_ONLY = {"Permission"}
LINUX_ONLY_METHODS = {
    "bind",
    "tmpfs",
    "rootfs",
    "seccomp",
    "uid",
    "gid",
    "host_uid",
    "host_gid",
    "hostname",
}
MACOS_ONLY_METHODS = {"shared_tmp"}
LINUX = sys.platform.startswith("linux")
MACOS = sys.platform == "darwin"


def built_here(member):
    if member in LINUX_ONLY_METHODS:
        return LINUX
    if member in MACOS_ONLY_METHODS:
        return MACOS
    return True


def stub_members():
    tree = ast.parse(STUB.read_text())
    top = {}
    for node in tree.body:
        if isinstance(node, ast.ClassDef):
            members = set()
            for item in node.body:
                if isinstance(item, ast.FunctionDef):
                    members.add(item.name)
                elif isinstance(item, ast.AnnAssign):
                    members.add(item.target.id)
            top[node.name] = members
        elif isinstance(node, ast.FunctionDef):
            top[node.name] = None
        elif isinstance(node, ast.AnnAssign):
            top[node.target.id] = None
    return top


def native_members(obj):
    return {n for n in dir(obj) if not n.startswith("_")}


def test_every_native_name_is_in_the_stub():
    stub = stub_members()
    for name in native_members(native):
        assert name in stub, f"{name} is in the module but not the stub"


def test_every_stub_name_is_in_the_module():
    for name, members in stub_members().items():
        if name in STUB_ONLY or (name in LINUX_ONLY and not LINUX):
            continue
        obj = getattr(native, name)
        if members is None:
            continue
        for member in members:
            if member == "__init__" or not built_here(member):
                continue
            assert hasattr(obj, member), f"{name}.{member} is in the stub but not the module"


def test_every_native_member_is_in_the_stub():
    stub = stub_members()
    for name in ("SandboxBuilder", "Sandbox", "ExecutionResult"):
        for member in native_members(getattr(native, name)):
            assert member in stub[name], f"{name}.{member} is in the module but not the stub"
