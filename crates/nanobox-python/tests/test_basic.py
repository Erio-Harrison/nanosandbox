from nanosandbox import Sandbox, MB


def test_basic_run():
    sandbox = Sandbox.builder().working_dir("/tmp").memory_limit(64 * MB).build()
    result = sandbox.run("echo", ["hello"])
    assert result.success()
    assert result.stdout.strip() == "hello"
    assert result.exit_code == 0


def test_run_with_input():
    sandbox = Sandbox.builder().working_dir("/tmp").build()
    result = sandbox.run_with_input("cat", [], stdin=b"piped")
    assert result.stdout.strip() == "piped"


def test_failure_reason():
    sandbox = Sandbox.builder().working_dir("/tmp").build()
    result = sandbox.run("false", [])
    assert not result.success()
    assert result.failure_reason() == "Exit code 1"


def test_presets_build():
    assert Sandbox.code_judge("/tmp").cpu_time_limit(2).build() is not None


def test_platform_helpers():
    assert isinstance(is_platform_supported_or_true(), bool)
    assert isinstance(Sandbox.builder().build().platform(), str)


def is_platform_supported_or_true():
    from nanosandbox import is_platform_supported

    return is_platform_supported()
