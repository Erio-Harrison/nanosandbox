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


def test_run_releases_the_gil():
    import threading
    import time

    sandbox = Sandbox.builder().working_dir("/tmp").wall_time_limit(20).build()

    def one():
        assert sandbox.run("sleep", ["1"]).success()

    start = time.monotonic()
    threads = [threading.Thread(target=one) for _ in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    elapsed = time.monotonic() - start
    # 4 x 1s in parallel is ~1s; with the GIL held through each run, ~4s.
    assert elapsed < 2.5, f"4 x 1s took {elapsed:.1f}s; the runs were serialized"


def test_other_threads_keep_running_during_a_run():
    import threading
    import time

    sandbox = Sandbox.builder().working_dir("/tmp").wall_time_limit(20).build()
    ticks = []
    stop = threading.Event()

    def ticker():
        while not stop.is_set():
            ticks.append(1)
            time.sleep(0.02)

    t = threading.Thread(target=ticker)
    t.start()
    assert sandbox.run("sleep", ["1"]).success()
    stop.set()
    t.join()
    assert len(ticks) >= 20, f"only {len(ticks)} ticks while the run was in flight"


def test_host_ids_exist_on_linux_and_need_root():
    import os
    import sys

    import pytest

    if not sys.platform.startswith("linux"):
        pytest.skip("Linux only")
    builder = Sandbox.builder().host_uid(12345).host_gid(12345)
    if os.geteuid() == 0:
        assert builder.build() is not None
    else:
        with pytest.raises(Exception):
            builder.build()
