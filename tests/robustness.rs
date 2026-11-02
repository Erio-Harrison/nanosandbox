//! Random configurations and commands: `build()` and `run()` return an error or a result,
//! never panic or hang, and no spelling of a granted path makes a file outside the grants
//! writable. Seeded, so a failure reproduces; `NANOSANDBOX_FUZZ_ITERS` sets the count.

#![cfg(unix)]

use nanosandbox::Sandbox;
use std::ffi::OsString;
use std::os::unix::ffi::OsStringExt;
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::time::Duration;

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n.max(1) as u64) as usize
    }
    fn pick<T: Clone>(&mut self, items: &[T]) -> T {
        items[self.below(items.len())].clone()
    }
}

fn iterations(default: usize) -> usize {
    std::env::var("NANOSANDBOX_FUZZ_ITERS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

/// Runs `f` on a thread, giving up (and saying so) after `limit`.
fn within<T: Send + 'static>(
    limit: Duration,
    f: impl FnOnce() -> T + Send + 'static,
) -> Result<T, String> {
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(f));
        let _ = tx.send(result);
    });
    match rx.recv_timeout(limit) {
        Ok(Ok(value)) => Ok(value),
        Ok(Err(panic)) => Err(format!(
            "panicked: {}",
            panic
                .downcast_ref::<String>()
                .cloned()
                .or_else(|| panic.downcast_ref::<&str>().map(|s| s.to_string()))
                .unwrap_or_default()
        )),
        Err(_) => Err(format!("no end after {limit:?}")),
    }
}

struct Fixture {
    _dir: tempfile::TempDir,
    root: PathBuf,
    canary: PathBuf,
}

/// Paths of every awkward kind, some of which exist.
fn fixture() -> (Fixture, Vec<PathBuf>) {
    let dir = tempfile::tempdir_in(env!("CARGO_TARGET_TMPDIR")).unwrap();
    let root = dir.path().canonicalize().unwrap();
    let canary = root.join("outside").join("canary");
    std::fs::create_dir_all(canary.parent().unwrap()).unwrap();
    std::fs::write(&canary, "ORIG").unwrap();
    let grants = root.join("grants");
    std::fs::create_dir_all(&grants).unwrap();
    for d in [
        "plain",
        "quote\"dir",
        "paren)(dir",
        "semi;dir",
        "new\nline",
        "sp ace",
        "uni\u{e9}\u{301}",
    ] {
        std::fs::create_dir_all(grants.join(d)).unwrap();
    }
    std::os::unix::fs::symlink(grants.join("b"), grants.join("a")).unwrap();
    std::os::unix::fs::symlink(grants.join("a"), grants.join("b")).unwrap();
    std::os::unix::fs::symlink(root.join("nowhere"), grants.join("dangling")).unwrap();
    std::os::unix::fs::symlink(root.join("outside"), grants.join("to_outside")).unwrap();
    std::fs::write(grants.join("file.txt"), "f").unwrap();
    unsafe {
        let fifo = std::ffi::CString::new(grants.join("fifo").to_str().unwrap()).unwrap();
        libc::mkfifo(fifo.as_ptr(), 0o666);
    }
    let long: String = "d".repeat(200);
    let _ = std::fs::create_dir_all(grants.join(&long));

    let mut paths: Vec<PathBuf> = [
        "",
        "/",
        ".",
        "..",
        "x/y",
        "/nonexistent/zzz",
        "/tmp",
        "/tmp/",
        "/etc/passwd",
        "/dev/null",
        "/proc",
        "/proc/self",
        "~",
        "//",
        "/tmp/../tmp/.",
    ]
    .iter()
    .map(PathBuf::from)
    .collect();
    paths.push(PathBuf::from(OsString::from_vec(b"a\0b".to_vec())));
    paths.push(PathBuf::from(OsString::from_vec(vec![b'/', 0xff, 0xfe])));
    paths.push(PathBuf::from("/".to_string() + &"x/".repeat(3000)));
    paths.push(PathBuf::from("a".repeat(5000)));
    for entry in std::fs::read_dir(&grants).unwrap().flatten() {
        paths.push(entry.path());
    }
    paths.push(grants.join("plain/../plain/./"));
    paths.push(grants.join("to_outside/.."));
    paths.push(grants.clone());
    paths.push(canary.parent().unwrap().to_path_buf());
    (
        Fixture {
            _dir: dir,
            root,
            canary,
        },
        paths,
    )
}

fn canonical_parent_of(path: &Path, canary: &Path) -> bool {
    std::fs::canonicalize(path).is_ok_and(|p| canary.starts_with(p))
}

#[test]
fn test_random_configurations_never_panic_hang_or_widen_a_grant() {
    let (fx, paths) = fixture();
    let strings = [
        "",
        "k",
        "PATH",
        "A=B",
        "a b",
        "\"",
        "x\ny",
        "é",
        "LD_PRELOAD",
    ];
    let mut rng = Rng(0x5eed_1234_abcd_ef01);
    let mut problems = Vec::new();
    let mut built = 0;

    for i in 0..iterations(300) {
        let mut b = Sandbox::builder();
        let mut writable = Vec::new();
        let mut log = Vec::new();
        for _ in 0..rng.below(7) {
            let path = rng.pick(&paths);
            match rng.below(14) {
                0 | 1 => {
                    log.push(format!("writable({path:?})"));
                    writable.push(path.clone());
                    b = b.writable(path);
                }
                2 | 3 => {
                    log.push(format!("read_only({path:?})"));
                    b = b.read_only(path);
                }
                4 => {
                    log.push(format!("deny_read({path:?})"));
                    b = b.deny_read(path);
                }
                5 => {
                    log.push(format!("working_dir({path:?})"));
                    b = b.working_dir(path);
                }
                6 => {
                    let n = rng.pick(&[0u64, 1, 4096, 1 << 20, u64::MAX, u64::MAX / 2]);
                    log.push(format!("private_tmp({n})"));
                    b = b.private_tmp(n);
                }
                7 => {
                    let d = rng.pick(&[
                        Duration::ZERO,
                        Duration::from_nanos(1),
                        Duration::from_millis(50),
                        Duration::from_secs(3),
                        Duration::MAX,
                    ]);
                    log.push(format!("wall_time_limit({d:?})"));
                    b = b.wall_time_limit(d);
                }
                8 => {
                    let n = rng.pick(&[0u64, 1, 1000, 1 << 20, 1 << 40, u64::MAX]);
                    log.push(format!("memory_limit({n})"));
                    b = b.memory_limit(n);
                }
                9 => {
                    let n = rng.pick(&[0u32, 1, 3, 100, u32::MAX]);
                    log.push(format!("max_pids({n})"));
                    b = b.max_pids(n);
                }
                10 => {
                    let n = rng.pick(&[0u64, 1, 100, 1 << 20, u64::MAX]);
                    log.push(format!("max_output({n}) max_file_size"));
                    b = b.max_output(n).max_file_size(n);
                }
                11 => {
                    let (k, v) = (rng.pick(&strings), rng.pick(&strings));
                    log.push(format!("env({k:?},{v:?})"));
                    b = b.env(k, v);
                }
                12 => {
                    let n = rng.pick(&[0u32, 1, 3, 1024, u32::MAX]);
                    log.push(format!("max_open_files({n})"));
                    b = b.max_open_files(n);
                }
                _ => {
                    log.push("hide_home".into());
                    b = b.hide_home();
                }
            }
        }
        let describe = format!("#{i} {}", log.join(" "));

        let built_once = within(Duration::from_secs(30), move || b.build());
        let sandbox = match built_once {
            Err(why) => {
                problems.push(format!("{describe}: build {why}"));
                continue;
            }
            Ok(Err(_)) => continue, // refused: fine
            Ok(Ok(sandbox)) => sandbox,
        };
        built += 1;
        let canary = fx.canary.clone();
        let script = format!("echo X >> '{}' 2>/dev/null; echo done", canary.display());
        if let Err(why) = within(Duration::from_secs(60), move || {
            sandbox.run("sh", &["-c", &script])
        }) {
            problems.push(format!("{describe}: run {why}"));
        }
        let legit = writable.iter().any(|p| canonical_parent_of(p, &fx.canary));
        let now = std::fs::read_to_string(&fx.canary).unwrap_or_default();
        if !legit && now != "ORIG" {
            problems.push(format!(
                "{describe}: the canary outside every grant is now {now:?}"
            ));
            std::fs::write(&fx.canary, "ORIG").unwrap();
        } else if legit && now != "ORIG" {
            std::fs::write(&fx.canary, "ORIG").unwrap();
        }
    }
    let _ = &fx.root;
    assert!(
        problems.is_empty(),
        "{} problems ({built} sandboxes built), first:\n{}",
        problems.len(),
        problems[..problems.len().min(8)].join("\n")
    );
    assert!(built > 20, "only {built} configurations were accepted");
}

#[test]
fn test_awkward_commands_and_arguments_end_in_an_error_or_a_result() {
    let sandbox = std::sync::Arc::new(
        Sandbox::builder()
            .working_dir("/tmp")
            .wall_time_limit(Duration::from_secs(10))
            .build()
            .unwrap(),
    );
    let nul = String::from_utf8(vec![b'a', 0, b'b']).unwrap();
    let long = "x".repeat(300_000);
    let huge = "y".repeat(4 << 20);
    let many: Vec<String> = (0..60_000).map(|i| i.to_string()).collect();
    let many_refs: Vec<&str> = many.iter().map(String::as_str).collect();
    let cases: Vec<(&str, Vec<&str>)> = vec![
        ("", vec![]),
        (" ", vec![]),
        ("/", vec![]),
        ("..", vec![]),
        ("/nonexistent/prog", vec![]),
        (&nul, vec![]),
        ("true", vec![&nul]),
        ("true", vec![&long]),
        ("true", vec![&huge]),
        ("true", many_refs),
        ("sh", vec!["-c", "kill -9 $$"]),
        ("sh", vec!["-c", "exec 1>&-; exec 2>&-; echo gone"]),
        ("sh", vec!["-c", "head -c 3000000 /dev/zero | tr '\\0' x"]),
        ("sh", vec!["-c", "trap '' TERM HUP INT; sleep 30"]),
        ("sh", vec!["-c", "ulimit -n 3; true"]),
        ("-", vec![]),
        ("--help", vec![]),
        ("sh", vec!["-c", "exit 300"]),
        ("sh", vec!["-c", "exit -1"]),
    ];
    for (n, (cmd, args)) in cases.into_iter().enumerate() {
        let cmd = cmd.to_string();
        let args: Vec<String> = args.into_iter().map(String::from).collect();
        let sandbox = std::sync::Arc::clone(&sandbox);
        let outcome = within(Duration::from_secs(60), move || {
            let refs: Vec<&str> = args.iter().map(String::as_str).collect();
            sandbox.run(&cmd, &refs)
        });
        assert!(outcome.is_ok(), "case {n}: {outcome:?}");
    }
}

#[test]
fn test_many_sandboxes_at_once_do_not_trip_over_each_other() {
    let mut threads = Vec::new();
    for t in 0..24 {
        threads.push(std::thread::spawn(move || {
            let mut failures = Vec::new();
            for i in 0..iterations(12) {
                let sandbox = Sandbox::builder()
                    .working_dir("/tmp")
                    .private_tmp(1 << 20)
                    .wall_time_limit(Duration::from_secs(20))
                    .build()
                    .unwrap();
                let script = match (t + i) % 4 {
                    0 => "echo hi > \"$TMPDIR/f\"; cat \"$TMPDIR/f\"",
                    1 => "mkdir \"$TMPDIR/d\"; chmod 000 \"$TMPDIR/d\"; echo hi",
                    2 => "sleep 0.05; echo hi",
                    _ => "echo hi; kill -9 $$",
                };
                match sandbox.run("sh", &["-c", script]) {
                    Ok(r) if (t + i) % 4 != 3 && !r.stdout.contains("hi") => {
                        failures.push(format!("thread {t} run {i}: {r:?}"))
                    }
                    Err(e) => failures.push(format!("thread {t} run {i}: {e}")),
                    _ => {}
                }
            }
            failures
        }));
    }
    let failures: Vec<String> = threads
        .into_iter()
        .flat_map(|t| t.join().unwrap())
        .collect();
    assert!(
        failures.is_empty(),
        "{} failures, first:\n{}",
        failures.len(),
        failures[..failures.len().min(5)].join("\n")
    );
}
