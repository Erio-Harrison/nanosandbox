//! Overhead and density: how long a sandbox takes to start and end, how many run at once, and
//! what each costs the host.
//!
//! `cargo run --release --example density -- [latency|density|throughput|all] [counts]`
//! (counts: comma-separated sandbox counts for `density`, e.g. 100,500,1000).
//! Unix only.

#[cfg(unix)]
mod bench {
    use nanosandbox::{Child, MB, Sandbox, SandboxBuilder};
    use std::process::Command;
    use std::time::{Duration, Instant};

    fn ms(d: Duration) -> f64 {
        d.as_secs_f64() * 1000.0
    }

    fn summary(label: &str, mut v: Vec<f64>) {
        v.sort_by(|a, b| a.partial_cmp(b).unwrap());
        let at = |p: f64| v[((v.len() as f64 - 1.0) * p).round() as usize];
        println!(
            "  {label:<34} p50 {:>7.2}  p95 {:>7.2}  p99 {:>7.2}  max {:>7.2}  ms  (n={})",
            at(0.5),
            at(0.95),
            at(0.99),
            v[v.len() - 1],
            v.len()
        );
    }

    /// A named configuration: a minimal sandbox, one with the usual rules and limits, one with
    /// the network proxy.
    type Make = Box<dyn Fn() -> SandboxBuilder>;

    fn variants(ws: &std::path::Path) -> Vec<(&'static str, Make)> {
        let ws = ws.to_path_buf();
        let ws2 = ws.clone();
        let (ws3, ws4, ws5) = (ws.clone(), ws.clone(), ws.clone());
        vec![
            (
                "only memory_limit",
                Box::new(|| {
                    Sandbox::builder()
                        .working_dir("/tmp")
                        .memory_limit(256 * MB)
                }),
            ),
            (
                "only cpu+wall limits",
                Box::new(|| {
                    Sandbox::builder()
                        .working_dir("/tmp")
                        .cpu_time_limit(Duration::from_secs(30))
                        .wall_time_limit(Duration::from_secs(3600))
                }),
            ),
            (
                "only writable+deny_read",
                Box::new(move || {
                    Sandbox::builder()
                        .working_dir(&ws3)
                        .writable(&ws3)
                        .deny_read(ws3.join("secret"))
                }),
            ),
            (
                "only hide_home",
                Box::new(|| Sandbox::builder().working_dir("/tmp").hide_home()),
            ),
            (
                "only writable",
                Box::new(move || Sandbox::builder().working_dir(&ws4).writable(&ws4)),
            ),
            (
                "only read_only",
                Box::new(move || Sandbox::builder().working_dir(&ws5).read_only(&ws5)),
            ),
            (
                "minimal",
                Box::new(|| Sandbox::builder().working_dir("/tmp")),
            ),
            (
                "rules and limits",
                Box::new(move || {
                    let b = Sandbox::builder()
                        .working_dir(&ws)
                        .writable(&ws)
                        .deny_read(ws.join("secret"))
                        .hide_home()
                        .memory_limit(256 * MB)
                        .cpu_time_limit(Duration::from_secs(30))
                        .wall_time_limit(Duration::from_secs(3600));
                    // (macOS has no per-sandbox process limit.)
                    if cfg!(target_os = "macos") {
                        b
                    } else {
                        b.max_pids(64)
                    }
                }),
            ),
            (
                "network proxy",
                Box::new(move || {
                    Sandbox::builder()
                        .working_dir(&ws2)
                        .read_only(&ws2)
                        .allow_network(&["example.invalid"])
                }),
            ),
        ]
    }

    fn latency(n: usize) {
        println!("== latency, one at a time, {n} rounds each");
        let mut base = Vec::new();
        for _ in 0..n {
            let t = Instant::now();
            Command::new("true").status().unwrap();
            base.push(ms(t.elapsed()));
        }
        summary("plain fork+exec of `true` (host)", base);

        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join("secret")).unwrap();
        let ws = dir.path().canonicalize().unwrap();
        for (name, make) in variants(&ws) {
            println!(" {name}");
            let (mut build, mut run, mut spawn, mut end) = (vec![], vec![], vec![], vec![]);
            for _ in 0..n {
                let t0 = Instant::now();
                let sb = match make().build() {
                    Ok(sb) => sb,
                    Err(e) => {
                        println!("  cannot build: {e}");
                        break;
                    }
                };
                let t1 = Instant::now();
                let r = sb.run("true", &[]);
                let t2 = Instant::now();
                if let Err(e) = r {
                    println!("  run failed: {e}");
                    break;
                }
                build.push(ms(t1 - t0));
                run.push(ms(t2 - t1));

                let t3 = Instant::now();
                let mut child = sb.spawn("sleep", &["600"]).unwrap();
                let t4 = Instant::now();
                child.kill().unwrap();
                child.wait().unwrap();
                let t5 = Instant::now();
                spawn.push(ms(t4 - t3));
                end.push(ms(t5 - t4));
            }
            if run.is_empty() {
                continue;
            }
            summary("build()", build);
            summary("run(\"true\"): start to result", run);
            summary("spawn() returns", spawn);
            summary("kill() + wait()", end);
        }
    }

    fn throughput() {
        println!("== throughput, run(\"true\") in a loop, 5 s per row");
        let cpus = std::thread::available_parallelism().map_or(1, |n| n.get());
        let mut threads = vec![1, 2, 4];
        threads.extend([cpus, cpus * 2]);
        threads.sort();
        threads.dedup();
        for t in threads {
            let stop = Instant::now() + Duration::from_secs(5);
            let handles: Vec<_> = (0..t)
                .map(|_| {
                    std::thread::spawn(move || {
                        let sb = Sandbox::builder().working_dir("/tmp").build().unwrap();
                        let (mut ok, mut failed) = (0u64, 0u64);
                        while Instant::now() < stop {
                            match sb.run("true", &[]) {
                                Ok(r) if r.exit_code == 0 => ok += 1,
                                _ => failed += 1,
                            }
                        }
                        (ok, failed)
                    })
                })
                .collect();
            let (mut ok, mut failed) = (0, 0);
            for h in handles {
                let (o, f) = h.join().unwrap();
                ok += o;
                failed += f;
            }
            println!(
                "  {t:>3} threads: {:>7.1} runs/s ({failed} failed)",
                ok as f64 / 5.0
            );
        }
    }

    /// `(pid, ppid, rss_kb)` of every process.
    fn processes() -> Vec<(u32, u32, u64)> {
        // (Fails once this process is out of descriptors, which is itself a result.)
        let Ok(out) = Command::new("ps")
            .args(["-axo", "pid=,ppid=,rss="])
            .output()
        else {
            return Vec::new();
        };
        String::from_utf8_lossy(&out.stdout)
            .lines()
            .filter_map(|l| {
                let mut f = l.split_whitespace().map(|x| x.parse::<u64>().ok());
                Some((f.next()?? as u32, f.next()?? as u32, f.next()??))
            })
            .collect()
    }

    fn descendants() -> (usize, u64) {
        let all = processes();
        let me = std::process::id();
        let mut set = std::collections::HashSet::from([me]);
        loop {
            let before = set.len();
            for &(pid, ppid, _) in &all {
                if set.contains(&ppid) {
                    set.insert(pid);
                }
            }
            if set.len() == before {
                break;
            }
        }
        let rss = all
            .iter()
            .filter(|(p, _, _)| *p != me && set.contains(p))
            .map(|p| p.2)
            .sum();
        (set.len() - 1, rss)
    }

    fn own_rss_kb() -> u64 {
        processes()
            .iter()
            .find(|p| p.0 == std::process::id())
            .map_or(0, |p| p.2)
    }

    fn own_threads() -> usize {
        if let Ok(t) = std::fs::read_dir("/proc/self/task") {
            return t.count();
        }
        let Ok(out) = Command::new("ps")
            .args(["-M", "-p", &std::process::id().to_string()])
            .output()
        else {
            return 0;
        };
        String::from_utf8_lossy(&out.stdout)
            .lines()
            .count()
            .saturating_sub(1)
    }

    fn own_fds() -> usize {
        let dir = if std::path::Path::new("/proc/self/fd").exists() {
            "/proc/self/fd"
        } else {
            "/dev/fd"
        };
        std::fs::read_dir(dir).map_or(0, |d| d.count())
    }

    /// Linux: the system's available memory, which counts what the kernel spends on each
    /// sandbox (page tables, stacks, mounts) as well as the processes' own.
    fn mem_available_kb() -> Option<u64> {
        let m = std::fs::read_to_string("/proc/meminfo").ok()?;
        m.lines()
            .find(|l| l.starts_with("MemAvailable:"))?
            .split_whitespace()
            .nth(1)?
            .parse()
            .ok()
    }

    /// CPU seconds this process has used so far (user + system).
    fn cpu_secs() -> f64 {
        let mut u: libc::rusage = unsafe { std::mem::zeroed() };
        unsafe { libc::getrusage(libc::RUSAGE_SELF, &mut u) };
        let t = |v: libc::timeval| v.tv_sec as f64 + v.tv_usec as f64 / 1e6;
        t(u.ru_utime) + t(u.ru_stime)
    }

    fn sleepers() -> usize {
        let Ok(out) = Command::new("pgrep").args(["-f", "sleep 600"]).output() else {
            return 0;
        };
        String::from_utf8_lossy(&out.stdout).lines().count()
    }

    fn density(counts: &[usize], only: Option<&str>) {
        println!("== density: sandboxes each running `sleep 600`, held for 3 s, then ended");
        let dir = tempfile::tempdir().unwrap();
        let ws = dir.path().canonicalize().unwrap();
        std::fs::create_dir(ws.join("secret")).unwrap();
        for (name, make) in variants(&ws) {
            if only.is_some_and(|o| !name.contains(o)) {
                continue;
            }
            println!(" {name}");
            for &k in counts {
                std::thread::sleep(Duration::from_secs(1));
                let avail0 = mem_available_kb();
                let (rss0, thr0, fds0) = (own_rss_kb(), own_threads(), own_fds());

                let t0 = Instant::now();
                let mut held: Vec<(Sandbox, Child)> = Vec::with_capacity(k);
                let mut failure = None;
                let mut each: Vec<f64> = Vec::new();
                for i in 0..k {
                    let started = Instant::now();
                    let sb = match make().build() {
                        Ok(sb) => sb,
                        Err(e) => {
                            failure = Some(format!("sandbox {i}: build: {e}"));
                            break;
                        }
                    };
                    match sb.spawn("sleep", &["600"]) {
                        Ok(c) => {
                            held.push((sb, c));
                            each.push(ms(started.elapsed()));
                        }
                        Err(e) => {
                            failure = Some(format!("sandbox {i}: spawn: {e}"));
                            break;
                        }
                    }
                }
                let up = t0.elapsed();
                let n = held.len();
                // The sandboxes only sleep: whatever the host spends here is the cost of holding them.
                let (c0, w0) = (cpu_secs(), Instant::now());
                std::thread::sleep(Duration::from_secs(3));
                let idle_cpu = (cpu_secs() - c0) / w0.elapsed().as_secs_f64() * 100.0;
                let (procs, kids_rss) = descendants();
                let avail1 = mem_available_kb();
                let (rss1, thr1, fds1) = (own_rss_kb(), own_threads(), own_fds());

                let t1 = Instant::now();
                for (_, c) in held.iter_mut() {
                    let _ = c.kill();
                }
                for (_, c) in held.drain(..) {
                    let _ = c.wait();
                }
                let down = t1.elapsed();
                std::thread::sleep(Duration::from_secs(1));
                let left = sleepers();

                let per = |x: f64| if n == 0 { 0.0 } else { x / n as f64 };
                println!(
                    "  {k:>5} asked, {n:>5} up in {:>6.2} s ({:>5.2} ms each); ended in {:>6.2} s; left {left}",
                    up.as_secs_f64(),
                    per(ms(up)),
                    down.as_secs_f64()
                );
                println!(
                    "        per sandbox: processes {:.1}, children RSS {:.0} KB, library RSS {:+.0} KB, threads {:+.1}, fds {:+.1}{}",
                    per(procs as f64),
                    per(kids_rss as f64),
                    per(rss1 as f64 - rss0 as f64),
                    per(thr1 as f64 - thr0 as f64),
                    per(fds1 as f64 - fds0 as f64),
                    match (avail0, avail1) {
                        (Some(a), Some(b)) =>
                            format!(", system memory {:.0} KB", per(a as f64 - b as f64)),
                        _ => String::new(),
                    }
                );
                println!(
                    "        library CPU while they sleep: {idle_cpu:.1}% of one core ({:.3}% per sandbox)",
                    if n == 0 { 0.0 } else { idle_cpu / n as f64 }
                );
                if n >= 20 {
                    let tenth = n / 10;
                    let avg = |v: &[f64]| v.iter().sum::<f64>() / v.len() as f64;
                    println!(
                        "        build+spawn: first tenth {:.1} ms, last tenth {:.1} ms",
                        avg(&each[..tenth]),
                        avg(&each[n - tenth..])
                    );
                }
                if let Some(f) = failure {
                    println!("        stopped: {f}");
                    break;
                }
            }
        }
    }

    pub fn main() {
        let args: Vec<String> = std::env::args().skip(1).collect();
        let what = args.first().map_or("all", |s| s.as_str());
        let counts: Vec<usize> = args
            .get(1)
            .map(|s| s.split(',').filter_map(|x| x.parse().ok()).collect())
            .unwrap_or_else(|| vec![50, 200, 500, 1000, 2000]);
        if matches!(what, "latency" | "all") {
            latency(150);
        }
        if matches!(what, "throughput" | "all") {
            throughput();
        }
        if matches!(what, "density" | "all") {
            density(&counts, args.get(2).map(|s| s.as_str()));
        }
    }
}

fn main() {
    #[cfg(unix)]
    bench::main();
    #[cfg(not(unix))]
    println!("the density benchmark runs on Unix only");
}
