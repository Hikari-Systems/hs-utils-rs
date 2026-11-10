//! Process and container resource readings from `/proc/self` and the cgroup
//! v2 files of the container this process runs in.
//!
//! Pure parsers over file contents (tested with fixtures below) plus a
//! [`GaugeSource`] that reads the files at collection time. Every file is
//! optional: a missing one (not Linux, cgroup v1, delay accounting off) just
//! means those samples are not reported — never an error, never a zero that
//! looks like a reading.
//!
//! **Which "iowait" is which.** `hs.container.pressure{resource=io}` is the
//! cgroup's pressure stall information: the share of wall time some task in
//! *this container* was stalled waiting on I/O. That is the per-container
//! iowait. `hs.process.blkio_delay` is this process's cumulative time blocked
//! on block I/O (needs the kernel's delay accounting). Host-wide CPU iowait
//! (`system.cpu.time{state=wait}`) comes from the Collector's `hostmetrics`
//! receiver, not from here.

use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::Instant;

use crate::telemetry::{GaugeSource, Sample};

/// Linux reports `/proc/<pid>/stat` times in clock ticks of `USER_HZ`, which
/// is 100 on every architecture Linux supports in practice (it is fixed by
/// the ABI, unlike the kernel's internal `HZ`). Reading `sysconf(_SC_CLK_TCK)`
/// would need libc for a constant.
const USER_HZ: f64 = 100.0;

/// Fields of `/proc/self/stat` this module reports.
#[derive(Debug, Default, Clone, Copy, PartialEq)]
pub(crate) struct Stat {
    pub user_secs: f64,
    pub system_secs: f64,
    /// `delayacct_blkio_ticks`: time blocked on block I/O. `None` when the
    /// line is too short (an old kernel).
    pub blkio_delay_secs: Option<f64>,
}

/// Parse `/proc/self/stat`. The command name (field 2) is in parentheses and
/// may itself contain spaces and `)`, so fields are counted from the LAST `)`.
pub(crate) fn parse_stat(text: &str) -> Option<Stat> {
    let rest = &text[text.rfind(')')? + 1..];
    // `rest` starts at field 3 (state), so field N is index N - 3.
    let f: Vec<&str> = rest.split_whitespace().collect();
    let field = |n: usize| f.get(n - 3).and_then(|v| v.parse::<f64>().ok());
    Some(Stat {
        user_secs: field(14)? / USER_HZ,
        system_secs: field(15)? / USER_HZ,
        blkio_delay_secs: field(42).map(|t| t / USER_HZ),
    })
}

/// Fields of `/proc/self/status` (sizes there are in kB, so no page size is
/// needed — it is 64 KiB on some arm64 kernels).
#[derive(Debug, Default, Clone, Copy, PartialEq)]
pub(crate) struct Status {
    pub rss_bytes: Option<f64>,
    pub virtual_bytes: Option<f64>,
    pub threads: Option<f64>,
}

pub(crate) fn parse_status(text: &str) -> Status {
    let mut s = Status::default();
    for line in text.lines() {
        let Some((key, value)) = line.split_once(':') else { continue };
        let num = || value.split_whitespace().next().and_then(|v| v.parse::<f64>().ok());
        match key {
            "VmRSS" => s.rss_bytes = num().map(|kb| kb * 1024.0),
            "VmSize" => s.virtual_bytes = num().map(|kb| kb * 1024.0),
            "Threads" => s.threads = num(),
            _ => {}
        }
    }
    s
}

/// `/proc/self/io`: bytes this process caused to be read from / written to
/// storage (not the page cache: `rchar`/`wchar` would count those).
#[derive(Debug, Default, Clone, Copy, PartialEq)]
pub(crate) struct Io {
    pub read_bytes: Option<f64>,
    pub write_bytes: Option<f64>,
}

pub(crate) fn parse_io(text: &str) -> Io {
    let mut io = Io::default();
    for line in text.lines() {
        let Some((key, value)) = line.split_once(':') else { continue };
        let v = value.trim().parse::<f64>().ok();
        match key {
            "read_bytes" => io.read_bytes = v,
            "write_bytes" => io.write_bytes = v,
            _ => {}
        }
    }
    io
}

/// cgroup v2 `cpu.stat`.
#[derive(Debug, Default, Clone, Copy, PartialEq)]
pub(crate) struct CpuStat {
    pub usage_secs: Option<f64>,
    pub throttled_secs: Option<f64>,
    pub nr_throttled: Option<f64>,
}

pub(crate) fn parse_cpu_stat(text: &str) -> CpuStat {
    let mut c = CpuStat::default();
    for line in text.lines() {
        let mut it = line.split_whitespace();
        let (Some(key), Some(value)) = (it.next(), it.next().and_then(|v| v.parse::<f64>().ok())) else {
            continue;
        };
        match key {
            "usage_usec" => c.usage_secs = Some(value / 1e6),
            "throttled_usec" => c.throttled_secs = Some(value / 1e6),
            "nr_throttled" => c.nr_throttled = Some(value),
            _ => {}
        }
    }
    c
}

/// cgroup v2 `cpu.max` (`"<quota> <period>"` or `"max <period>"`) as a
/// number of CPUs. `None` for no limit.
pub(crate) fn parse_cpu_max(text: &str) -> Option<f64> {
    let mut it = text.split_whitespace();
    let quota = it.next()?.parse::<f64>().ok()?;
    let period = it.next()?.parse::<f64>().ok()?;
    (period > 0.0).then(|| quota / period)
}

/// cgroup v2 `memory.max` / `memory.current`: a byte count, or `"max"`.
pub(crate) fn parse_bytes(text: &str) -> Option<f64> {
    text.trim().parse::<f64>().ok()
}

/// One line of a PSI file (`cpu.pressure`, `memory.pressure`, `io.pressure`):
/// `some avg10=1.23 avg60=… avg300=… total=…`. Returns `(kind, avg10)` — the
/// percentage of the last 10 s that some (or, for `full`, every) runnable task
/// in the cgroup was stalled on that resource.
pub(crate) fn parse_pressure(text: &str) -> Vec<(&str, f64)> {
    text.lines()
        .filter_map(|line| {
            let mut it = line.split_whitespace();
            let kind = it.next()?;
            let avg10 = it.find_map(|kv| kv.strip_prefix("avg10="))?.parse::<f64>().ok()?;
            Some((kind, avg10))
        })
        .collect()
}

/// Where to read from. Separate so tests can point it at a fixture tree.
pub(crate) struct Paths {
    pub proc_self: PathBuf,
    pub cgroup: PathBuf,
}

impl Default for Paths {
    fn default() -> Self {
        Self {
            proc_self: PathBuf::from("/proc/self"),
            // Inside a container with its own cgroup namespace (Docker's
            // default on cgroup v2), this is the container's cgroup.
            cgroup: PathBuf::from("/sys/fs/cgroup"),
        }
    }
}

fn read(dir: &Path, file: &str) -> Option<String> {
    std::fs::read_to_string(dir.join(file)).ok()
}

/// CPU time at the previous collection, for `process.cpu.utilization`.
struct Last {
    at: Instant,
    cpu_secs: f64,
}

/// The gauge source for everything above.
pub(crate) fn source(paths: Paths) -> GaugeSource {
    let last: Mutex<Option<Last>> = Mutex::new(None);
    Box::new(move |out: &mut Vec<Sample>| {
        let push = |out: &mut Vec<Sample>, name, value, attrs: &[(&'static str, &str)]| {
            out.push(Sample {
                name,
                value,
                attrs: attrs.iter().map(|(k, v)| (*k, v.to_string())).collect(),
            })
        };
        let cg = &paths.cgroup;
        let cpu_limit = read(cg, "cpu.max").and_then(|t| parse_cpu_max(&t));

        if let Some(stat) = read(&paths.proc_self, "stat").and_then(|t| parse_stat(&t)) {
            push(out, "process.cpu.time", stat.user_secs, &[("cpu.mode", "user")]);
            push(out, "process.cpu.time", stat.system_secs, &[("cpu.mode", "system")]);
            if let Some(d) = stat.blkio_delay_secs {
                push(out, "hs.process.blkio_delay", d, &[]);
            }
            // Share of the CPU this process may use: the container's quota
            // when it has one, else every CPU the process can run on. 1.0 is
            // "using all of it"; above that is not possible for long.
            let cpu_secs = stat.user_secs + stat.system_secs;
            let now = Instant::now();
            let mut last = last.lock().unwrap_or_else(|p| p.into_inner());
            if let Some(prev) = last.as_ref() {
                let wall = now.duration_since(prev.at).as_secs_f64();
                let cpus = cpu_limit
                    .or_else(|| std::thread::available_parallelism().ok().map(|n| n.get() as f64))
                    .unwrap_or(1.0);
                if wall > 0.0 && cpus > 0.0 {
                    let used = (cpu_secs - prev.cpu_secs).max(0.0);
                    push(out, "process.cpu.utilization", used / wall / cpus, &[]);
                }
            }
            *last = Some(Last { at: now, cpu_secs });
        }

        if let Some(status) = read(&paths.proc_self, "status").map(|t| parse_status(&t)) {
            if let Some(v) = status.rss_bytes {
                push(out, "process.memory.usage", v, &[]);
            }
            if let Some(v) = status.virtual_bytes {
                push(out, "process.memory.virtual", v, &[]);
            }
            if let Some(v) = status.threads {
                push(out, "process.thread.count", v, &[]);
            }
        }

        if let Ok(fds) = std::fs::read_dir(paths.proc_self.join("fd")) {
            push(out, "process.open_file_descriptor.count", fds.count() as f64, &[]);
        }

        if let Some(io) = read(&paths.proc_self, "io").map(|t| parse_io(&t)) {
            if let Some(v) = io.read_bytes {
                push(out, "process.disk.io", v, &[("disk.io.direction", "read")]);
            }
            if let Some(v) = io.write_bytes {
                push(out, "process.disk.io", v, &[("disk.io.direction", "write")]);
            }
        }

        // ── container (cgroup v2) ──
        if let Some(cpu) = read(cg, "cpu.stat").map(|t| parse_cpu_stat(&t)) {
            if let Some(v) = cpu.usage_secs {
                push(out, "container.cpu.time", v, &[]);
            }
            if let Some(v) = cpu.throttled_secs {
                push(out, "hs.container.cpu.throttled_time", v, &[]);
            }
        }
        if let Some(v) = cpu_limit {
            push(out, "hs.container.cpu.limit", v, &[]);
        }
        if let Some(v) = read(cg, "memory.current").and_then(|t| parse_bytes(&t)) {
            push(out, "container.memory.usage", v, &[]);
        }
        if let Some(v) = read(cg, "memory.max").and_then(|t| parse_bytes(&t)) {
            push(out, "hs.container.memory.limit", v, &[]);
        }
        for resource in ["cpu", "memory", "io"] {
            if let Some(text) = read(cg, &format!("{resource}.pressure")) {
                for (kind, avg10) in parse_pressure(&text) {
                    push(out, "hs.container.pressure", avg10, &[("resource", resource), ("kind", kind)]);
                }
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A real `/proc/self/stat` line, with a command name containing `) (`
    /// to prove fields are counted from the last parenthesis.
    const STAT: &str = "4242 (my) (svc) S 1 4242 4242 0 -1 4194560 2735 0 0 0 \
        150 75 0 0 20 0 9 0 12345 123456789 2048 18446744073709551615 1 1 0 0 0 0 0 4096 0 0 0 0 17 3 0 0 \
        37 0 0 0 0 0 0 0 0 0";

    #[test]
    fn stat_counts_fields_from_the_last_parenthesis() {
        let s = parse_stat(STAT).unwrap();
        assert_eq!(s.user_secs, 1.5);
        assert_eq!(s.system_secs, 0.75);
        assert_eq!(s.blkio_delay_secs, Some(0.37));
    }

    #[test]
    fn a_short_stat_line_has_no_blkio_delay() {
        let s = parse_stat("1 (x) S 1 1 1 0 -1 0 0 0 0 0 10 20").unwrap();
        assert_eq!((s.user_secs, s.system_secs, s.blkio_delay_secs), (0.1, 0.2, None));
        assert_eq!(parse_stat("garbage"), None);
    }

    #[test]
    fn status_sizes_are_kilobytes() {
        let s = parse_status("Name:\tsvc\nVmSize:\t  204800 kB\nVmRSS:\t   51200 kB\nThreads:\t9\n");
        assert_eq!(s.rss_bytes, Some(51200.0 * 1024.0));
        assert_eq!(s.virtual_bytes, Some(204800.0 * 1024.0));
        assert_eq!(s.threads, Some(9.0));
    }

    #[test]
    fn io_reports_storage_bytes_not_page_cache() {
        let io = parse_io("rchar: 999999\nwchar: 888888\nread_bytes: 4096\nwrite_bytes: 8192\n");
        assert_eq!(io, Io { read_bytes: Some(4096.0), write_bytes: Some(8192.0) });
    }

    #[test]
    fn cgroup_cpu_files() {
        let c = parse_cpu_stat("usage_usec 2500000\nuser_usec 2000000\nsystem_usec 500000\nnr_periods 10\nnr_throttled 3\nthrottled_usec 120000\n");
        assert_eq!(c.usage_secs, Some(2.5));
        assert_eq!(c.throttled_secs, Some(0.12));
        assert_eq!(c.nr_throttled, Some(3.0));
        assert_eq!(parse_cpu_max("150000 100000\n"), Some(1.5));
        assert_eq!(parse_cpu_max("max 100000\n"), None, "no quota is no limit, not zero");
    }

    #[test]
    fn memory_max_of_max_is_no_limit() {
        assert_eq!(parse_bytes("536870912\n"), Some(536870912.0));
        assert_eq!(parse_bytes("max\n"), None);
    }

    #[test]
    fn pressure_lines() {
        let p = parse_pressure("some avg10=12.50 avg60=3.00 avg300=1.00 total=123\nfull avg10=4.25 avg60=1.00 avg300=0.50 total=45\n");
        assert_eq!(p, vec![("some", 12.5), ("full", 4.25)]);
    }

    /// The source over a fixture tree: every reading named as the catalog
    /// expects, and a missing file simply absent rather than zero.
    #[test]
    fn source_reads_a_fixture_tree() {
        let dir = std::env::temp_dir().join(format!("hs-utils-procfs-{}", std::process::id()));
        let (proc_self, cgroup) = (dir.join("proc"), dir.join("cg"));
        std::fs::create_dir_all(proc_self.join("fd")).unwrap();
        std::fs::create_dir_all(&cgroup).unwrap();
        std::fs::write(proc_self.join("stat"), STAT).unwrap();
        std::fs::write(proc_self.join("status"), "VmRSS:\t100 kB\n").unwrap();
        std::fs::write(proc_self.join("fd").join("0"), "").unwrap();
        std::fs::write(cgroup.join("io.pressure"), "some avg10=7.00 avg60=0 avg300=0 total=1\n").unwrap();
        std::fs::write(cgroup.join("memory.max"), "max\n").unwrap();

        let src = source(Paths { proc_self, cgroup });
        let mut out = Vec::new();
        src(&mut out);
        src(&mut out); // a second collection yields the utilisation gauge
        let _ = std::fs::remove_dir_all(&dir);

        let names: Vec<_> = out.iter().map(|s| s.name).collect();
        for want in ["process.cpu.time", "hs.process.blkio_delay", "process.memory.usage", "process.open_file_descriptor.count", "hs.container.pressure", "process.cpu.utilization"] {
            assert!(names.contains(&want), "missing {want}: {names:?}");
        }
        assert!(!names.contains(&"hs.container.memory.limit"), "memory.max=max must not report a limit");
        assert!(!names.contains(&"process.disk.io"), "no io file, no reading");
        let io = out.iter().find(|s| s.name == "hs.container.pressure").unwrap();
        assert_eq!(io.value, 7.0);
        assert_eq!(io.attrs, vec![("resource", "io".to_string()), ("kind", "some".to_string())]);
    }
}
