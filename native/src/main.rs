use anyhow::{Context, Result, ensure};
use serde::Serialize;
use std::{
    collections::{BTreeMap, BTreeSet},
    env,
    fs::File,
    io,
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

macro_rules! re {
    ($s:literal) => {{
        static R: std::sync::LazyLock<regex::Regex> =
            std::sync::LazyLock::new(|| regex::Regex::new($s).unwrap());
        &*R
    }};
}
type Span = (usize, usize);
mod model;
mod report;
mod rules;
mod source;
mod truffle;
use source::Source;

#[derive(Serialize)]
struct Finding {
    file_id: usize,
    path: String,
    line: usize,
    column: usize,
    end_line: usize,
    end_column: usize,
    value: &'static str,
}
#[derive(Serialize)]
struct Report {
    version: &'static str,
    status: &'static str,
    scanned_files: usize,
    scanned_lines: usize,
    skipped_files: BTreeMap<&'static str, usize>,
    unlocalized_native_candidates: usize,
    native_coverage_mismatch_batches: usize,
    finding_count: usize,
    findings: Vec<Finding>,
}
#[derive(Default, Serialize)]
struct ScanTimes {
    model_load_seconds: f64,
    trufflehog_seconds: f64,
    gliner_seconds: f64,
}

fn log_progress(enabled: bool, message: std::fmt::Arguments<'_>) {
    if enabled {
        eprintln!("Hushgrep progress: {message}");
    }
}

fn scan(root: &Path, base: &Path, progress: bool) -> Result<(Report, ScanTimes)> {
    let names = source::names(root)?;
    let total_paths = names.len();
    log_progress(progress, format_args!("inventory {total_paths} paths"));
    let dir = File::open(root)?;
    let mut report = Report {
        version: env!("CARGO_PKG_VERSION"),
        status: "complete",
        scanned_files: 0,
        scanned_lines: 0,
        skipped_files: BTreeMap::new(),
        unlocalized_native_candidates: 0,
        native_coverage_mismatch_batches: 0,
        finding_count: 0,
        findings: vec![],
    };
    let mut sensitive = BTreeSet::<String>::new();
    let mut model = None;
    let mut times = ScanTimes::default();
    let mut batch = 0;
    let mut iter = names.into_iter().peekable();
    while iter.peek().is_some() {
        let mut files = Vec::<Source>::new();
        let mut size = 0;
        while files.len() < 256 && size < 8 * 1024 * 1024 {
            let Some(name) = iter.next() else {
                break;
            };
            match source::read(&dir, name)? {
                Ok(src) => {
                    size += src.text.len();
                    report.scanned_lines += src.lines.len() - 1;
                    files.push(src);
                }
                Err(why) => *report.skipped_files.entry(why).or_default() += 1,
            }
        }
        if files.is_empty() {
            log_progress(
                progress,
                format_args!("processed {total_paths}/{total_paths} paths"),
            );
            break;
        }
        batch += 1;
        log_progress(
            progress,
            format_args!("TruffleHog batch {batch}: {} files", files.len()),
        );
        let start = Instant::now();
        let (native, unresolved, mismatch) = truffle::scan(&base.join("bin/trufflehog"), &files)?;
        times.trufflehog_seconds += start.elapsed().as_secs_f64();
        report.unlocalized_native_candidates += unresolved;
        report.native_coverage_mismatch_batches += usize::from(mismatch);
        if model.is_none() {
            log_progress(progress, format_args!("loading GLiNER"));
            let start = Instant::now();
            model = Some(model::Model::load(base)?);
            times.model_load_seconds = start.elapsed().as_secs_f64();
        }
        let windows: usize = files.iter().map(|src| src.lines.len() - 1).sum();
        log_progress(
            progress,
            format_args!("GLiNER batch {batch}: 0/{windows} windows"),
        );
        let start = Instant::now();
        let mut last_progress = start;
        let neural = model.as_mut().unwrap().scan(&files, |done| {
            if progress && (done == windows || last_progress.elapsed() >= Duration::from_secs(15)) {
                log_progress(
                    progress,
                    format_args!("GLiNER batch {batch}: {done}/{windows} windows"),
                );
                last_progress = Instant::now();
            }
        })?;
        times.gliner_seconds += start.elapsed().as_secs_f64();
        for (i, ((src, mut th), gliner)) in files.iter().zip(native).zip(neural).enumerate() {
            th.extend(gliner);
            let parsed = rules::Parsed::new(&src.text);
            for (a, b) in parsed.accept(src, th) {
                let l = src.line(a);
                let e = src.line(b - 1);
                report.findings.push(Finding {
                    file_id: report.scanned_files + i,
                    path: src.name.to_string_lossy().into_owned(),
                    line: l + 1,
                    column: src.text[src.lines[l]..a].chars().count() + 1,
                    end_line: e + 1,
                    end_column: src.text[src.lines[e]..b].chars().count() + 1,
                    value: "[REDACTED]",
                });
                let v = &src.text[a..b];
                sensitive.insert(v.into());
                match parsed.pairs.get(&(a, b)) {
                    Some(rules::Carrier::Uri) => {
                        sensitive.insert(
                            percent_encoding::percent_decode_str(v)
                                .decode_utf8_lossy()
                                .into_owned(),
                        );
                    }
                    Some(rules::Carrier::Encoded) => {
                        if let Some(bytes) = rules::decoded_basic(v) {
                            sensitive.insert(String::from_utf8_lossy(&bytes).into_owned());
                        }
                    }
                    _ => {}
                }
            }
        }
        report.scanned_files += files.len();
        log_progress(
            progress,
            format_args!("processed {}/{total_paths} paths", total_paths - iter.len()),
        );
    }
    let mut redact = BTreeMap::new();
    for f in &report.findings {
        redact.entry(f.file_id).or_insert_with(|| {
            sensitive
                .iter()
                .any(|v| !v.is_empty() && f.path.contains(v))
        });
    }
    for f in &mut report.findings {
        if redact[&f.file_id] {
            f.path = "[REDACTED PATH]".into();
        }
    }
    report.finding_count = report.findings.len();
    if report.unlocalized_native_candidates + report.native_coverage_mismatch_batches > 0 {
        report.status = "partial";
    }
    log_progress(progress, format_args!("writing report"));
    Ok((report, times))
}
fn run() -> Result<i32> {
    let started = Instant::now();
    let mut root = None;
    let mut output = None;
    let mut report_dir = None;
    let mut timings = false;
    let mut progress = false;
    let mut args = env::args_os().skip(1);
    while let Some(arg) = args.next() {
        match arg.to_str() {
            Some("--version") => {
                println!("hushgrep {} (v10 INT8)", env!("CARGO_PKG_VERSION"));
                return Ok(0);
            }
            Some("--help" | "-h") => {
                println!(
                    "hushgrep [--output NEW_REPORT.json | --report-dir NEW_DIRECTORY] [--timings] [--progress] REPOSITORY\nScan a local Git working tree on CPU. By default masked JSON goes to stdout.\n--report-dir writes JSON, HTML, measurements and a Markdown summary to a new directory, and prints the finding count.\n--progress writes phase names and counts to stderr."
                );
                return Ok(0);
            }
            Some("--output") if output.is_none() => {
                output = Some(PathBuf::from(args.next().context("output filename")?));
            }
            Some("--report-dir") if report_dir.is_none() => {
                report_dir = Some(PathBuf::from(args.next().context("report directory")?));
            }
            Some("--timings") => timings = true,
            Some("--progress") => progress = true,
            _ => {
                ensure!(
                    root.is_none() && !arg.to_string_lossy().starts_with('-'),
                    "usage"
                );
                root = Some(PathBuf::from(arg));
            }
        }
    }
    let root = root.context("repository")?.canonicalize()?;
    ensure!(
        output.is_none() || report_dir.is_none(),
        "choose one output mode"
    );
    if let Some(p) = output.as_ref().or(report_dir.as_ref()) {
        ensure!(p.symlink_metadata().is_err(), "output exists");
    }
    let exe = env::current_exe()?;
    let base = exe.parent().context("bundle directory")?;
    let (report, times) = scan(&root, base, progress)?;
    if let Some(p) = report_dir {
        report::write_bundle(&p, &report, started.elapsed().as_secs_f64(), &times)?;
        println!("{}", report.finding_count);
    } else if let Some(p) = output {
        let mut tmp = tempfile::NamedTempFile::new_in(report::parent(&p))?;
        report::write_json(tmp.as_file_mut(), &report)?;
        tmp.persist_noclobber(p)?;
    } else {
        report::write_json(io::stdout().lock(), &report)?;
    }
    if timings {
        eprintln!(
            "{}",
            serde_json::json!({
                "total_seconds": started.elapsed().as_secs_f64(),
                "model_load_seconds": times.model_load_seconds,
                "trufflehog_seconds": times.trufflehog_seconds,
                "gliner_seconds": times.gliner_seconds,
            })
        );
    }
    Ok(if report.status == "complete" { 0 } else { 2 })
}
fn main() {
    // Paths and third-party errors can contain credentials. Keep diagnostics fixed.
    std::panic::set_hook(Box::new(|_| eprintln!("Internal scan error.")));
    let code = run().unwrap_or_else(|_| {
        eprintln!(
            "Scan failed. Check the Git root, bundle assets, and output path. Use --help for usage."
        );
        1
    });
    std::process::exit(code)
}
