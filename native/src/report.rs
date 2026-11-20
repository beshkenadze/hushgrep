use crate::{Finding, Report, ScanTimes};
use anyhow::Result;
use rustix::fs::{CWD, RenameFlags, renameat_with};
use serde::Serialize;
use std::{
    collections::BTreeMap,
    fs::{self, File},
    io::{BufWriter, Write},
    os::unix::fs::PermissionsExt,
    path::Path,
};

#[derive(Serialize)]
struct Metrics<'a> {
    wall_seconds: f64,
    #[serde(flatten)]
    stages: &'a ScanTimes,
    peak_rss_kib: Option<u64>,
    runner_memory_kib: Option<u64>,
    cpu_count: usize,
    architecture: &'static str,
    runner_environment: String,
    image: String,
    image_version: String,
}

fn proc_kib(path: &str, field: &str) -> Option<u64> {
    let text = fs::read_to_string(path).ok()?;
    text.lines().find_map(|line| {
        line.strip_prefix(field)?
            .split_whitespace()
            .next()?
            .parse()
            .ok()
    })
}

pub fn parent(path: &Path) -> &Path {
    path.parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."))
}

pub fn write_json(mut out: impl Write, value: &impl Serialize) -> Result<()> {
    serde_json::to_writer_pretty(&mut out, value)?;
    writeln!(out)?;
    out.flush()?;
    Ok(())
}

fn write_escaped(mut out: impl Write, value: &str) -> std::io::Result<()> {
    for c in value.chars() {
        match c {
            '&' => out.write_all(b"&amp;")?,
            '<' => out.write_all(b"&lt;")?,
            '>' => out.write_all(b"&gt;")?,
            '"' => out.write_all(b"&quot;")?,
            '\'' => out.write_all(b"&#39;")?,
            _ => write!(out, "{c}")?,
        }
    }
    Ok(())
}

fn write_html(
    mut out: impl Write,
    report: &Report,
    groups: &[(usize, Vec<&Finding>)],
    metrics: &Metrics<'_>,
    rss: &str,
    skipped: usize,
) -> std::io::Result<()> {
    out.write_all(include_bytes!("report.html"))?;
    let (status, title) = if report.status == "complete" {
        ("complete", "Complete")
    } else {
        ("partial", "Partial")
    };
    write!(
        out,
        r#"<span class="state {status}">{title}</span></header><div class="cards">"#
    )?;
    for (label, count) in [
        ("Findings", report.finding_count),
        ("Files with findings", groups.len()),
        ("Files scanned", report.scanned_files),
        ("Lines scanned", report.scanned_lines),
    ] {
        write!(
            out,
            r#"<div class="card"><small>{label}</small><strong>{count}</strong></div>"#
        )?;
    }
    write!(
        out,
        r#"</div><p class="muted">{:.2} s scan time · {rss} peak RSS<br>"#,
        metrics.wall_seconds
    )?;
    write!(
        out,
        "{skipped} skipped files · {} unlocalized candidates · {} batches with incomplete coverage</p><h2>Findings by file</h2>",
        report.unlocalized_native_candidates, report.native_coverage_mismatch_batches,
    )?;
    if groups.is_empty() {
        write!(out, "<p>No candidate ranges were reported.</p>")?;
    } else {
        write!(
            out,
            "<p>Lines and columns start at 1. End columns are exclusive. Files are ordered by finding count.</p>"
        )?;
    }
    for (index, (file_id, rows)) in groups.iter().enumerate() {
        let open = if index == 0 { " open" } else { "" };
        write!(out, "<details{open}><summary><bdi>")?;
        if rows[0].path == "[REDACTED PATH]" {
            write!(out, "File {file_id} · path masked")?;
        } else {
            write_escaped(&mut out, &rows[0].path)?;
        }
        write!(
            out,
            r#"</bdi><span>{} findings</span></summary><div class="scroll"><table><thead><tr><th>Line</th><th>Column</th><th>End line</th><th>End column</th><th>Value</th></tr></thead><tbody>"#,
            rows.len(),
        )?;
        for row in rows {
            write!(
                out,
                "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td><code>[REDACTED]</code></td></tr>",
                row.line, row.column, row.end_line, row.end_column,
            )?;
        }
        write!(out, "</tbody></table></div></details>")?;
    }
    writeln!(out, "</main></html>")?;
    out.flush()
}

pub(super) fn write_bundle(
    directory: &Path,
    report: &Report,
    seconds: f64,
    stages: &ScanTimes,
) -> Result<()> {
    let metrics = Metrics {
        wall_seconds: seconds,
        stages,
        peak_rss_kib: proc_kib("/proc/self/status", "VmHWM:"),
        runner_memory_kib: proc_kib("/proc/meminfo", "MemTotal:"),
        cpu_count: std::thread::available_parallelism().map_or(1, |n| n.get()),
        architecture: std::env::consts::ARCH,
        runner_environment: std::env::var("RUNNER_ENVIRONMENT").unwrap_or_else(|_| "local".into()),
        image: std::env::var("ImageOS").unwrap_or_default(),
        image_version: std::env::var("ImageVersion").unwrap_or_default(),
    };
    let rss = metrics.peak_rss_kib.map_or_else(
        || "unavailable".into(),
        |kib| format!("{:.2} GiB", kib as f64 / 1_048_576.0),
    );
    let mut files = BTreeMap::<usize, Vec<&Finding>>::new();
    for finding in &report.findings {
        files.entry(finding.file_id).or_default().push(finding);
    }
    let mut groups: Vec<_> = files.into_iter().collect();
    groups.sort_by_key(|(id, rows)| (std::cmp::Reverse(rows.len()), *id));
    let skipped: usize = report.skipped_files.values().sum();
    let summary = format!(
        "## Hushgrep · Credential scan\n\n**{}** · {} masked findings in {} files.\n\n\
        | Files scanned | Lines scanned | Scan time | Peak RSS |\n\
        | ---: | ---: | ---: | ---: |\n\
        | {} | {} | {seconds:.2} s | {rss} |\n\n\
        Skipped files: {skipped}. Unlocalized candidates: {}. Coverage mismatches: {}.\n\n\
        TruffleHog {:.2} s · GLiNER load {:.2} s · GLiNER scan {:.2} s.\n",
        if report.status == "complete" {
            "Complete"
        } else {
            "Partial"
        },
        report.finding_count,
        groups.len(),
        report.scanned_files,
        report.scanned_lines,
        report.unlocalized_native_candidates,
        report.native_coverage_mismatch_batches,
        stages.trufflehog_seconds,
        stages.model_load_seconds,
        stages.gliner_seconds,
    );
    let staging = tempfile::Builder::new()
        .permissions(fs::Permissions::from_mode(0o700))
        .tempdir_in(parent(directory))?;
    let dir = staging.path();
    write_json(
        BufWriter::new(File::create(dir.join("report.json"))?),
        report,
    )?;
    write_json(
        BufWriter::new(File::create(dir.join("metrics.json"))?),
        &metrics,
    )?;
    write_html(
        BufWriter::new(File::create(dir.join("report.html"))?),
        report,
        &groups,
        &metrics,
        &rss,
        skipped,
    )?;
    fs::write(dir.join("summary.md"), summary)?;
    renameat_with(CWD, dir, CWD, directory, RenameFlags::NOREPLACE)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn html_escapes_repo_paths() {
        let mut output = Vec::new();
        super::write_escaped(&mut output, r#"путь/<tag "x"='y'>&.txt"#).unwrap();
        assert_eq!(
            String::from_utf8(output).unwrap(),
            "путь/&lt;tag &quot;x&quot;=&#39;y&#39;&gt;&amp;.txt"
        );
    }
}
