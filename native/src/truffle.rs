use crate::{Span, source::Source};
use anyhow::{Context, Result, ensure};
use serde_json::Value;
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
    process::Command,
};

fn identity(value: &str) -> Option<(String, String, String, String)> {
    let u = url::Url::parse(value).ok()?;
    let decode = |s: &str| {
        percent_encoding::percent_decode_str(s)
            .decode_utf8_lossy()
            .into_owned()
    };
    Some((
        u.scheme().into(),
        u.host_str()?.into(),
        decode(u.username()),
        decode(u.password().unwrap_or("")),
    ))
}
fn locate(row: &Value, src: &Source, line: usize) -> Option<Span> {
    let text = &src.text;
    let lo = *src.lines.get(line.checked_sub(1)?)?;
    let hi = *src.lines.get(line)?;
    let raw = row["Raw"].as_str().unwrap_or("");
    let v2 = row["RawV2"].as_str().unwrap_or("");
    let mut same = BTreeSet::new();
    for v in [raw, v2].into_iter().filter(|s| !s.is_empty()) {
        same.extend(
            text[lo..]
                .match_indices(v)
                .take_while(|(i, _)| lo + i < hi)
                .map(|(i, _)| (lo + i, lo + i + v.len())),
        );
    }
    if same.len() == 1 {
        return same.first().copied();
    }
    if row["DetectorName"] == "PrivateKey" {
        if let Some(v) = raw.strip_suffix('\n') {
            if v.starts_with("-----BEGIN ")
                && text.ends_with(v)
                && text.matches(v).count() == 1
                && src.line(text.len() - v.len()) == line - 1
            {
                return Some((text.len() - v.len(), text.len()));
            }
        }
    }
    for v in [raw, v2].into_iter().filter(|s| !s.is_empty()) {
        if let Some(i) = text[lo..hi].find(v) {
            if text[lo..hi].matches(v).count() == 1 {
                return Some((lo + i, lo + i + v.len()));
            }
        }
    }
    let parts: Vec<_> =
        re!(r#"(?i)(?:postgres(?:ql)?|mongodb(?:\+srv)?|https?|ftps?)://[^\s"'<>\x60)]+"#)
            .find_iter(text)
            .collect();
    let line_parts: Vec<_> = parts
        .iter()
        .filter(|m| (lo..hi).contains(&m.start()))
        .collect();
    if let [m] = line_parts.as_slice() {
        return Some((m.start(), m.end()));
    }
    let wanted: Vec<_> = [raw, v2].iter().filter_map(|s| identity(s)).collect();
    let hits: Vec<_> = parts
        .iter()
        .filter(|m| identity(m.as_str()).is_some_and(|id| wanted.contains(&id)))
        .collect();
    if let [m] = hits.as_slice() {
        return Some((m.start(), m.end()));
    }
    if row["DetectorName"] == "URI" && !raw.is_empty() && raw == v2 {
        let quoted: Vec<_> = text[lo..hi]
            .match_indices(raw)
            .filter(|(i, _)| {
                let l = text[lo..lo + i].chars().next_back();
                let r = text[lo + i + raw.len()..hi].chars().next();
                matches!(l, Some('"' | '\'')) && l == r
            })
            .collect();
        if let [(i, _)] = quoted.as_slice() {
            return Some((lo + i, lo + i + raw.len()));
        }
    }
    None
}
pub fn scan(exe: &Path, files: &[Source]) -> Result<(Vec<BTreeSet<Span>>, usize, bool)> {
    let tmp = tempfile::Builder::new()
        .prefix("cred-ner-")
        .tempdir_in("/dev/shm")?;
    let mut ids = BTreeMap::<PathBuf, usize>::new();
    let mut expected = 0;
    for (i, src) in files.iter().enumerate() {
        let file = tmp.path().join(&src.name);
        fs::create_dir_all(file.parent().unwrap())?;
        fs::write(&file, src.text.as_bytes())?;
        ids.insert(file, i);
        let n = src.text.len();
        expected += n
            + (10240..n)
                .step_by(10240)
                .map(|p| (n - p).min(3072))
                .sum::<usize>();
    }
    let output = Command::new(exe)
        .current_dir("/dev/shm")
        .arg("filesystem")
        .arg(tmp.path())
        .args([
            "--concurrency",
            "1",
            "--no-verification",
            "--no-update",
            "--fail-on-scan-errors",
            "--json",
        ])
        .output()?;
    ensure!(output.status.success(), "TruffleHog failed");
    let stats = output
        .stderr
        .split(|&b| b == 10)
        .filter_map(|l| serde_json::from_slice::<Value>(l).ok())
        .find(|v| v["msg"] == "finished scanning")
        .context("missing scan statistics")?;
    ensure!(
        stats["trufflehog_version"] == "3.99.9",
        "unexpected TruffleHog version"
    );
    let mut spans = vec![BTreeSet::new(); files.len()];
    let mut unresolved = 0;
    for raw in output.stdout.split(|&b| b == 10).filter(|b| !b.is_empty()) {
        let row: Value = serde_json::from_slice(raw)?;
        let meta = &row["SourceMetadata"]["Data"]["Filesystem"];
        let Some(&i) = meta["file"].as_str().and_then(|p| ids.get(Path::new(p))) else {
            unresolved += 1;
            continue;
        };
        if let Some(span) = locate(&row, &files[i], meta["line"].as_u64().unwrap_or(0) as usize) {
            spans[i].insert(span);
        } else {
            unresolved += 1;
        }
    }
    Ok((
        spans,
        unresolved,
        stats["bytes"].as_u64() != Some(expected as u64),
    ))
}
