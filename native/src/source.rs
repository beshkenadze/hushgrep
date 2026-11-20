use crate::Span;
use anyhow::{Result, ensure};
use rustix::fs::{Mode, OFlags, openat};
use std::{
    ffi::OsStr,
    fs::File,
    io::Read,
    os::unix::ffi::OsStrExt,
    path::{Component, Path, PathBuf},
    process::Command,
};

pub const MAX: usize = 1024 * 1024;
pub struct Source {
    pub name: PathBuf,
    pub text: String,
    pub lines: Vec<usize>,
}
pub fn names(root: &Path) -> Result<Vec<PathBuf>> {
    let git = |args: &[&str]| -> Result<Vec<u8>> {
        let o = Command::new("git")
            .args(["-c", "core.fsmonitor=false", "-C"])
            .arg(root)
            .args(args)
            .output()?;
        ensure!(o.status.success(), "git inventory failed");
        Ok(o.stdout)
    };
    ensure!(
        git(&["rev-parse", "--show-prefix"])?
            .iter()
            .all(u8::is_ascii_whitespace)
            && git(&["rev-parse", "--is-inside-work-tree"])?.starts_with(b"true"),
        "expected Git root"
    );
    let raw = git(&[
        "ls-files",
        "-z",
        "--cached",
        "--others",
        "--exclude-standard",
    ])?;
    let mut paths: Vec<_> = raw
        .split(|&b| b == 0)
        .filter(|s| !s.is_empty())
        .map(|s| PathBuf::from(OsStr::from_bytes(s)))
        .collect();
    paths.sort_by(|a, b| a.as_os_str().as_bytes().cmp(b.as_os_str().as_bytes()));
    paths.dedup();
    Ok(paths)
}
pub fn lines(text: &str) -> Vec<usize> {
    let mut result = vec![0];
    let mut iter = text.char_indices().peekable();
    while let Some((i, c)) = iter.next() {
        if c == '\r' && iter.peek().is_some_and(|&(_, x)| x == '\n') {
            continue;
        }
        if matches!(
            c,
            '\n' | '\r' | '\x0b' | '\x0c' | '\x1c'..='\x1e' | '\u{85}' | '\u{2028}' | '\u{2029}'
        ) {
            result.push(i + c.len_utf8());
        }
    }
    if result.last() != Some(&text.len()) {
        result.push(text.len());
    }
    result
}
pub fn read(root: &File, name: PathBuf) -> Result<std::result::Result<Source, &'static str>> {
    let mut parts = name.components().peekable();
    let mut directory = root.try_clone()?;
    let mut buf = Vec::new();
    while let Some(part) = parts.next() {
        let Component::Normal(part) = part else {
            return Ok(Err("link_or_special"));
        };
        let mut flags = OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC;
        if parts.peek().is_some() {
            flags |= OFlags::DIRECTORY;
        }
        let child = match openat(&directory, part, flags, Mode::empty()) {
            Ok(fd) => File::from(fd),
            Err(rustix::io::Errno::NOENT) => return Ok(Err("missing")),
            Err(rustix::io::Errno::LOOP | rustix::io::Errno::NOTDIR | rustix::io::Errno::NXIO) => {
                return Ok(Err("link_or_special"));
            }
            Err(e) => return Err(e.into()),
        };
        if parts.peek().is_some() {
            directory = child;
            continue;
        }
        let meta = child.metadata()?;
        if !meta.is_file() {
            return Ok(Err("link_or_special"));
        }
        if meta.len() > MAX as u64 {
            return Ok(Err("large"));
        }
        child.take(MAX as u64 + 1).read_to_end(&mut buf)?;
        if buf.len() > MAX {
            return Ok(Err("large"));
        }
    }
    if buf.contains(&0) {
        return Ok(Err("binary_or_encoding"));
    }
    let Ok(text) = String::from_utf8(buf) else {
        return Ok(Err("binary_or_encoding"));
    };
    let lines = lines(&text);
    if lines.windows(2).any(|w| {
        text[w[0]..w[1]]
            .trim_end_matches([
                '\n', '\r', '\x0b', '\x0c', '\x1c', '\x1d', '\x1e', '\u{85}', '\u{2028}',
                '\u{2029}',
            ])
            .chars()
            .count()
            > 4096
    }) {
        return Ok(Err("long_line"));
    }
    Ok(Ok(Source { name, text, lines }))
}
impl Source {
    pub fn line(&self, byte: usize) -> usize {
        self.lines.partition_point(|&s| s <= byte) - 1
    }
    pub fn context(&self, a: usize, b: usize) -> Span {
        (
            self.lines[self.line(a).saturating_sub(2)],
            self.lines[(self.line(b - 1) + 3).min(self.lines.len() - 1)],
        )
    }
}
