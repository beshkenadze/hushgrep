use crate::{Span, source::Source};
use base64::{
    Engine,
    engine::general_purpose::{STANDARD, STANDARD_NO_PAD},
};
use percent_encoding::percent_decode_str;
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Copy, PartialEq)]
pub enum Carrier {
    Uri,
    Encoded,
    Userinfo,
    Encoder,
}
pub fn decoded_basic(token: &str) -> Option<Vec<u8>> {
    let bytes = if token.contains('=') {
        STANDARD.decode(token)
    } else {
        STANDARD_NO_PAD.decode(token)
    }
    .ok()?;
    if bytes.iter().any(|&b| b < 32 || b == 127) {
        return None;
    }
    let colon = bytes.iter().position(|&b| b == b':')?;
    (colon + 1 < bytes.len()).then(|| bytes[colon + 1..].to_vec())
}
fn dynamic(s: &str) -> bool {
    re!(r"\$\{|#\{|\{[^}]*\}|\$[A-Za-z_]\w*|\\").is_match(s)
        || re!(r"%[sd]").find_iter(s).any(|m| {
            !s[m.end()..]
                .as_bytes()
                .first()
                .is_some_and(u8::is_ascii_hexdigit)
        })
}
fn bad_escape(s: &str) -> bool {
    s.bytes().enumerate().any(|(i, b)| {
        b == b'%'
            && !s
                .as_bytes()
                .get(i + 1..i + 3)
                .is_some_and(|x| x.iter().all(u8::is_ascii_hexdigit))
    })
}
pub struct Parsed {
    pub pairs: BTreeMap<Span, Carrier>,
    masks: Vec<(Span, Span)>,
}
impl Parsed {
    pub fn new(text: &str) -> Self {
        let mut result = Self {
            pairs: BTreeMap::new(),
            masks: vec![],
        };
        let authority = re!(
            r#"(?i)(?:(?:[a-z][a-z0-9+.\-]*):)?//(?P<user>[^\s/?#@:\\"'\x60<>{}\[\]]*):(?P<pw>[^\s/?#@\\"'\x60<>{}\[\]]+)@(?P<host>\[[0-9a-f:.%]+\]|[\w.%-]+)(?::(?P<port>\d+))?"#
        );
        for c in authority.captures_iter(text) {
            let m = c.get(0).unwrap();
            let p = c.name("pw").unwrap();
            let mut start = m.start();
            if !m.as_str().starts_with("//")
                && text[..start]
                    .chars()
                    .next_back()
                    .is_some_and(|x| x.is_alphanumeric() || "_+.-".contains(x))
            {
                start += m.as_str().find("//").unwrap();
            }
            let uri = &text[start..m.end()];
            if dynamic(uri)
                || bad_escape(uri)
                || c.name("port")
                    .is_some_and(|p| p.as_str().parse::<u16>().is_err())
            {
                continue;
            }
            let host = c.name("host").unwrap().as_str();
            if host.starts_with('[')
                && host[1..host.len() - 1]
                    .split('%')
                    .next()
                    .unwrap()
                    .parse::<std::net::Ipv6Addr>()
                    .is_err()
            {
                continue;
            }
            let span = (p.start(), p.end());
            result.pairs.insert(span, Carrier::Uri);
            if re!(r"(?i-u)^(?:\*{3,}|redacted|\[redacted\]|<redacted>)$")
                .is_match(&percent_decode_str(p.as_str()).decode_utf8_lossy())
            {
                result.masks.push((span, (start, m.end())));
            }
        }
        let literals = re!(
            r#"(?:"(?:\\[^\r\n]|[^"\\\r\n])*"|'(?:\\[^\r\n]|[^'\\\r\n])*'|\x60(?:\\[^\r\n]|[^\x60\\\r\n])*\x60)"#
        );
        for m in literals.find_iter(text) {
            let body = &text[m.start() + 1..m.end() - 1];
            if let Some(c) =
                re!(r"(?i)^\s*Basic[ \t]+([A-Za-z0-9+/]+={0,2})[ \t]*\z").captures(body)
            {
                let v = c.get(1).unwrap();
                if decoded_basic(v.as_str()).is_some() {
                    result.pairs.insert(
                        (m.start() + 1 + v.start(), m.start() + 1 + v.end()),
                        Carrier::Encoded,
                    );
                }
            }
            let Some((user, pw)) = body.split_once(':') else {
                continue;
            };
            if pw.is_empty() || dynamic(body) || body.bytes().any(|b| b < 32) {
                continue;
            }
            let prefix = &text[..m.start()];
            let prefix = &prefix[prefix.char_indices().rev().nth(383).map_or(0, |x| x.0)..];
            let kind=if re!(r"(?i)(?:\b(?:setUserInfo|with_userinfo)\s*\(\s*|\bgetUserInfo\s*\(\s*\)\s*(?:->|\.)\s*(?:willReturn|toEqual|toBe)\s*\(\s*|\buserinfo\s*[:=]\s*)\z").is_match(prefix) {Carrier::Userinfo}
            else if let Some(enc)=re!(r"(?:\b(?:base64_encode|(?:base64\.)?b64encode|btoa|Buffer\.from)\s*\(\s*[bB]?|\bbase64\.(?:StdEncoding|RawStdEncoding)\.EncodeToString\s*\(\s*\[\]byte\s*\(\s*)\z").find(prefix) {
                if !re!(r#"(?i)(?:['"]\s*Basic\s+['"]\s*(?:[.+]|<<)\s*\(*\s*|\bbasic(?:Scheme)?\s*\+\s*['"] ['"]\s*\+\s*\(*\s*)\z"#).is_match(&prefix[..enc.start()]) {continue;}
                Carrier::Encoder
            } else {continue;};
            result
                .pairs
                .insert((m.start() + 1 + user.len() + 1, m.end() - 1), kind);
        }
        result
    }
    pub fn accept(&self, src: &Source, proposals: BTreeSet<Span>) -> BTreeSet<Span> {
        proposals
            .into_iter()
            .chain(self.pairs.keys().copied())
            .filter(|&(a, b)| {
                if self
                    .masks
                    .iter()
                    .any(|&((x, y), whole)| (a >= x && b <= y) || (a, b) == whole)
                {
                    return false;
                }
                let (lo, hi) = src.context(a, b);
                common(&src.text[lo..hi], a - lo, b - lo)
            })
            .collect()
    }
}
fn structural(text: &str, a: usize, b: usize) -> bool {
    let Some(c)=re!(r"^(?P<s>jdbc:(?:mysql|mariadb|postgresql)|postgres(?:ql)?)://(?:(?P<u>[\w.-]+)@)?(?P<h>[\w.-]+)(?::(?P<p>[A-Za-z0-9]+))?(?P<path>/[\w.%/-]*)?(?:\?(?P<q>[^#;\s]+))?\z").captures(text) else{return false;};
    let mut keys = BTreeSet::new();
    let mut example = false;
    let mut session = false;
    if let Some(q) = c.name("q") {
        if q.as_str().split('&').any(|s| !s.contains('=')) {
            return false;
        }
        for (k, v) in url::form_urlencoded::parse(q.as_str().as_bytes()) {
            if !keys.insert(k.to_string()) {
                return false;
            }
            let valid = match k.as_ref() {
                "user" => re!(r"^[\w.-]+\z").is_match(&v),
                "autoReconnect" | "tcpKeepAlive" => {
                    matches!(v.to_ascii_lowercase().as_str(), "true" | "false")
                }
                "hostaddr" => re!(r"^(?:\d{1,3}\.){3}\d{1,3}\z").is_match(&v),
                "zeroDateTimeBehavior" => v == "convertToNull",
                "connectionCollation" => re!(r"^\w+_(?:ci|cs|bin)\z").is_match(&v),
                "sessionVariables" => {
                    session=re!(r"^sql_mode='(?:IGNORE_SPACE|ANSI)(?:,(?:IGNORE_SPACE|ANSI))*',FOREIGN_KEY_CHECKS=[01]\z").is_match(&v);
                    session
                }
                "key" => {
                    example = v == "value";
                    example
                }
                _ => false,
            };
            if !valid {
                return false;
            }
        }
    }
    let is = |name: &str| c.name(name).is_some_and(|m| (a, b) == (m.start(), m.end()));
    if c["s"].starts_with("jdbc:") {
        return is("p")
            || (a == 0 && b == text.len() && !session && !example && keys.contains("user"));
    }
    is("u")
        || c.name("u")
            .is_some_and(|u| (a, b) == (u.start(), c.name("h").unwrap().end()))
        || c.name("path").is_some_and(|p| {
            (a, b) == (p.start() + 1, p.end())
                && re!(r"^[\w/-]+\z").is_match(&percent_decode_str(p.as_str()).decode_utf8_lossy())
        })
}
fn common(t: &str, a: usize, b: usize) -> bool {
    let value = &t[a..b];
    let before = &t[..a];
    if re!(r"(?i)\bsha(?:256|384|512)[:-]\z").is_match(before) {
        return false;
    }
    if ["jdbc:mysql://", "jdbc:postgresql://", "jdbc:mariadb://"]
        .iter()
        .any(|k| t.starts_with(k))
    {
        if let Ok(u) = url::Url::parse(&t[5..]) {
            let options: Vec<_> = u.query_pairs().collect();
            if u.username().is_empty()
                && u.password().is_none()
                && !options.is_empty()
                && options
                    .iter()
                    .all(|(k, _)| matches!(k.to_ascii_lowercase().as_str(), "user" | "notpassword"))
            {
                return false;
            }
        }
    }
    if re!(r"(?i)^(?:x{4,}|changeme)\z").is_match(value)
        && re!(r#"(?i)\b(?:password|pwd)\s*=\s*[{"']?\z"#).is_match(before)
    {
        return false;
    }
    if re!(
        r#"(?i)^\s*["']?aws_secret_(?:access_)?key["']?\s*[:=]\s*["']?([A-Za-z0-9/+=]+)["']?\s*\z"#
    )
    .captures(t)
    .is_some_and(|c| c[1].len() != 40)
    {
        return false;
    }
    if structural(t, a, b) {
        return false;
    }
    if t.starts_with("jdbc:pgsql://")
        && (a == 0 || a >= "jdbc:pgsql://".len())
        && structural(
            &t.replacen("jdbc:pgsql://", "jdbc:postgresql://", 1),
            if a == 0 { 0 } else { a + 5 },
            b + 5,
        )
    {
        return false;
    }
    if a == 0
        && b == t.len()
        && re!(r"^jdbc:(?:mysql|postgresql|mariadb)://[\w.-]+(?::\d+)?/[\w.-]+\z").is_match(t)
    {
        return false;
    }
    if !t.starts_with("postgres://") && !t.starts_with("postgresql://") {
        return true;
    }
    if let Some(c) =
        re!(r"^postgres(?:ql)?://([\w.-]+)@(?::\d+)?(?:/[\w.-]*)?\?host=/[\w./-]+\z").captures(t)
    {
        let u = c.get(1).unwrap();
        if (a, b) == (u.start(), u.end()) {
            return false;
        }
    }
    if let Some(c) = re!(r"^postgres(?:ql)?://(%2[fF][A-Za-z0-9%._-]+)/([\w.-]+)\z").captures(t) {
        let x = c.get(2).unwrap();
        if (a, b) == (x.start(), x.end())
            && re!(r"^/[\w./-]+\z").is_match(&percent_decode_str(&c[1]).decode_utf8_lossy())
        {
            return false;
        }
    }
    if let Some(c) = re!(
        r"^postgres(?:ql)?://[\w.-]+(?:/[\w.-]*)?\?((?:[\w%.-]+=[\w.-]*)(?:&[\w%.-]+=[\w.-]*)*)\z"
    )
    .captures(t)
    {
        let q = c.get(1).unwrap();
        let mut i = q.start();
        for item in q.as_str().split('&') {
            let (key, val) = item.split_once('=').unwrap();
            let eq = i + key.len();
            if val.is_empty() && (a, b) == (i, eq)
                || !val.is_empty()
                    && (a, b) == (eq + 1, eq + 1 + val.len())
                    && percent_decode_str(key).decode_utf8_lossy() == "user"
            {
                return false;
            }
            i += item.len() + 1;
        }
    }
    true
}
