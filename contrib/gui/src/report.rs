//! The `netdoc --json` report (schema/report-v1.schema.json in Network Doctor).
//! Every field is optional or defaulted: the schema is additive within v1.

use serde::Deserialize;
use std::collections::BTreeMap;

#[derive(Clone, Debug, Default, Deserialize)]
pub struct Report {
    pub target: Option<Target>,
    #[serde(default)]
    pub checks: Vec<Check>,
    #[serde(default)]
    pub summary: String,
    #[serde(default)]
    pub verdict: String,
    #[serde(default)]
    pub ok: bool,
    pub failed_stage: Option<String>,
    #[serde(default)]
    pub findings: Vec<Finding>,
}

#[derive(Clone, Debug, Default, Deserialize)]
pub struct Target {
    #[serde(default)]
    pub host: String,
}

#[derive(Clone, Debug, Default, Deserialize)]
pub struct Check {
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub status: String,
    #[serde(default)]
    pub ms: u64,
    #[serde(default)]
    pub detail: String,
    pub cause: Option<String>,
    pub fix: Option<String>,
    #[serde(default)]
    pub addrs: Vec<String>,
    pub address_families: Option<BTreeMap<String, String>>,
    pub network: Option<String>,
    pub portal: Option<Portal>,
    /// Plain-language title and sentence, worked out once in `parse`.
    #[serde(skip)]
    pub title: String,
    #[serde(skip)]
    pub says: String,
}

#[derive(Clone, Debug, Default, Deserialize)]
pub struct Portal {
    pub redirect_url: Option<String>,
}

#[derive(Clone, Debug, Default, Deserialize)]
pub struct Finding {
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub confidence: String,
    pub remediation: Option<Remediation>,
    /// The observations behind the diagnosis, for the "Why?" view.
    #[serde(default)]
    pub causal_evidence: Vec<Evidence>,
}

#[derive(Clone, Debug, Default, Deserialize)]
pub struct Evidence {
    #[serde(default)]
    pub kind: String,
    #[serde(default)]
    pub check: String,
    pub observation: Option<String>,
    /// The other explanation this item rules out or weakens.
    pub candidate: Option<String>,
    pub reason: Option<String>,
    pub value: Option<serde_json::Value>,
}

/// `netdoc --profile NAME --json`: one ordinary report per part of a service.
#[derive(Clone, Debug, Default, Deserialize)]
pub struct ProfileReport {
    #[serde(default)]
    pub title: String,
    #[serde(default)]
    pub components: Vec<Component>,
    #[serde(default)]
    pub aggregate: Aggregate,
}

#[derive(Clone, Debug, Default, Deserialize)]
pub struct Component {
    #[serde(default)]
    pub label: String,
    pub target: Option<Target>,
    #[serde(default)]
    pub status: String,
    pub report: Option<Report>,
}

#[derive(Clone, Debug, Default, Deserialize)]
pub struct Aggregate {
    #[serde(default)]
    pub status: String,
    #[serde(default)]
    pub summary: String,
}

impl Component {
    /// PASS is working, WARN is working with a problem; FAIL and SKIP both
    /// mean this part isn't available.
    pub fn tone(&self) -> Tone {
        match self.status.as_str() {
            "PASS" => Tone::Good,
            "WARN" => Tone::Warn,
            _ => Tone::Bad,
        }
    }

    pub fn word(&self) -> &'static str {
        match self.status.as_str() {
            "PASS" => "Working",
            "WARN" => "Working, with a problem",
            _ => "Not working",
        }
    }
}

impl Report {
    /// The verdict to show. netdoc clears `ok` for a FAIL or a check with no
    /// result, so verdict "ok" with `ok` false means a check never reported:
    /// that is shown as incomplete, never as healthy.
    pub fn shown_verdict(&self) -> &str {
        if self.verdict == "ok" && !self.ok {
            "incomplete"
        } else {
            &self.verdict
        }
    }

    /// Only a clean run is healthy. A WARN keeps netdoc's `ok` true, so `ok`
    /// alone is not enough.
    pub fn healthy(&self) -> bool {
        self.shown_verdict() == "ok"
    }
}

/// What one run of netdoc produced.
#[derive(Clone, Debug)]
pub enum Outcome {
    Single(Report),
    Profile(ProfileReport),
}

impl Outcome {
    pub fn ok(&self) -> bool {
        match self {
            Outcome::Single(r) => r.healthy(),
            // A profile is "ok" when anything works; only all-PASS is trouble-free.
            Outcome::Profile(p) => p.aggregate.status == "PASS",
        }
    }

    pub fn summary(&self) -> &str {
        match self {
            Outcome::Single(r) => &r.summary,
            Outcome::Profile(p) => &p.aggregate.summary,
        }
    }

    pub fn tone(&self) -> Tone {
        match self {
            Outcome::Single(r) => verdict_text(r.shown_verdict()).2,
            Outcome::Profile(p) => match p.aggregate.status.as_str() {
                "PASS" => Tone::Good,
                "WARN" => Tone::Warn,
                _ => Tone::Bad,
            },
        }
    }

    /// The short word for the header pill.
    pub fn pill(&self) -> &'static str {
        match self {
            Outcome::Single(r) => match r.shown_verdict() {
                "ok" => "Online",
                "degraded" => "Working, with a problem",
                "dns" => "Names don't work",
                "network" => "Can't get out",
                "service" => "The site has a problem",
                _ => "No answer yet",
            },
            Outcome::Profile(p) => match p.aggregate.status.as_str() {
                "PASS" => "All working",
                "WARN" => "Partly working",
                _ => "Not working",
            },
        }
    }

    /// The part to open first: the first one with a problem.
    pub fn first_problem(&self) -> usize {
        match self {
            Outcome::Single(_) => 0,
            Outcome::Profile(p) => p
                .components
                .iter()
                .position(|c| c.status != "PASS")
                .unwrap_or(0),
        }
    }

    /// The step-by-step report to show: the only one, or the chosen part's.
    pub fn detail(&self, part: usize) -> Option<&Report> {
        match self {
            Outcome::Single(r) => Some(r),
            Outcome::Profile(p) => p.components.get(part)?.report.as_ref(),
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize)]
pub struct Remediation {
    #[serde(default)]
    pub action: String,
    pub why: Option<String>,
    #[serde(default)]
    pub steps: Vec<String>,
    /// An argv array. netdoc never runs it, and neither do we.
    #[serde(default)]
    pub command: Vec<String>,
    pub expect: Option<String>,
}

const BAD_OUTPUT: &str = "netdoc's output wasn't a report this app understands";

/// Either kind of report netdoc prints with `--json`.
pub fn parse(json: &str) -> Result<Outcome, String> {
    let mut v: serde_json::Value =
        serde_json::from_str(json).map_err(|e| format!("{BAD_OUTPUT}: {e}"))?;
    clean_strings(&mut v)?;
    if v.get("schema")
        .and_then(|s| s.as_str())
        .is_some_and(|s| s.starts_with("netdoc.profile-report."))
    {
        require(
            &v,
            "a profile report",
            &["title", "components", "aggregate"],
        )?;
        require(&v["aggregate"], "the aggregate", &["status", "summary"])?;
        for c in v["components"].as_array().into_iter().flatten() {
            require(c, "a component", &["label", "status"])?;
            if let Some(r) = c.get("report").filter(|r| !r.is_null()) {
                validate_report(r)?;
            }
        }
        let mut p: ProfileReport =
            serde_json::from_value(v).map_err(|e| format!("{BAD_OUTPUT}: {e}"))?;
        for c in &mut p.components {
            if let Some(r) = &mut c.report {
                finish(r);
            }
        }
        return Ok(Outcome::Profile(p));
    }
    validate_report(&v)?;
    let mut r: Report = serde_json::from_value(v).map_err(|e| format!("{BAD_OUTPUT}: {e}"))?;
    finish(&mut r);
    Ok(Outcome::Single(r))
}

/// Cleans every string and every object key in a report, once, where netdoc
/// output enters the window: no escapes, invisible or direction-changing
/// characters. Line breaks are kept, and nothing else is rewritten. Two keys
/// that clean to the same name make the report unreadable, so it is rejected
/// rather than letting one silently replace the other.
fn clean_strings(v: &mut serde_json::Value) -> Result<(), String> {
    match v {
        serde_json::Value::String(s) => *s = clean_lines(s),
        serde_json::Value::Array(a) => a.iter_mut().try_for_each(clean_strings)?,
        serde_json::Value::Object(o) => {
            let mut cleaned = serde_json::Map::new();
            for (key, mut value) in std::mem::take(o) {
                clean_strings(&mut value)?;
                let key = clean_lines(&key);
                if cleaned.insert(key.clone(), value).is_some() {
                    return Err(format!("{BAD_OUTPUT}: two keys read as \"{key}\""));
                }
            }
            *o = cleaned;
        }
        _ => {}
    }
    Ok(())
}

/// Fails unless `v` has each key. The keys are the schema's required fields
/// (schema/report-v1.schema.json): a report missing one is rejected rather than
/// shown with defaults. A null is present, so it passes.
fn require(v: &serde_json::Value, what: &str, keys: &[&str]) -> Result<(), String> {
    match keys.iter().find(|k| v.get(**k).is_none()) {
        Some(k) => Err(format!("{BAD_OUTPUT}: {what} has no \"{k}\"")),
        None => Ok(()),
    }
}

/// The required fields of an ordinary report and of the objects inside it.
fn validate_report(v: &serde_json::Value) -> Result<(), String> {
    require(
        v,
        "a report",
        &["version", "target", "checks", "summary", "verdict", "ok"],
    )?;
    if let Some(t) = v.get("target").filter(|t| !t.is_null()) {
        require(t, "a target", &["host", "port", "protocol"])?;
    }
    for c in v["checks"].as_array().into_iter().flatten() {
        require(c, "a check", &["id", "name", "status", "ms", "detail"])?;
    }
    for f in v["findings"].as_array().into_iter().flatten() {
        require(f, "a finding", &["id"])?;
        if let Some(r) = f.get("remediation").filter(|r| !r.is_null()) {
            require(r, "a remediation", &["id", "action"])?;
        }
        for e in f["causal_evidence"].as_array().into_iter().flatten() {
            require(e, "a piece of evidence", &["kind", "check"])?;
        }
    }
    Ok(())
}

/// An ordinary (non-profile) report.
#[cfg(test)]
pub fn parse_report(json: &str) -> Result<Report, String> {
    match parse(json)? {
        Outcome::Single(r) => Ok(r),
        Outcome::Profile(_) => Err("expected an ordinary report".into()),
    }
}

/// The plain-language text, worked out once so the window doesn't rebuild it every frame.
fn finish(r: &mut Report) {
    let host = r.target.as_ref().map(|t| t.host.clone());
    for c in &mut r.checks {
        c.title = step_title(c, host.as_deref());
        c.says = step_says(c, host.as_deref());
    }
}

fn words(id: &str) -> String {
    id.replace('_', " ")
}

/// The evidence behind a finding, as sentences in four groups.
#[derive(Default, Debug, PartialEq)]
pub struct Why {
    pub supports: Vec<String>,
    pub ruled_out: Vec<String>,
    pub weakened: Vec<String>,
    pub unchecked: Vec<String>,
}

/// What a check observed, as the end of a sentence ("… passed").
fn observed(e: &Evidence, check: Option<&Check>) -> String {
    let value = e.value.as_ref().and_then(|v| v.as_str()).unwrap_or("");
    let with = |text: &str| {
        if value.is_empty() {
            text.to_string()
        } else {
            format!("{text} ({value})")
        }
    };
    match e.observation.as_deref().unwrap_or("") {
        "status_pass" => "passed".into(),
        "status_warn" => "gave a warning".into(),
        "status_fail" => "failed".into(),
        "status_skip" => "was skipped".into(),
        "status_not_applicable" => "didn't apply".into(),
        "cause" => match check.and_then(|c| c.cause.as_deref()) {
            Some(c) => format!("failed: {}", words(c)),
            None => "reported a specific cause".into(),
        },
        "dns_answers" => with("returned addresses"),
        "dns_not_found" => "said the name doesn't exist".into(),
        "captive_portal" => "saw a sign-in page in the way".into(),
        "timeout" => "timed out".into(),
        "clock_offset" => "found this computer's clock is off".into(),
        "status_downgraded" => "failed, but another path got through".into(),
        "family_reachable" => with("works"),
        "family_failed" => with("fails"),
        "address_succeeded" => with("connected"),
        "address_failed" => with("couldn't connect"),
        "" => "was looked at".into(),
        other => with(&format!("saw: {}", words(other))),
    }
}

/// The alternative explanations netdoc names, in plain words.
fn candidate(id: &str) -> String {
    match id {
        "offline" => "You're offline".into(),
        "tls_tcp_unreachable" => "The server can't be reached at all".into(),
        "local_device_unreachable" => "The device is off or gone".into(),
        "target_unreachable" => "The server can't be reached".into(),
        "dns_failure" => "Names (DNS) are broken".into(),
        "captive_portal" => "A sign-in page is in the way".into(),
        "tls_clock_skew" => "This computer's clock is wrong".into(),
        other => {
            let w = words(other);
            let mut c = w.chars();
            c.next()
                .map(|f| f.to_uppercase().collect::<String>() + c.as_str())
                .unwrap_or(w)
        }
    }
}

pub fn why(f: &Finding, r: &Report) -> Why {
    let mut w = Why::default();
    for e in &f.causal_evidence {
        let check = r.checks.iter().find(|c| c.id == e.check);
        let title = check
            .map(|c| c.title.clone())
            .filter(|t| !t.is_empty())
            .unwrap_or_else(|| words(&e.check));
        let saw = observed(e, check);
        let other = e
            .candidate
            .as_deref()
            .map(candidate)
            .unwrap_or_else(|| "Another cause".into());
        match e.kind.as_str() {
            "support" => w.supports.push(format!("\"{title}\" {saw}.")),
            "ruled_out" => w
                .ruled_out
                .push(format!("{other}: no, because \"{title}\" {saw}.")),
            "contradiction" => w
                .weakened
                .push(format!("{other}: less likely, because \"{title}\" {saw}.")),
            "not_evaluated" => {
                let reason = match e.reason.as_deref().unwrap_or("") {
                    "prerequisite_failed" => "an earlier step failed first",
                    "not_selected" => "it wasn't part of this run",
                    "not_applicable" => "it doesn't apply here",
                    "incomplete" => "it didn't finish",
                    _ => "no result",
                };
                w.unchecked.push(format!("\"{title}\": {reason}."));
            }
            _ => {}
        }
    }
    w
}

/// What each confidence level claims, from Network Doctor's reference.
pub fn confidence_means(c: &str) -> &'static str {
    match c {
        "high" => {
            "A check saw the exact thing that separates this from the other explanations, and nothing relevant is left open."
        }
        "medium" => {
            "This is the best explanation the checks support, but something is still open: another cause wasn't fully excluded, or one thing couldn't be checked."
        }
        "low" => "The checks show where it breaks, but not why. Several causes still fit.",
        _ => "There isn't enough evidence to name a cause.",
    }
}

#[derive(Clone, Copy, PartialEq, Debug)]
pub enum Tone {
    Good,
    Warn,
    Bad,
    Muted,
}

/// Headline and explanation for each verdict, from the reference's verdict table.
pub fn verdict_text(v: &str) -> (&'static str, &'static str, Tone) {
    match v {
        "ok" => ("Everything works", "Every check passed.", Tone::Good),
        "degraded" => (
            "Working, with a problem",
            "Everything you asked for works, but part of the path is impaired, for example high latency or a proxy-only network.",
            Tone::Warn,
        ),
        "dns" => (
            "The name doesn't resolve",
            "Your computer couldn't turn the name into an address. That's DNS, not the connection itself.",
            Tone::Bad,
        ),
        "network" => (
            "Your connection is the problem",
            "The path is unavailable: the link is down, there's no way off the network, or the target can't be reached and nothing else proves the network works.",
            Tone::Bad,
        ),
        "service" => (
            "Your connection is fine, the other end isn't",
            "The internet is reachable from here, but the site or service itself refused or failed.",
            Tone::Bad,
        ),
        "incomplete" => (
            "The checks didn't finish",
            "At least one check never got a result, so there's no conclusion yet.",
            Tone::Muted,
        ),
        _ => (
            "Unknown result",
            "This version of netdoc returned a verdict this app doesn't know yet.",
            Tone::Muted,
        ),
    }
}

/// The headline and explanation for a report, the one place the GUI decides
/// what a result says. Only a healthy report gets "Everything checks out".
pub fn headline(r: &Report) -> (&'static str, &'static str, Tone) {
    let (head, explain, tone) = verdict_text(r.shown_verdict());
    if r.healthy() {
        ("Everything checks out.", explain, tone)
    } else {
        (head, explain, tone)
    }
}

pub fn status_tone(s: &str) -> Tone {
    match s {
        "PASS" => Tone::Good,
        "WARN" => Tone::Warn,
        "FAIL" | "INCOMPLETE" => Tone::Bad,
        _ => Tone::Muted,
    }
}

pub fn status_word(s: &str) -> &'static str {
    match s {
        "PASS" => "OK",
        "WARN" => "Warning",
        "FAIL" => "Failed",
        "SKIP" => "Skipped",
        "N/A" => "Not needed",
        "INCOMPLETE" => "Didn't finish",
        _ => "?",
    }
}

pub fn confidence_word(c: &str) -> &'static str {
    match c {
        "high" => "High confidence",
        "medium" => "Medium confidence",
        "low" => "Low confidence",
        _ => "Confidence unknown",
    }
}

/// Text that is safe to put on the clipboard: no control characters
/// (terminal escapes, line breaks a paste would act on) and no invisible
/// formatting characters (bidi overrides that make text read differently
/// from what it is). netdoc already does this; this is a second layer in
/// case a different netdoc is used.
pub fn clean(s: &str) -> String {
    s.chars()
        .filter(|&c| {
            let bidi_or_invisible = matches!(c,
                '\u{00AD}' | '\u{061C}' | '\u{180E}' | '\u{200B}'..='\u{200F}' | '\u{2028}'..='\u{202E}' |
                '\u{2060}'..='\u{2069}' | '\u{FEFF}' | '\u{FFF9}'..='\u{FFFB}');
            !c.is_control() && !bidi_or_invisible
        })
        .collect()
}

/// `clean`, keeping line breaks: for the multi-line "Copy report".
pub fn clean_lines(s: &str) -> String {
    s.lines().map(clean).collect::<Vec<_>>().join("\n")
}

/// Shell-quote an argv array so the user can paste it into a terminal.
pub fn shell_line(argv: &[String]) -> String {
    argv.iter()
        .map(|a| clean(a))
        .map(|a| {
            if !a.is_empty()
                && a.chars()
                    .all(|c| c.is_ascii_alphanumeric() || "-_./:=@%+,".contains(c))
            {
                a
            } else {
                format!("'{}'", a.replace('\'', "'\\''"))
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

/// net-watch-style step names: what the step proves, in plain words.
pub fn step_title(c: &Check, host: Option<&str>) -> String {
    let host = host.unwrap_or("the site");
    match c.id.as_str() {
        "iface" => "Connected to a network".into(),
        "ssid" => "Wi-Fi network".into(),
        "internet_tcp" => "Reaches the internet".into(),
        "quic_udp_443" => "Fast web connections (HTTP/3)".into(),
        "proxy_connect" => "Proxy".into(),
        "dns" => "Names work (DNS)".into(),
        "dns_public" => "Second opinion on names".into(),
        "dns_encrypted" => "Private DNS (encrypted)".into(),
        "target_tcp" => format!("Reaches {host}"),
        "path_mtu" => "Large data gets through".into(),
        "tls" => "Secure connection is valid".into(),
        "http" => format!("{host} answers"),
        "https" => format!("{host} answers securely"),
        "ssh_banner" => format!("{host} answers SSH"),
        "smtp_banner" => format!("{host} answers as a mail server"),
        _ => c.name.clone(),
    }
}

/// One sentence for the step, like net-watch's: what was found.
pub fn step_says(c: &Check, host: Option<&str>) -> String {
    let host = host.unwrap_or("the site");
    let ms = |t: &str| {
        if c.ms > 1 {
            format!("{t} ({} ms).", c.ms)
        } else {
            format!("{t}.")
        }
    };
    match c.status.as_str() {
        "SKIP" => return "Skipped: an earlier step failed.".into(),
        "N/A" => {
            return match c.id.as_str() {
                "proxy_connect" => "No proxy is set up, so there's nothing to check.".into(),
                "dns" | "dns_public" => "Not needed: the target is an address, not a name.".into(),
                _ => "Doesn't apply here.".into(),
            };
        }
        "INCOMPLETE" => return "Didn't finish.".into(),
        "PASS" => {}
        // Problems: netdoc's own fix line is the most useful sentence.
        _ => {
            return c
                .fix
                .clone()
                .filter(|f| !f.is_empty())
                .unwrap_or_else(|| c.detail.clone());
        }
    }
    match c.id.as_str() {
        "iface" => "Your network adapter is up.".into(),
        "ssid" => match &c.network {
            Some(n) => format!("On Wi-Fi \"{n}\"."),
            None => "On Wi-Fi.".into(),
        },
        "internet_tcp" => {
            let fams = c
                .address_families
                .as_ref()
                .map(|f| {
                    f.iter()
                        .filter(|(_, v)| v.as_str() == "reachable")
                        .map(|(k, _)| k.to_uppercase().replace("IPV", "IPv"))
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();
            if fams.is_empty() {
                ms("Reaches the internet")
            } else {
                format!("Reaches the internet over {}.", fams.join(" and "))
            }
        }
        "quic_udp_443" => "Newer, faster web connections get through.".into(),
        "proxy_connect" => "The proxy carries traffic.".into(),
        "dns" => ms("Names turn into addresses"),
        "dns_public" => "A public DNS server was asked too, as a second opinion.".into(),
        "dns_encrypted" => "Encrypted DNS works, if you want to use it.".into(),
        "target_tcp" => ms(&format!("Connects to {host}")),
        "path_mtu" => "Big pieces of data arrive without being dropped.".into(),
        "tls" => "The certificate is valid and the connection is encrypted.".into(),
        "http" => format!("{host} answers on plain HTTP."),
        "https" => format!("{host} answers on HTTPS."),
        "ssh_banner" => "The SSH server introduced itself.".into(),
        "smtp_banner" => "The mail server introduced itself.".into(),
        _ => c.detail.clone(),
    }
}

/// The whole result as text, for "Copy report".
pub fn as_text(r: &Report) -> String {
    let host = r.target.as_ref().map(|t| t.host.as_str());
    let (head, _, _) = headline(r);
    let mut s = format!("Network Doctor: {head}\n{}\n", r.summary);
    for f in &r.findings {
        if let Some(rem) = &f.remediation {
            s += &format!(
                "\nWhat to do ({}, {}): {}\n",
                confidence_word(&f.confidence).to_lowercase(),
                f.id,
                rem.action
            );
            for (i, step) in rem.steps.iter().enumerate() {
                s += &format!("  {}. {step}\n", i + 1);
            }
        }
    }
    s += "\nStep by step:\n";
    for c in &r.checks {
        s += &format!(
            "  [{}] {}: {}\n",
            status_word(&c.status),
            step_title(c, host),
            step_says(c, host)
        );
    }
    clean_lines(&s)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn load(name: &str) -> Report {
        let p = format!("{}/tests/fixtures/{name}.json", env!("CARGO_MANIFEST_DIR"));
        parse_report(&std::fs::read_to_string(p).unwrap()).unwrap()
    }

    #[test]
    fn healthy_target() {
        let r = load("healthy");
        assert!(r.ok);
        assert_eq!(r.verdict, "ok");
        assert_eq!(r.target.unwrap().host, "github.com");
        assert!(r.findings.is_empty());
        assert!(
            r.checks
                .iter()
                .all(|c| c.status == "PASS" || c.status == "N/A")
        );
        let known = [
            "iface",
            "ssid",
            "internet_tcp",
            "quic_udp_443",
            "proxy_connect",
            "dns",
            "dns_public",
            "dns_encrypted",
            "target_tcp",
            "path_mtu",
            "tls",
            "http",
            "https",
        ];
        for c in &r.checks {
            assert!(
                known.contains(&c.id.as_str()),
                "no plain title for {}",
                c.id
            );
        }
    }

    #[test]
    fn degraded_is_not_healthy() {
        // netdoc keeps ok for a WARN; only a FAIL or an unreported check clears it.
        let r = load("degraded");
        assert!(r.ok);
        let o = Outcome::Single(r.clone());
        assert!(!o.ok(), "a degraded verdict must not count as healthy");
        assert_eq!(o.tone(), Tone::Warn);
        assert_eq!(headline(&r).0, "Working, with a problem");
        assert_eq!(headline(&load("healthy")).0, "Everything checks out.");
    }

    #[test]
    fn unfinished_ok_is_not_healthy() {
        // verdict "ok" with ok false: a check never reported, so it is incomplete.
        let r = parse_report(
            r#"{"version":"x","target":null,"verdict":"ok","ok":false,"checks":[],"summary":""}"#,
        )
        .unwrap();
        assert_eq!(r.shown_verdict(), "incomplete");
        assert!(!Outcome::Single(r.clone()).ok());
        assert_eq!(headline(&r).0, "The checks didn't finish");
    }

    #[test]
    fn generic_run_has_no_target() {
        let r = load("generic");
        assert!(r.target.is_none());
        assert!(r.ok);
    }

    #[test]
    fn dns_failure() {
        let r = load("dns");
        assert!(!r.ok);
        assert_eq!(r.verdict, "dns");
        assert_eq!(r.failed_stage.as_deref(), Some("dns"));
        let f = &r.findings[0];
        assert_eq!(f.id, "dns_failure");
        let rem = f.remediation.as_ref().unwrap();
        assert_eq!(shell_line(&rem.command), "cat /etc/resolv.conf");
        assert!(!rem.steps.is_empty());
    }

    #[test]
    fn refused_and_tls() {
        let r = load("refused");
        assert_eq!(r.verdict, "service");
        assert_eq!(
            r.checks
                .iter()
                .find(|c| c.id == "target_tcp")
                .unwrap()
                .cause
                .as_deref(),
            Some("connection_refused")
        );
        let t = load("tls");
        assert_eq!(t.findings[0].id, "tls_certificate_expired");
        assert_eq!(t.findings[0].confidence, "medium");
    }

    #[test]
    fn plain_language() {
        let r = load("healthy");
        let host = Some("github.com");
        let get = |id: &str| r.checks.iter().find(|c| c.id == id).unwrap();
        assert_eq!(step_title(get("target_tcp"), host), "Reaches github.com");
        assert_eq!(get("target_tcp").title, "Reaches github.com");
        assert_eq!(get("ssid").says, "On Wi-Fi \"Example Wi-Fi\".");
        assert_eq!(
            step_says(get("internet_tcp"), host),
            "Reaches the internet over IPv4 and IPv6."
        );
        assert_eq!(step_says(get("ssid"), host), "On Wi-Fi \"Example Wi-Fi\".");
        assert_eq!(
            step_says(get("proxy_connect"), host),
            "No proxy is set up, so there's nothing to check."
        );
        let d = load("dns");
        let dns = d.checks.iter().find(|c| c.id == "dns").unwrap();
        assert!(step_says(dns, Some("x")).contains("check /etc/resolv.conf"));
        let text = as_text(&d);
        assert!(text.contains("The name doesn't resolve") && text.contains("Step by step:"));
    }

    #[test]
    fn clipboard_text_is_cleaned() {
        // A terminal escape, a newline that would run a second command when
        // pasted, and a right-to-left override that disguises text.
        let evil = "ls\u{1b}[2J\nrm -rf ~ \u{202E}txt.exe";
        assert_eq!(clean(evil), "ls[2Jrm -rf ~ txt.exe");
        assert_eq!(shell_line(&["echo".into(), "a\nb".into()]), "echo ab");
        let mut r =
            parse_report(r#"{"version":"x","target":null,"summary":"ok\u001b[31m","verdict":"ok","ok":true,"checks":[]}"#)
                .unwrap();
        r.summary.push('\u{202E}');
        let t = as_text(&r);
        assert!(!t.chars().any(|c| c == '\u{1b}' || c == '\u{202E}'));
        assert!(t.contains('\n'), "line breaks between lines are kept");
    }

    #[test]
    fn why_view() {
        let r = load("tls");
        let w = why(&r.findings[0], &r);
        assert_eq!(
            w.supports,
            [
                "\"Secure connection is valid\" failed: certificate expired.",
                "\"Reaches expired.badssl.com\" passed.",
            ]
        );
        assert_eq!(
            w.ruled_out,
            [
                "The server can't be reached at all: no, because \"Reaches expired.badssl.com\" passed."
            ]
        );
        let d = load("dns");
        let w = why(&d.findings[0], &d);
        assert_eq!(
            w.ruled_out,
            ["You're offline: no, because \"Reaches the internet\" passed."]
        );
        assert_eq!(
            w.unchecked,
            ["\"Reaches nonexistent-host.invalid\": an earlier step failed first."]
        );
        assert!(
            w.supports
                .iter()
                .any(|s| s.contains("said the name doesn't exist"))
        );
    }

    #[test]
    fn service_profile() {
        let p = format!(
            "{}/tests/fixtures/profile-web.json",
            env!("CARGO_MANIFEST_DIR")
        );
        let o = parse(&std::fs::read_to_string(p).unwrap()).unwrap();
        let Outcome::Profile(p) = &o else {
            panic!("not a profile")
        };
        assert_eq!(p.title, "Web");
        assert_eq!(p.components.len(), 2);
        assert_eq!(p.components[0].word(), "Not working");
        assert_eq!(p.components[1].word(), "Working");
        assert_eq!(o.pill(), "Partly working");
        assert!(!o.ok());
        assert_eq!(o.first_problem(), 0);
        let detail = o.detail(0).unwrap();
        assert_eq!(detail.verdict, "service");
        assert!(
            detail.checks.iter().all(|c| !c.title.is_empty()),
            "nested reports get plain titles too"
        );
    }

    #[test]
    fn quoting() {
        assert_eq!(
            shell_line(&["echo".into(), "a b".into(), "it's".into()]),
            "echo 'a b' 'it'\\''s'"
        );
    }

    #[test]
    fn missing_required_fields_are_rejected() {
        // The schema's required fields. A null target is present, so it is allowed.
        let base: serde_json::Value = serde_json::from_str(
            r#"{"version":"x","target":null,"checks":[{"id":"dns","name":"DNS","status":"PASS","ms":1,"detail":""}],"summary":"s","verdict":"ok","ok":true}"#,
        )
        .unwrap();
        assert!(
            parse(&base.to_string()).is_ok(),
            "the complete report must parse"
        );
        for key in ["version", "target", "checks", "summary", "verdict", "ok"] {
            let mut v = base.clone();
            v.as_object_mut().unwrap().remove(key);
            assert!(
                parse(&v.to_string()).is_err(),
                "a report without {key} was accepted"
            );
        }
        let mut v = base.clone();
        v["checks"][0].as_object_mut().unwrap().remove("detail");
        assert!(
            parse(&v.to_string()).is_err(),
            "a check without detail was accepted"
        );
    }

    #[test]
    fn every_text_field_is_cleaned_when_parsed() {
        // Escapes, a right-to-left override and a NUL in each kind of text field.
        // Line breaks in steps are kept: they are structure, not a control hazard.
        let r = parse_report(
            r#"{"version":"x","target":{"host":"h\u001b[2J","port":1,"protocol":"tcp"},"checks":[{"id":"dns","name":"DNS\u202e","status":"FAIL","ms":1,"detail":"d\u0007","fix":"f\u001b"}],"summary":"s\u001b[31m","verdict":"service","ok":false,"findings":[{"id":"x","remediation":{"id":"r","action":"a\u0000b","steps":["one\ntwo"]}}]}"#,
        )
        .unwrap();
        assert_eq!(r.summary, "s[31m");
        assert_eq!(r.target.unwrap().host, "h[2J");
        assert_eq!(r.checks[0].name, "DNS");
        assert_eq!(r.checks[0].detail, "d");
        assert_eq!(r.checks[0].fix.as_deref(), Some("f"));
        assert_eq!(r.checks[0].status, "FAIL", "identifiers are left alone");
        let rem = r.findings[0].remediation.as_ref().unwrap();
        assert_eq!(rem.action, "ab");
        assert_eq!(rem.steps, ["one\ntwo"]);
    }

    #[test]
    fn keys_are_cleaned_as_well_as_values() {
        // A right-to-left override in an address-family key must not change how
        // the family reads: the step still says IPv4.
        let r = parse_report(
            r#"{"version":"x","target":null,"checks":[{"id":"internet_tcp","name":"Internet","status":"PASS","ms":1,"detail":"","address_families":{"ipv4\u202e":"reachable"}}],"summary":"s","verdict":"ok","ok":true}"#,
        )
        .unwrap();
        let fams = r.checks[0].address_families.as_ref().unwrap();
        assert!(fams.contains_key("ipv4"), "keys: {fams:?}");
        assert!(fams.keys().all(|k| !k.contains('\u{202e}')));
        assert_eq!(r.checks[0].says, "Reaches the internet over IPv4.");
    }

    #[test]
    fn keys_that_clean_to_the_same_name_are_rejected() {
        // "ok" and "ok" with a zero-width space are different keys, but read the
        // same. One must not silently replace the other: a failed report could
        // come out healthy.
        let json = r#"{"version":"x","target":null,"checks":[],"summary":"s","verdict":"ok","ok":false,"ok\u200b":true}"#;
        assert!(parse(json).is_err());
    }

    #[test]
    fn unknown_fields_are_ignored() {
        let r = parse_report(r#"{"version":"9","target":null,"summary":"","checks":[{"id":"new_check","name":"New","status":"PASS","ms":1,"detail":"","brand_new":1}],"verdict":"ok","ok":true,"extra":{}}"#).unwrap();
        assert_eq!(r.checks[0].id, "new_check");
    }
}
