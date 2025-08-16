use anyhow::{Context, Result};
use clap::Parser;
use regex::Regex;
use serde::Deserialize;
use std::{collections::HashMap, fs, path::PathBuf};
use walkdir::WalkDir;

#[derive(Parser, Debug)]
#[command(name = "misra-cli", version)]
struct Args {
    /// Source directory to scan
    #[arg(long)]
    source: PathBuf,

    /// Rules YAML (patterns + severities)
    #[arg(long)]
    rules: PathBuf,

    /// Output directory, use: --out dir:<path>
    #[arg(long)]
    out: String,

    /// Gate thresholds, e.g. "critical:0,high:5,medium:20,low:100"
    #[arg(long, default_value = "")]
    gate: String,
}

#[derive(Debug, Deserialize)]
struct RuleItem {
    pattern: String,
    rule: String,
    severity: String, // critical|high|medium|low
}

#[derive(Debug, Deserialize, Default)]
struct Rules {
    // Accept "severities" from YAML, but we mark it unused internally.
    #[serde(default, rename = "severities")]
    _severities: HashMap<String, Vec<String>>,
    // Make heuristics optional in YAML; default to empty list if absent.
    #[serde(default)]
    heuristics: Vec<RuleItem>,
}

#[derive(Debug, Clone)]
struct Finding {
    file: String,
    line: usize,
    rule: String,
    severity: String,
    message: String,
}

fn main() -> Result<()> {
    let args = Args::parse();
    let out_dir = parse_out_dir(&args.out)?;
    fs::create_dir_all(&out_dir).ok();

    let rules: Rules = serde_yaml::from_str(&fs::read_to_string(&args.rules)?)?;

    // Gather files
    let mut files = vec![];
    for e in WalkDir::new(&args.source).into_iter().filter_map(|e| e.ok()) {
        if !e.file_type().is_file() {
            continue;
        }
        let p = e.path();
        if let Some(ext) = p.extension().and_then(|s| s.to_str()) {
            if ["c", "h", "cpp", "hpp"].contains(&ext) {
                files.push(p.to_path_buf());
            }
        }
    }

    // Heuristic scan
    let mut findings = vec![];
    for f in &files {
        let content = fs::read_to_string(f).unwrap_or_default();
        let lines: Vec<&str> = content.lines().collect();
        for h in &rules.heuristics {
            let re = Regex::new(&h.pattern).with_context(|| format!("bad regex: {}", h.pattern))?;
            for (idx, line) in lines.iter().enumerate() {
                if re.is_match(line) {
                    findings.push(Finding {
                        file: f.to_string_lossy().to_string(),
                        line: idx + 1,
                        rule: h.rule.clone(),
                        severity: h.severity.clone(),
                        message: format!("Heuristic match for {}", h.rule),
                    });
                }
            }
        }
    }

    // Write reports
    write_junit(&findings, &out_dir)?;
    write_html(&findings, &out_dir)?;
    write_sarif(&findings, &out_dir)?;

    // Gate
    if let Some(err) = evaluate_gate(&findings, &args.gate) {
        eprintln!("{err}");
        std::process::exit(2);
    }

    println!(
        "Completed. Reports at: {}/report.junit.xml, report.html, report.sarif.json",
        out_dir.display()
    );
    Ok(())
}

fn parse_out_dir(s: &str) -> Result<PathBuf> {
    let p = s.strip_prefix("dir:").unwrap_or(s);
    Ok(PathBuf::from(p))
}

fn write_junit(findings: &[Finding], out_dir: &PathBuf) -> Result<()> {
    use junit_report::{Duration, Report, TestCase, TestSuite};
    use std::fs::File;

    let mut suite = TestSuite::new("misra-ci");
    for f in findings {
        // junit-report 0.8.x: build a failure test case directly
        let name = format!("{}:{}", f.file, f.line);
        let msg = format!("[{}] {} - {}", f.severity, f.rule, f.message);
        let type_ = f.rule.as_str();
        let case = TestCase::failure(&name, Duration::seconds(0), type_, &msg);
        suite.add_testcase(case);
    }

    let mut report = Report::new();
    report.add_testsuite(suite);
    let mut file = File::create(out_dir.join("report.junit.xml"))?;
    report.write_xml(&mut file).context("failed to write JUnit XML")?;
    Ok(())
}

fn write_html(findings: &[Finding], out_dir: &PathBuf) -> Result<()> {
    let mut rows = String::new();
    for f in findings {
        rows.push_str(&format!(
            "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>\n",
            html_escape(&f.severity),
            html_escape(&f.rule),
            html_escape(&f.file),
            f.line
        ));
    }
    let doc = format!(
        r#"<!doctype html><html><head><meta charset="utf-8">
<title>MISRA Report</title>
<style>body{{font-family:sans-serif}} table{{border-collapse:collapse;margin-top:8px}}
td,th{{border:1px solid #ccc;padding:6px}} th{{background:#eee}}</style>
</head><body><h1>MISRA Report</h1>
<table><thead><tr><th>Severity</th><th>Rule</th><th>File</th><th>Line</th></tr></thead>
<tbody>
{rows}
</tbody></table></body></html>"#
    );
    fs::write(out_dir.join("report.html"), doc)?;
    Ok(())
}

fn write_sarif(findings: &[Finding], out_dir: &PathBuf) -> Result<()> {
    #[derive(serde::Serialize)]
    struct SarifLog<'a> {
        version: &'a str,
        #[serde(rename = "$schema")]
        schema: &'a str,
        runs: Vec<SarifRun<'a>>,
    }
    #[derive(serde::Serialize)]
    struct SarifRun<'a> {
        tool: SarifTool<'a>,
        results: Vec<SarifResult>,
    }
    #[derive(serde::Serialize)]
    struct SarifTool<'a> {
        driver: SarifDriver<'a>,
    }
    #[derive(serde::Serialize)]
    struct SarifDriver<'a> {
        name: &'a str,
    }
    #[derive(serde::Serialize)]
    struct SarifResult {
        #[serde(rename = "ruleId")]
        rule_id: String,
        level: String,
        message: SarifMessage,
        locations: Vec<SarifLocation>,
    }
    #[derive(serde::Serialize)]
    struct SarifMessage {
        text: String,
    }
    #[derive(serde::Serialize)]
    struct SarifLocation {
        #[serde(rename = "physicalLocation")]
        physical_location: SarifPhysicalLocation,
    }
    #[derive(serde::Serialize)]
    struct SarifPhysicalLocation {
        #[serde(rename = "artifactLocation")]
        artifact_location: SarifArtifactLocation,
        region: SarifRegion,
    }
    #[derive(serde::Serialize)]
    struct SarifArtifactLocation {
        uri: String,
    }
    #[derive(serde::Serialize)]
    struct SarifRegion {
        #[serde(rename = "startLine")]
        start_line: usize,
    }

    let level_map = |sev: &str| match sev {
        "critical" | "high" => "error",
        "medium" => "warning",
        _ => "note",
    };

    let results = findings
        .iter()
        .map(|f| SarifResult {
            rule_id: f.rule.clone(),
            level: level_map(&f.severity).to_string(),
            message: SarifMessage {
                text: format!("{} - {}", f.severity, f.message),
            },
            locations: vec![SarifLocation {
                physical_location: SarifPhysicalLocation {
                    artifact_location: SarifArtifactLocation {
                        uri: f.file.clone(),
                    },
                    region: SarifRegion { start_line: f.line },
                },
            }],
        })
        .collect::<Vec<_>>();

    let sarif = SarifLog {
        version: "2.1.0",
        schema: "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0.json",
        runs: vec![SarifRun {
            tool: SarifTool {
                driver: SarifDriver { name: "misra-ci" },
            },
            results,
        }],
    };

    fs::write(
        out_dir.join("report.sarif.json"),
        serde_json::to_string_pretty(&sarif)?,
    )?;
    Ok(())
}

fn evaluate_gate(findings: &[Finding], gate: &str) -> Option<String> {
    if gate.trim().is_empty() { return None; }
    // Parse "critical:0,high:5,medium:20,low:100" (commas or spaces)
    let mut budget = HashMap::<String, usize>::new();
    let cleaned = gate.replace(',', " ");
    for pair in cleaned.split_whitespace() {
        if let Some((k, v)) = pair.split_once(':') {
            if let Ok(n) = v.parse::<usize>() {
                budget.insert(k.to_lowercase(), n);
            }
        }
    }

    let mut counts = HashMap::from([
        ("critical".to_string(), 0usize),
        ("high".to_string(), 0),
        ("medium".to_string(), 0),
        ("low".to_string(), 0),
    ]);
    for f in findings {
        *counts.entry(f.severity.to_lowercase()).or_default() += 1;
    }

    let mut violations = vec![];
    for (sev, limit) in budget {
        let c = *counts.get(&sev).unwrap_or(&0);
        if c > limit {
            violations.push(format!("{sev}={c} > limit {limit}"));
        }
    }
    if violations.is_empty() { None } else { Some(format!("Gate failed: {}", violations.join(", "))) }
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;")
}
