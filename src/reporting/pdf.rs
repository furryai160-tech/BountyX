use crate::errors::{BountyScopeError, Result};
use crate::reporting::ai_writer::ReportDraft;
use crate::reporting::generator::BugBountyReport;
use std::path::Path;
use tokio::process::Command;
use tracing::{info, warn};

pub struct PdfReportGenerator;

impl PdfReportGenerator {
    /// Render HTML template for the report draft
    pub fn render_html(draft: &ReportDraft) -> String {
        let mut html = String::new();

        html.push_str(r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>BountyX Security Assessment Report</title>
<style>
  @page {
    size: A4;
    margin: 18mm 15mm 20mm 15mm;
    @bottom-right {
      content: "Page " counter(page) " of " counter(pages);
      font-size: 8pt;
      color: #64748b;
    }
    @bottom-left {
      content: "BountyX V3 — Confidential Security Audit Report";
      font-size: 8pt;
      color: #64748b;
    }
  }
  body {
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
    color: #0f172a;
    line-height: 1.5;
    font-size: 10pt;
    margin: 0;
    padding: 0;
  }
  .header {
    border-bottom: 2px solid #0284c7;
    padding-bottom: 12px;
    margin-bottom: 20px;
  }
  .brand {
    font-size: 18pt;
    font-weight: 800;
    color: #0369a1;
    letter-spacing: -0.5px;
    margin: 0;
  }
  .subtitle {
    font-size: 10pt;
    color: #475569;
    margin-top: 4px;
    margin-bottom: 0;
  }
  .meta-box {
    background: #f8fafc;
    border: 1px solid #e2e8f0;
    border-radius: 6px;
    padding: 12px 16px;
    margin-bottom: 24px;
    font-size: 9.5pt;
  }
  .meta-row {
    display: flex;
    justify-content: space-between;
    margin-bottom: 4px;
  }
  .badge {
    display: inline-block;
    padding: 2px 8px;
    border-radius: 4px;
    font-weight: 700;
    font-size: 8pt;
    text-transform: uppercase;
  }
  .badge-critical { background: #fee2e2; color: #991b1b; }
  .badge-high { background: #ffedd5; color: #9a3412; }
  .badge-medium { background: #fef3c7; color: #92400e; }
  .badge-low { background: #dbeafe; color: #1e40af; }
  .badge-info { background: #f1f5f9; color: #475569; }
  .badge-confirmed { background: #dcfce7; color: #166534; }
  .badge-review { background: #fef3c7; color: #854d0e; }

  table {
    width: 100%;
    border-collapse: collapse;
    margin: 16px 0 24px 0;
    font-size: 9pt;
  }
  th {
    background: #f1f5f9;
    color: #334155;
    text-align: left;
    padding: 8px 10px;
    border: 1px solid #cbd5e1;
    font-weight: 700;
  }
  td {
    padding: 8px 10px;
    border: 1px solid #e2e8f0;
  }
  tr:nth-child(even) td {
    background: #f8fafc;
  }

  .finding-card {
    page-break-inside: avoid;
    border: 1px solid #cbd5e1;
    border-radius: 6px;
    padding: 16px;
    margin-bottom: 24px;
    background: #ffffff;
  }
  .finding-title {
    font-size: 13pt;
    font-weight: 700;
    color: #0f172a;
    margin-top: 0;
    margin-bottom: 8px;
    border-bottom: 1px solid #e2e8f0;
    padding-bottom: 6px;
  }
  .section-heading {
    font-size: 10.5pt;
    font-weight: 700;
    color: #1e293b;
    margin-top: 14px;
    margin-bottom: 6px;
  }
  p {
    margin: 0 0 8px 0;
  }
  pre, code {
    font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
    font-size: 8.5pt;
  }
  pre {
    background: #0f172a;
    color: #f8fafc;
    padding: 10px 12px;
    border-radius: 4px;
    overflow-x: auto;
    white-space: pre-wrap;
    word-break: break-all;
    margin: 8px 0;
  }
  .unverified-box {
    background: #fffbeb;
    border-left: 4px solid #f59e0b;
    padding: 8px 12px;
    margin: 10px 0;
    font-size: 9pt;
    color: #92400e;
  }
  .remediation-box {
    background: #f0fdf4;
    border-left: 4px solid #22c55e;
    padding: 8px 12px;
    margin: 10px 0;
    font-size: 9pt;
    color: #166534;
  }
  ul, ol {
    margin: 4px 0 8px 18px;
    padding: 0;
  }
  li {
    margin-bottom: 4px;
  }
  .footer {
    text-align: center;
    font-size: 8pt;
    color: #94a3b8;
    margin-top: 30px;
    border-top: 1px solid #e2e8f0;
    padding-top: 10px;
  }
</style>
</head>
<body>
"#);

        // Header
        html.push_str(r#"<div class="header">
  <h1 class="brand">🛡️ BountyX V3 — Security Assessment Report</h1>
  <p class="subtitle">Autonomous AI Security Research Platform &bull; Human-in-the-Loop Governance</p>
</div>"#);

        // Meta box
        let review_badge = if draft.is_approved_by_human {
            format!(r#"<span class="badge badge-confirmed">✅ Approved by {}</span>"#, draft.approved_by.as_deref().unwrap_or("Reviewer"))
        } else {
            r#"<span class="badge badge-review">⚠️ Pending Human Review</span>"#.to_string()
        };

        html.push_str(&format!(r#"<div class="meta-box">
  <div class="meta-row"><strong>Target Asset:</strong> <code>{}</code></div>
  <div class="meta-row"><strong>Report ID:</strong> <code>{}</code></div>
  <div class="meta-row"><strong>Generated At:</strong> {}</div>
  <div class="meta-row"><strong>Human Review Status:</strong> {}</div>
</div>"#, draft.target_domain, draft.id, draft.generated_at.format("%Y-%m-%d %H:%M:%S UTC"), review_badge));

        // Executive Table
        html.push_str("<h2>📊 Executive Findings Summary</h2>");
        html.push_str(r#"<table>
  <thead>
    <tr>
      <th>#</th>
      <th>Severity</th>
      <th>CVSS 3.1</th>
      <th>Evidence Conf.</th>
      <th>AI Conf.</th>
      <th>Status</th>
      <th>Title</th>
    </tr>
  </thead>
  <tbody>"#);

        for (i, f) in draft.findings.iter().enumerate() {
            let sev_badge = match f.severity {
                crate::security::risk::Severity::Critical => r#"<span class="badge badge-critical">CRITICAL</span>"#,
                crate::security::risk::Severity::High => r#"<span class="badge badge-high">HIGH</span>"#,
                crate::security::risk::Severity::Medium => r#"<span class="badge badge-medium">MEDIUM</span>"#,
                crate::security::risk::Severity::Low => r#"<span class="badge badge-low">LOW</span>"#,
                crate::security::risk::Severity::Informational => r#"<span class="badge badge-info">INFO</span>"#,
            };

            let status_badge = match f.verification_status {
                crate::reporting::ai_writer::VerificationStatus::Confirmed => r#"<span class="badge badge-confirmed">CONFIRMED</span>"#,
                crate::reporting::ai_writer::VerificationStatus::RequiresHumanReview => r#"<span class="badge badge-review">REVIEW</span>"#,
            };

            html.push_str(&format!(
                r#"<tr>
  <td>{}</td>
  <td>{}</td>
  <td><strong>{:.1}</strong></td>
  <td>{}%</td>
  <td>{}%</td>
  <td>{}</td>
  <td><strong>{}</strong></td>
</tr>"#,
                i + 1,
                sev_badge,
                f.cvss_base_score,
                f.evidence_confidence,
                f.ai_confidence,
                status_badge,
                f.title
            ));
        }

        html.push_str("</tbody></table>");

        // Per-finding cards
        html.push_str("<h2>🔬 Detailed Technical Findings</h2>");

        for (i, f) in draft.findings.iter().enumerate() {
            html.push_str(r#"<div class="finding-card">"#);
            html.push_str(&format!(r#"<h3 class="finding-title">{}. {}</h3>"#, i + 1, f.title));

            html.push_str(&format!(
                r#"<p><strong>Endpoint:</strong> <code>{}</code> | <strong>CVSS Vector:</strong> <code>{}</code></p>"#,
                f.vulnerable_endpoint, f.cvss_vector
            ));

            html.push_str(r#"<div class="section-heading">1. 📝 Executive Summary</div>"#);
            html.push_str(&format!("<p>{}</p>", f.executive_summary));

            html.push_str(r#"<div class="section-heading">2. 🔍 Vulnerability Description</div>"#);
            html.push_str(&format!("<p>{}</p>", f.description));

            html.push_str(r#"<div class="section-heading">3. 💥 Business & Technical Impact</div>"#);
            html.push_str(&format!("<p>{}</p>", f.business_impact));

            html.push_str(r#"<div class="section-heading">4. ⚖️ Severity Justification</div>"#);
            html.push_str(&format!("<p>{}</p>", f.severity_justification));

            html.push_str(r#"<div class="section-heading">5. 🔁 Safe Steps to Reproduce</div><ol>"#);
            for s in &f.safe_reproduction_steps {
                html.push_str(&format!("<li>{}</li>", s));
            }
            html.push_str("</ol>");

            html.push_str(r#"<div class="section-heading">6. 💻 Verified Proof of Concept (cURL)</div>"#);
            html.push_str(&format!("<pre>{}</pre>", f.reproduction_curl));

            html.push_str(r#"<div class="section-heading">7. 🔬 Observed Network Telemetry</div>"#);
            html.push_str(&format!("<p><strong>HTTP Status:</strong> <code>{}</code> | <strong>Notes:</strong> {}</p>", f.observed_response_status, f.differential_evidence));
            html.push_str(&format!("<pre>{}</pre>", f.observed_response_snippet));

            if !f.unverified_aspects.is_empty() {
                html.push_str(r#"<div class="unverified-box"><strong>⚠️ Anti-Hallucination Disclaimers (نقاط لم يتم التحقق منها):</strong><ul>"#);
                for u in &f.unverified_aspects {
                    html.push_str(&format!("<li>{}</li>", u));
                }
                html.push_str("</ul></div>");
            }

            html.push_str(r#"<div class="remediation-box"><strong>💡 Actionable Remediation Guidance:</strong><ul>"#);
            for r in &f.remediation_recommendations {
                html.push_str(&format!("<li>{}</li>", r));
            }
            html.push_str("</ul></div>");

            html.push_str(r#"<div class="section-heading">📚 References & Standards</div><ul>"#);
            for r in &f.technical_references {
                html.push_str(&format!("<li><code>{}</code></li>", r));
            }
            html.push_str("</ul>");

            html.push_str("</div>");
        }

        html.push_str(r#"<div class="footer">Generated autonomously by BountyX V3 AI Smart Report Writer &bull; Evaluated under Safe Harbor Bug Bounty Policy</div>"#);
        html.push_str("</body></html>");

        html
    }

    /// Generate PDF file on disk from a BugBountyReport
    pub async fn generate_pdf(report: &BugBountyReport, output_pdf_path: &Path) -> Result<()> {
        let packages: Vec<crate::reporting::ai_writer::EvidencePackage> = report.findings.iter().map(crate::reporting::ai_writer::EvidencePackage::from).collect();
        let mut draft = crate::reporting::ai_writer::SmartReportWriter::generate_report(&report.target_domain, &packages);
        draft.id = report.id.clone();
        draft.is_approved_by_human = report.is_approved_by_human;
        draft.approved_by = report.approved_by.clone();
        draft.approval_timestamp = report.approval_timestamp;

        let html_content = Self::render_html(&draft);

        // Save temporary HTML file
        let temp_html_path = output_pdf_path.with_extension("html");
        tokio::fs::write(&temp_html_path, &html_content).await?;

        // 1. Try weasyprint first
        let weasy_res = Command::new("weasyprint")
            .arg(&temp_html_path)
            .arg(output_pdf_path)
            .output()
            .await;

        let success = match weasy_res {
            Ok(output) if output.status.success() => {
                info!("Generated PDF report via WeasyPrint: {:?}", output_pdf_path);
                true
            }
            _ => false,
        };

        // 2. Fallback to headless chromium if weasyprint failed
        if !success {
            info!("Attempting PDF generation fallback via headless chromium...");
            let chrome_res = Command::new("chromium")
                .arg("--headless")
                .arg("--disable-gpu")
                .arg("--no-sandbox")
                .arg(format!("--print-to-pdf={}", output_pdf_path.to_string_lossy()))
                .arg(&temp_html_path)
                .output()
                .await;

            match chrome_res {
                Ok(output) if output.status.success() => {
                    info!("Generated PDF report via Chromium fallback: {:?}", output_pdf_path);
                }
                Ok(output) => {
                    warn!("Chromium PDF conversion failed: {}", String::from_utf8_lossy(&output.stderr));
                    return Err(BountyScopeError::Internal("PDF conversion failed via both WeasyPrint and Chromium".to_string()));
                }
                Err(e) => {
                    return Err(BountyScopeError::Internal(format!("Failed to execute PDF tool: {}", e)));
                }
            }
        }

        // Clean up temporary HTML file
        tokio::fs::remove_file(&temp_html_path).await.ok();

        Ok(())
    }
}
