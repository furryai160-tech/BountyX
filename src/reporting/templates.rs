use crate::evidence::CollectedEvidence;
use chrono::Utc;

pub struct ReportTemplate;

impl ReportTemplate {
    pub fn render_markdown(evidence: &CollectedEvidence, program_handle: &str) -> String {
        let now = Utc::now().format("%Y-%m-%d %H:%M:%S UTC");

        let curl_block = evidence
            .curl_command
            .as_ref()
            .map(|c| format!("```bash\n{}\n```", c))
            .unwrap_or_else(|| "```text\nNo explicit curl command recorded.\n```".to_string());

        let req_block = evidence
            .request
            .as_ref()
            .map(|r| format!("```http\n{}\n```", r))
            .unwrap_or_else(|| "```http\n(Request details captured in raw scanner telemetry)\n```".to_string());

        let resp_block = evidence
            .response
            .as_ref()
            .map(|r| format!("```http\n{}\n```", r))
            .unwrap_or_else(|| "```http\n(Response details captured in raw scanner telemetry)\n```".to_string());

        let extracted_summary = if !evidence.extracted_data.is_empty() {
            format!(
                "- **Extracted Indicators:**\n{}",
                evidence
                    .extracted_data
                    .iter()
                    .map(|d| format!("  - `{}`", d))
                    .collect::<Vec<_>>()
                    .join("\n")
            )
        } else {
            "- **Extracted Indicators:** None".to_string()
        };

        format!(
r#"# Vulnerability Report: {template_name}

**Report Generated:** {timestamp}  
**Program:** `{program_handle}`  
**Status:** `Automated Finding — Requires Human Verification`

---

## Summary
An automated vulnerability assessment scan flagged a potential security issue on `{target}` matching template `{template_id}`.

> **IMPORTANT DISCLAIMER:**  
> This finding is preliminary and unverified. It must be manually reviewed and confirmed by a security engineer before any submission to HackerOne.

---

## Affected Asset
- **Target Host:** `{target}`
- **Vulnerable URL / Matched Endpoint:** `{matched_url}`
- **Scope Program:** `{program_handle}`

---

## Severity
- **Assessed Severity:** `{severity}`
- **Confidence:** `POTENTIAL` (Automated Detection)

---

## Description
{description}

---

## Steps to Reproduce
1. Ensure authorization under the `{program_handle}` HackerOne bug bounty policy.
2. Execute the following reproduction command against `{matched_url}`.
3. Observe the response headers and payload behavior matching the signature.

---

## Proof of Concept
{curl_block}

---

## Request
{req_block}

---

## Response
{resp_block}

---

## Evidence & Telemetry
{extracted_summary}

### Raw Scanner Output
```json
{raw_scanner_output}
```

---

## Impact
Potential unauthorized exposure or behavioral deviation on `{matched_url}` as indicated by template `{template_id}`.

---

## Remediation
1. Validate whether the endpoint is intended to be publicly reachable.
2. Verify access control, input validation, and security headers.
3. Patch or update the underlying software component to the latest recommended vendor version.

---

*Generated automatically by BountyScope Engine. Confidential — For Authorized Assessment Only.*
"#,
            template_name = evidence.template_name,
            timestamp = now,
            program_handle = program_handle,
            target = evidence.target,
            template_id = evidence.template_id,
            matched_url = evidence.matched_url,
            severity = evidence.severity,
            description = format!("Automated scanner match for signature `{}`.", evidence.template_name),
            curl_block = curl_block,
            req_block = req_block,
            resp_block = resp_block,
            extracted_summary = extracted_summary,
            raw_scanner_output = evidence.raw_scanner_output
        )
    }
}
