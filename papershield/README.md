# PaperShield

**Antivirus scans files for malware. PaperShield scans documents for instructions and data that should never reach your AI.**

PaperShield creates a trust boundary before a document reaches an AI agent, retrieval system, or employee workflow. It extracts what the machine will see, identifies suspicious instructions and sensitive data, routes every finding to a human reviewer, and produces a permanently sanitized PDF with a full audit trail.

Built for the **Nutrient: Turn Documents Into Something People Actually Trust** challenge.

---

## Features

- **Prompt-injection detection** — 30+ deterministic rules covering instruction overrides, assistant-directed commands, secret exfiltration, tool invocations, trust claims, policy bypasses, and encoded markers.
- **Sensitive-data detection** — email, phone, credit card (Luhn validated), SSN, IBAN, API keys, IPs, URLs, dates of birth.
- **Visibility comparison** — detects text present in the digital layer but absent from a rendered/OCR view (white-on-white, micro-font, etc.).
- **Static PDF inspection** — JavaScript actions, launch actions, embedded files, form submit actions, suspicious external links, metadata anomalies.
- **Risk scoring** — composite score (0–100) with four weighted components: Injection (40%), Sensitive (25%), Hidden (20%), Active (15%).
- **Human review** — per-finding Redact / Keep / Escalate controls with mandatory reasons for Critical/High keeps; bulk actions by category.
- **Permanent redaction** — via Nutrient API in live mode; PyMuPDF fallback in demo mode. Applied to a copy; original is never modified.
- **Post-redaction verification** — re-extracts sanitized PDF, confirms fingerprints are absent, checks page count, verifies hash change.
- **Audit report** — JSON + Markdown, including hashes, findings, reviewer decisions, timestamps, and verification status.
- **Demo mode** — works fully offline with a synthetic malicious PDF. Shows "Prepared demo" badge; never silently simulates live calls.

---

## Quick Start

```bash
cd papershield
pip install -r requirements.txt

# Generate the synthetic demo PDF
python3 -m papershield.fixtures.create_demo_pdf

# Run the app
streamlit run app.py
```

Open [http://localhost:8501](http://localhost:8501). Select **Use sample document** → `Vendor_Onboarding_Packet.pdf` → **Inspect document**.

---

## Secrets Configuration

Copy `.streamlit/secrets.toml.example` to `.streamlit/secrets.toml` and fill in your credentials:

```toml
NUTRIENT_API_KEY = "your-key-here"
NUTRIENT_BASE_URL = "https://api.nutrient.io"
DEMO_MODE = "false"   # set to "true" to force demo mode
```

**Never commit the populated secrets.toml.**

For Streamlit Community Cloud, add the same keys under **Settings → Secrets**.

If no valid API key is configured, PaperShield automatically switches to Demo mode with a visible badge.

---

## Running Tests

```bash
cd papershield
python3 -m pytest tests/ -v
```

27 unit and integration tests covering: MIME validation, SHA-256 hashing, Luhn validation, each injection rule family, sensitive-data detection, visibility comparison, risk thresholds, reviewer decision rules, coordinate normalization, audit masking, and one mocked end-to-end test.

---

## Project Structure

```
papershield/
├── app.py                          # Streamlit entry point (state machine)
├── requirements.txt
├── components/
│   ├── upload.py                   # Upload tab + privacy notice
│   ├── inspection.py               # Risk summary + page preview with overlays
│   ├── review.py                   # Per-finding review cards
│   ├── comparison.py               # Original vs sanitized comparison
│   └── report.py                   # Downloads + audit summary
├── services/
│   ├── nutrient_client.py          # Live + Demo provider implementations
│   ├── extraction_normalizer.py    # PyMuPDF local extraction + page rendering
│   ├── pdf_static_inspector.py     # pikepdf read-only structure inspection
│   ├── injection_detector.py       # Deterministic prompt-injection rules
│   ├── sensitive_data_detector.py  # PII / credential pattern matching
│   ├── visibility_comparator.py    # Digital-vs-OCR layer comparison
│   ├── risk_engine.py              # I/S/H/A component scoring
│   ├── redaction_service.py        # Apply redactions + verify output
│   └── audit_builder.py           # Build JSON + Markdown audit records
├── models/
│   └── document.py                 # Pydantic schemas (Finding, AuditRecord, …)
├── fixtures/
│   └── create_demo_pdf.py          # Generate synthetic malicious PDF
├── sample_documents/
│   └── Vendor_Onboarding_Packet.pdf
├── tests/
│   └── test_core.py
└── .streamlit/
    ├── config.toml                 # White theme
    └── secrets.toml.example
```

---

## Architecture

### Inspection Pipeline

```
PDF upload
  │
  ├─ Stage A: Safe intake — MIME check, size/page limits, SHA-256
  ├─ Stage B: Nutrient extraction/OCR — structured text + coordinates
  ├─ Stage C: Static PDF checks — pikepdf read-only structure scan
  ├─ Stage D: Prompt-injection detection — 30+ deterministic rules
  └─ Stage E: Sensitive-data detection — validators + Luhn check
```

### Provider Interface

`NutrientProvider` defines: `extract_document`, `apply_ocr`, `apply_redactions`, `render_pages`.

- **`LiveNutrientProvider`** — calls Nutrient Data Extraction API (`/v1/extract`) and DWS Processor API (`/v1/process`). Exponential backoff on extraction calls. Redaction is treated as a non-idempotent mutation — no automatic retry after ambiguous response.
- **`DemoNutrientProvider`** — uses PyMuPDF for local extraction and redaction. Always shows "Prepared demo" badge.

### Risk Model

```
document_risk = round(100 × (0.40·I + 0.25·S + 0.20·H + 0.15·A))
```

| Score | Label    |
|-------|----------|
| 80–100 | Critical |
| 60–79  | High     |
| 30–59  | Medium   |
| 0–29   | Low      |

A confirmed Critical injection or executable action enforces a minimum score of 80.

---

## Threat Model & Limitations

**What PaperShield detects:**
- Known prompt-injection language patterns.
- Common sensitive-data formats with checksum validation.
- Text present in PDF digital layer but not rendered.
- Active PDF features (JavaScript, launch, form-submit, embedded files).

**What PaperShield does not do:**
- It does not certify that a document is malware-free or legally compliant.
- It does not execute, follow, or test instructions found in a document.
- It does not prevent all possible prompt-injection attacks — novel phrasings or highly obfuscated encodings may not be detected.
- It does not replace DLP, antivirus, or legal review.
- Pattern matches are candidates until reviewed by a human.

**Security design:**
- Document content never instructs the application logic — all extracted text is treated as inert quoted data.
- API keys are read from server-side secrets only.
- No document content is logged or persisted beyond the session.
- LLM integration (optional/not enabled by default) uses a fixed untrusted-data system prompt, no tools, no memory, no secrets.

---

## Data Retention

- Uploaded PDFs are stored in the Streamlit session only (in-memory bytes).
- No files are written to persistent disk except the demo fixture.
- Session data is cleared on "Start over" or session expiry.
- No analytics, filenames, or document content are sent to external services beyond the configured Nutrient API.

---

## Two-Minute Demo Checklist

1. Open PaperShield at http://localhost:8501
2. Click **Use sample document** → select `Vendor_Onboarding_Packet.pdf`
3. Note the privacy notice and SHA-256 displayed
4. Click **Inspect document**
5. Watch the 8-stage processing progress
6. Observe Risk Score (should be Critical, 80+)
7. Note the finding counts: injection, sensitive data, hidden content
8. Click through the page navigator to see colored bounding-box overlays
9. Click **Proceed to Review**
10. Expand individual findings to see evidence, detector, and confidence
11. Apply **Redact** to injection and sensitive-data findings
12. Click **Create sanitized document** (all findings decided)
13. Observe the verification checklist — all checks green
14. Compare original vs sanitized pages side-by-side
15. Download sanitized PDF, JSON audit record, and Markdown report
16. Confirm workflow status shows **Sanitized and rechecked**

---

## Nutrient API References

- [Data Extraction API](https://www.nutrient.io/api/data-extraction-api/)
- [DWS Processor API](https://www.nutrient.io/api/processor-api/)
- [Permanent Redaction Guide](https://www.nutrient.io/guides/document-engine/redaction/)
- [Python OCR Guide](https://www.nutrient.io/guides/python/extraction/apply-ocr-to-pdf/)
