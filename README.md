# SecureGuard AI

**AI Security Vulnerability Detection & Code Remediation Agent**

SecureGuard AI reads SAST scan reports, finds vulnerable code, generates targeted fixes using an AI agent with a reasoning chain and feedback loop, validates fixes against your test suite, and delivers PR-ready patches with plain-English reports.

## Architecture

- **LangGraph** orchestrates the remediation pipeline as a stateful graph
- **LangChain** provides tools, prompt templates, and LLM interactions within each node
- **8-stage pipeline**: Parse -> Filter -> Locate -> Agent -> Validate -> Review -> Patch -> Report

```
┌─────────┐    ┌────────┐    ┌────────┐    ┌─────────────┐
│  Parse  │───▶│ Filter │───▶│ Locate │───▶│ Generate Fix │
└─────────┘    └────────┘    └────────┘    └──────┬──────┘
                                                   │
                                                   ▼
┌──────────┐    ┌─────────┐    ┌────────┐    ┌──────────┐
│  Report  │◀───│  Patch  │◀───│ Review │◀───│ Validate │
└──────────┘    └─────────┘    └────────┘    └─────┬────┘
                                                   │
                                              FAIL │ (retry ≤3)
                                                   │
                                            ┌──────▼──────┐
                                            │ Generate Fix │
                                            └─────────────┘
```

## Quick Start

### 1. Install dependencies

```bash
cd secureguard
pip install -r requirements.txt
```

### 2. Set your API key

```bash
cp .env.example .env
# Edit .env and add your Google Gemini API key
export GOOGLE_API_KEY=your-key-here
```

### 3. Run on a scan report

```bash
# Automatic mode (default)
python main.py --scan demo_report.json --repo .

# Interactive mode (human-in-the-loop review)
python main.py --scan demo_report.json --repo . --interactive

# Scan only specific vulnerability types
python main.py --scan demo_report.json --repo . --vuln-types sql_injection,xss,hardcoded_secrets

# Custom config
python main.py --scan demo_report.json --repo . --config my_config.yaml
```

## Project Structure

```
secureguard/
├── main.py                     # CLI entry point, wires all modules
├── parser.py                   # Reads JSON scan reports (Semgrep, Bandit, generic)
├── fp_filter.py                # LLM-based false positive filtering
├── locator.py                  # Extracts code context around vulnerable lines
├── validator.py                # Applies fix to temp copy, runs tests
├── reviewer.py                 # Human-in-the-loop review (interactive mode)
├── patch_generator.py          # Generates .patch files (git diff format)
├── reporter.py                 # Markdown report generation
├── agent/
│   ├── agent.py                # LangGraph workflow (nodes + edges)
│   ├── tools.py                # 4 LangChain tools (@tool decorated)
│   ├── memory.py               # ConversationBufferMemory management
│   └── feedback_loop.py        # Retry prompts with failure context
├── prompts/
│   ├── fix_templates.py        # 24 vulnerability-specific prompt templates
│   └── fp_filter.py            # False positive analysis prompt
├── config/
│   └── vuln_config.yaml        # Configurable vulnerability types & prompts
├── sample_vulns/               # 24 sample vulnerable files for testing
│   └── tests/                  # Test suite for each vulnerable file
├── output/                     # Generated patches and reports
├── demo_report.json            # Sample scan report for demo
├── requirements.txt
├── .env.example
└── README.md
```

## Modes

| Mode | Description |
|------|-------------|
| **Automatic** | Fully autonomous - parses, fixes, validates, patches |
| **Interactive** | Pauses after validation to show diff and get developer approval |

## Configuration

Edit `config/vuln_config.yaml` to:

- **Enable/disable** vulnerability types
- **Add custom** vulnerability definitions
- **Modify** prompt templates per vulnerability type
- **Adjust** confidence thresholds, retry limits, context window
- **Override** severity levels

Example - scan only injection types:
```yaml
vulnerabilities:
  sql_injection:
    category: Injection
    severity: HIGH
    ...
  command_injection:
    category: Injection
    ...
```

## Pipeline Stages

| # | Stage | Description |
|---|-------|-------------|
| 1 | **Parse** | Read scan report (Semgrep, Bandit, or generic JSON) |
| 2 | **Filter** | Remove false positives via LLM confidence scoring |
| 3 | **Locate** | Find vulnerable code, extract function scope + context |
| 4 | **Agent** | LangGraph agent reasons about the fix using 4 tools |
| 5 | **Validate** | Apply fix to temp copy, run test suite |
| 6 | **Review** | Optional human approval (interactive mode) |
| 7 | **Patch** | Generate `.patch` file (valid git diff) |
| 8 | **Report** | Plain English Markdown with OWASP reference |

## Agent Tools

| Tool | Purpose |
|------|---------|
| `read_file_tool` | Read source files to understand full context |
| `run_tests_tool` | Apply fix and run test suite |
| `search_codebase_tool` | Find related code and other vulnerable patterns |
| `explain_fix_tool` | Self-verify reasoning before finalizing |

## Feedback Loop

When a fix fails tests, the agent:
1. Reads the test failure output
2. Identifies what assumption was wrong
3. Generates a refined fix with accumulated context
4. Up to 3 retries before escalating as UNVERIFIED

## Vulnerability Types (24 Built-in)

| Category | Types |
|----------|-------|
| **Injection** | SQL Injection, Command Injection, LDAP Injection, XPath Injection |
| **Web** | XSS, CSRF, Open Redirect, XXE |
| **File & Data** | Path Traversal, Insecure Deserialization, Arbitrary File Upload, Log Injection |
| **Auth & Crypto** | Hardcoded Secrets, Weak Hashing, Broken JWT Auth, Weak Randomness |
| **Code & Config** | Insecure eval/exec, Debug Mode in Prod, Overly Permissive CORS, Missing Security Headers |
| **Resource & Memory** | Buffer Overflow, Use After Free, Integer Overflow, ReDoS |

## Output

For each vulnerability, SecureGuard produces:
- **`.patch` file** - valid git diff, apply with `git apply`
- **Markdown report** - vulnerability details, before/after code, OWASP reference, test results, fix reasoning

A **summary report** is generated across all processed vulnerabilities with accuracy metrics.

## Scan Report Formats

SecureGuard accepts JSON reports from:
- **Semgrep** - `results` array with `check_id`, `path`, `start.line`
- **Bandit** - `results` array with `test_id`, `filename`, `line_number`
- **Generic** - `vulnerabilities` array with `type`, `file_path`, `line_number`
