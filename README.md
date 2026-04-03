# SecureGuard AI

**AI Security Vulnerability Detection and Code Remediation Agent**

SecureGuard AI takes a SAST scan report, finds the affected code, filters likely false positives, generates a targeted fix, validates that fix against the project test suite, and produces a PR-ready patch with a plain-English explanation.

## How This Project Is Different

Most security tools stop at detection. They tell you what is wrong, but they do not close the loop.

SecureGuard is different because it is built as a remediation workflow, not just a reporting tool:

- It does not stop at the scan output. It traces the finding back to the source file and extracts local code context.
- It does not trust every scanner finding blindly. It runs a false-positive filtering stage before spending tokens on remediation.
- It does not produce only a suggestion. It generates a concrete patch file and a human-readable remediation report.
- It does not treat fix generation as the last step. It validates fixes against existing tests and can optionally run LLM-based verification on top.
- It supports both CLI execution and a UI workflow for developer review.

In short: **scan report in -> code context -> fix generation -> validation -> patch + explanation out**.

## Problem It Solves

Security scanners frequently create a gap between detection and remediation:

- developers must manually inspect noisy findings
- false positives waste time and reduce trust in scanner output
- writing secure fixes manually is slow and error-prone
- even a correct-looking fix can break application behavior

SecureGuard aims to reduce that gap by automating the path from vulnerability report to validated patch.

## Core Features

- Parse scan reports from Semgrep, Bandit, and generic JSON formats
- Extract vulnerable code context from the target repository
- Filter likely false positives using prompt-based reasoning plus deterministic checks
- Generate targeted fixes with a LangGraph-based remediation workflow
- Retry failed fixes with accumulated failure context
- Validate fixes against the project's existing test suite
- Optionally perform additional LLM-based fix verification
- Produce a unified diff patch and a Markdown remediation report
- Provide both CLI and Streamlit UI workflows

## High-Level Workflow

SecureGuard currently runs this flow:

1. Parse scan report
2. Restrict findings to enabled vulnerability types
3. Locate code context around each finding
4. Filter likely false positives
5. Generate a fix
6. Validate the fix
7. Optionally review the fix
8. Generate patch and report artifacts

```text
Scan Report
   |
   v
 Parse -> Locate -> FP Filter -> Generate Fix -> Validate -> Review -> Patch -> Report
                                             ^        |
                                             |        |
                                             +-- retry on validation failure
```

## Architecture

- **LangGraph** drives the remediation state machine and retry flow.
- **LangChain** is used for provider integration, tools, prompts, and agent execution.
- **Validator** applies fixes to a temporary repo copy and runs tests safely.
- **Reporter** emits both per-finding reports and a summary report.
- **UI layer** exposes the same backend workflow in Streamlit.

Main implementation areas:

- [main.py](/home/p7500125/Projects/HK/secureguard/main.py): CLI entry point and pipeline orchestration
- [parser.py](/home/p7500125/Projects/HK/secureguard/parser.py): scan report normalization
- [locator.py](/home/p7500125/Projects/HK/secureguard/locator.py): code context extraction
- [fp_filter.py](/home/p7500125/Projects/HK/secureguard/fp_filter.py): false-positive filtering
- [agent/agent.py](/home/p7500125/Projects/HK/secureguard/agent/agent.py): remediation workflow
- [validator.py](/home/p7500125/Projects/HK/secureguard/validator.py): test and LLM-based validation
- [patch_generator.py](/home/p7500125/Projects/HK/secureguard/patch_generator.py): diff generation
- [reporter.py](/home/p7500125/Projects/HK/secureguard/reporter.py): remediation reporting
- [ui_app.py](/home/p7500125/Projects/HK/secureguard/ui_app.py): Streamlit UI

## Supported Inputs

### Scan report formats

SecureGuard accepts JSON reports from:

- **Semgrep**
- **Bandit**
- **Generic JSON** with a `vulnerabilities` or `findings` array

### Vulnerability coverage

The project ships with **24 built-in vulnerability prompt templates**, including:

- SQL Injection
- Command Injection
- LDAP Injection
- XPath Injection
- XSS
- CSRF
- Open Redirect
- XXE
- Path Traversal
- Insecure Deserialization
- Arbitrary File Upload
- Log Injection
- Hardcoded Secrets
- Weak Hashing
- Broken JWT Auth
- Weak Randomness
- Insecure Eval/Exec
- Debug Mode in Production
- Overly Permissive CORS
- Missing Security Headers
- Buffer Overflow
- Use After Free
- Integer Overflow
- ReDoS

Coverage is configurable through `config/vuln_config.yaml`.

### LLM providers

Supported providers in the current implementation:

- Gemini
- Anthropic
- OpenAI
- GitHub Models
- Groq
- Cerebras
- OpenRouter
- Ollama

## Installation

### Prerequisites

- Python 3.10+
- `pip`
- At least one supported LLM API key, unless you are using Ollama locally

### Setup

```bash
cd secureguard
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### Environment variables

Create a local `.env` file from the example:

```bash
cp .env.example .env
```

Then set the API key that matches the provider selected in `config/vuln_config.yaml`.

Examples:

```bash
export GOOGLE_API_KEY=your-key-here
export OPENAI_API_KEY=your-key-here
export ANTHROPIC_API_KEY=your-key-here
export GROQ_API_KEY=your-key-here
export GITHUB_TOKEN=your-token-here
```

## Configuration

Main runtime settings live in [config/vuln_config.yaml](/home/p7500125/Projects/HK/secureguard/config/vuln_config.yaml).

Important settings:

- `llm.provider`: active provider
- `llm.model`: active model
- `settings.max_retries`: remediation retry limit
- `settings.confidence_threshold`: false-positive threshold
- `settings.context_lines`: code context window around a finding
- `settings.interactive_mode`: enable human review in CLI mode
- `settings.enable_llm_fix_verification`: if `true`, run LLM judge / generated-test style verification in addition to local tests

You can also enable or disable individual vulnerability types by editing the `vulnerabilities` section.

## Usage

### CLI

Automatic mode:

```bash
venv/bin/python main.py --scan demo_report.json --repo .
```

Interactive mode:

```bash
venv/bin/python main.py --scan demo_report.json --repo . --interactive
```

Run only selected vulnerability types:

```bash
venv/bin/python main.py --scan demo_report.json --repo . --vuln-types sql_injection,xss
```

Use a custom config file:

```bash
venv/bin/python main.py --scan demo_report.json --repo . --config my_config.yaml
```

### UI

Launch the Streamlit UI:

```bash
venv/bin/streamlit run ui_app.py
```

The UI is configured to run on:

- `http://localhost:8081`

The UI supports:

- scan report upload
- provider and model selection
- runtime config overrides
- live execution logs
- per-finding diff review
- patch download

## Validation Model

SecureGuard validates fixes in layers:

1. Syntax check for Python fixes
2. Apply the fix to a temporary repo copy
3. Run existing tests from the target repo
4. Optionally run extra LLM-based verification if enabled

### What "existing test suite" means here

This project follows the intended problem statement: a generated fix should be checked against the repo's already-present test suite to make sure application behavior is not broken.

### Sample repo note

The files under [sample_vulns](/home/p7500125/Projects/HK/secureguard/sample_vulns) are a demo target repo.

The tests under [sample_vulns/tests](/home/p7500125/Projects/HK/secureguard/sample_vulns/tests) are now **baseline regression tests**, not "security already fixed" assertions. They are meant to simulate normal existing unit tests that should pass before remediation and continue to pass after a correct fix.

Run them with:

```bash
venv/bin/python -m pytest sample_vulns/tests -v
```

## Outputs

For each processed vulnerability, SecureGuard produces:

- a `.patch` file with a unified diff
- a Markdown report containing:
  - vulnerability details
  - validation summary
  - plain-English explanation of the fix
  - before/after snippets
  - diff text

It also generates:

- `output/summary_report.md`

Status meanings:

- `VERIFIED`: validation passed
- `UNVERIFIED`: best fix attempt generated, but not fully validated
- `SKIPPED`: developer rejected the patch
- `ERROR`: processing failed

## Project Structure

```text
secureguard/
├── main.py
├── parser.py
├── locator.py
├── fp_filter.py
├── validator.py
├── reviewer.py
├── reporter.py
├── patch_generator.py
├── ui_app.py
├── config/
│   ├── llm_factory.py
│   └── vuln_config.yaml
├── prompts/
│   ├── fix_templates.py
│   └── fp_filter.py
├── agent/
│   ├── agent.py
│   ├── tools.py
│   ├── feedback_loop.py
│   ├── llm_judge.py
│   ├── test_generator.py
│   └── memory.py
├── sample_vulns/
│   ├── *.py
│   └── tests/
├── output/
├── demo_report.json
└── README.md
```

## Current Limitations

- LLM outputs vary by provider and model.
- Provider-side tool calling is not equally reliable across all supported models, so the agent may fall back to no-tool generation.
- LLM-based validation depends on working API credentials and network access.
- The demo repo is useful for showing workflow behavior, but it is still a controlled sample environment.
- Not every listed vulnerability type is equally demonstrated in the sample files.

## Future Scope

- Add database support for storing scan history, remediation history, validation outcomes, and user review decisions.
- Add native scanning so SecureGuard can run its own scan before a commit as a pre-commit hook and immediately provide a remedy if a vulnerability is found.
- Add direct GitHub / GitLab / Bitbucket integration for opening PRs automatically from generated patches.
- Add team dashboards for vulnerability trends, fix accuracy, retry patterns, and false-positive rates over time.
- Expand multi-language support beyond the current Python-focused sample workflow.
- Add organization-specific policy packs and custom remediation prompt libraries.
- Add richer human-in-the-loop review, including inline code comments and side-by-side patch review.
- Add approval workflows and role-based access control for enterprise use.
- Add semantic codebase indexing so the agent can reason over larger repositories more effectively.
- Add offline / local-only secure deployment modes for restricted enterprise environments.

## Authors

- Sahil Nichal
- Shyamlee Badole
- Rashmi Prasad
