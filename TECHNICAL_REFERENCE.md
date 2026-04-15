# SecureGuard AI Technical Reference

## 1. Purpose

SecureGuard AI is an AI-assisted remediation pipeline for security scanner findings.
It takes a scan report as input, maps findings to real source files, filters likely false positives, generates a targeted code fix, validates the fix, and emits:

- a unified diff patch
- a Markdown remediation report
- a summary report across all processed findings

The project supports both CLI execution and a Streamlit UI.

This document describes the current implementation as it exists in the repository, including the actual execution flow, configuration model, validation logic, UI behavior, and a file-by-file source map.

## 2. Core Idea

Most SAST pipelines stop at detection. SecureGuard is designed as a remediation workflow:

1. Read scanner output
2. Normalize findings
3. Locate vulnerable code in the repository
4. Filter noise and likely false positives
5. Generate a concrete fix
6. Validate that fix against the repository test suite
7. Optionally add LLM-based fix verification
8. Produce a patch and a plain-English explanation

In short:

```text
scan report -> normalized findings -> code context -> false-positive filter
           -> AI remediation -> validation -> patch + report
```

## 3. High-Level Architecture

The system is organized into six main layers.

### 3.1 Input and normalization

- `parser.py` reads scan reports from supported formats and converts them into a common finding schema.
- `config/vuln_config.yaml` defines which vulnerability types are currently enabled and what metadata or fix strategy is associated with each type.

### 3.2 Code context extraction

- `locator.py` opens the target file, extracts the vulnerable snippet, captures surrounding context, and identifies the enclosing function and imports.

### 3.3 False-positive filtering

- `fp_filter.py` applies deterministic prechecks and then calls an LLM to decide whether a finding is likely real or noise.
- `prompts/fp_filter.py` defines the output contract and classification rules for that LLM step.

### 3.4 AI remediation workflow

- `agent/agent.py` defines the LangGraph remediation state machine.
- `prompts/fix_templates.py` contains the vulnerability-specific fixing prompts.
- `agent/tools.py` provides the agent toolset for reading files, running tests, searching the repo, and producing a human-readable fix explanation.
- `agent/feedback_loop.py` builds the initial prompt, retry prompt, and response-cleaning logic.

### 3.5 Validation

- `validator.py` syntax-checks fixes, applies them to a temporary copy of the repository, runs tests, and optionally runs LLM-based verification.
- `agent/llm_judge.py` independently reviews a fix in a fresh model context.
- `agent/test_generator.py` can generate and execute a security-focused pytest when needed.

### 3.6 Outputs and presentation

- `patch_generator.py` builds a unified diff patch.
- `reporter.py` generates per-finding Markdown reports and a global summary report.
- `reviewer.py` provides terminal-based human approval for CLI interactive mode.
- `ui_app.py` exposes the pipeline through Streamlit.

## 4. End-to-End Runtime Flow

### 4.1 CLI entry

The pipeline starts in `main.py`.

`run_pipeline()` performs these stages:

1. Load YAML configuration
2. Register that config as the active runtime config for all downstream LLM calls
3. Parse the scan report
4. Keep only findings whose vulnerability types are enabled
5. Enrich each finding with source-code context
6. Run false-positive filtering
7. For each remaining finding, invoke the LangGraph remediation workflow
8. Generate a summary report

### 4.2 Finding schema

After parsing, each finding is normalized into a dict with fields such as:

- `vuln_type`
- `file_path`
- `line_number`
- `end_line`
- `severity`
- `description`
- `scanner_id`
- `rule_id`
- `raw`

### 4.3 Locate stage

`locator.py` enriches each finding with:

- `code_snippet`
- `full_context`
- `function_scope`
- `imports`
- `relocated_line_number`
- `locator_error`

If the reported scanner line is stale, blank, or outside the file, the locator tries to recover by choosing the nearest non-empty code line.

### 4.4 False-positive filter stage

`fp_filter.py` first performs deterministic prechecks to reject obviously irrelevant findings, such as:

- test files
- non-source files
- vendor or dependency directories
- findings with no usable location

If a finding survives prechecks, the LLM is asked to return a structured JSON decision:

- `is_false_positive`
- `confidence`
- `fp_reason`
- `checks`

The parser then normalizes the model response and enforces consistency rules, especially for:

- test-file detection
- sample/demo/example source files
- nearby-line matches

If the LLM call fails, SecureGuard keeps the finding by default rather than dropping it.

### 4.5 Remediation stage

For each filtered finding, `agent/agent.py` runs a LangGraph workflow with the following nodes:

- `generate_fix`
- `validate`
- `review`
- `patch`
- `report`
- `escalate`
- `skip`

The core loop is:

```text
generate_fix -> validate
validate -> retry | review | patch | escalate
review -> patch | skip
patch -> report -> END
escalate -> patch -> report -> END
skip -> report -> END
```

### 4.6 Fix generation behavior

`generate_fix_node()` does the following:

1. Combine a global remediation system prompt with a vulnerability-specific prompt from `prompts/fix_templates.py`
2. Build the initial or retry prompt from the vulnerability context
3. Construct a tool-enabled LangGraph ReAct agent
4. Invoke the model with history from previous failed attempts if present
5. Extract the full-file fixed code from the final AI response
6. Generate a plain-English explanation by calling `explain_fix_tool`

If the provider rejects tool calls, SecureGuard falls back to a no-tool generation path and asks the model to return only the fixed file content.

### 4.7 Validation stage

`validate_fix()` in `validator.py` validates a proposed fix in this order:

1. Clean LLM formatting artifacts from the generated code
2. Perform Python syntax checking with `ast.parse` if the target file is Python
3. Copy the repository into a temporary directory
4. Write the fix into the copied repo
5. Detect and run relevant tests
6. If enabled, run LLM-based verification as an additional validation layer

### 4.8 Validation modes

SecureGuard supports two validation modes.

#### Local-test-only mode

If `settings.enable_llm_fix_verification` is `false`, validation relies only on the repository test suite.

- If tests exist, their result is returned directly.
- If no tests exist, the fix is marked `NO_TESTS` and later treated as `UNVERIFIED`.

#### LLM-enhanced mode

If `settings.enable_llm_fix_verification` is `true`, SecureGuard always runs:

- the independent LLM judge
- and either local tests or an LLM-generated security test

This creates two verification signals:

- semantic review by the judge
- executable evidence from tests

### 4.9 Retry behavior

If validation fails and retries remain, the graph returns to `generate_fix`.

The retry prompt includes:

- previous attempts
- previous fix code
- failing test output
- explicit instructions to reason about what went wrong

If retries are exhausted, SecureGuard chooses the best attempt with the fewest failed tests and marks it `UNVERIFIED`.

### 4.10 Output generation

After a fix is accepted for output:

- `patch_generator.py` generates a unified diff and writes a `.patch` file
- `reporter.py` generates a Markdown report with:
  - vulnerability details
  - status
  - attempt summary
  - plain-English explanation
  - before/after code
  - unified diff
  - patch location

`generate_summary_report()` writes a summary report across all processed findings.

## 5. Configuration Model

The main runtime config is `config/vuln_config.yaml`.

### 5.1 LLM settings

The `llm` section defines:

- `provider`
- `model`
- `temperature`
- `max_retries`

Supported providers in `config/llm_factory.py`:

- `gemini`
- `anthropic`
- `openai`
- `github`
- `groq`
- `cerebras`
- `openrouter`
- `ollama`

### 5.2 Pipeline settings

The `settings` section defines:

- `max_retries`
- `confidence_threshold`
- `context_lines`
- `interactive_mode`
- `enable_llm_fix_verification`

### 5.3 Vulnerability catalog

The `vulnerabilities` section maps vulnerability types to metadata such as:

- `category`
- `severity`
- `fix_strategy`
- `prompt_key`
- `sample_file`

Important implementation detail:

- The project contains built-in prompts for 24 vulnerability types in `prompts/fix_templates.py`
- The current active YAML only enables a subset of those types; many others are present but commented out

## 6. LLM Configuration Propagation

One important runtime design detail is the active-config propagation mechanism in `config/llm_factory.py`.

`main.py` calls:

- `set_active_config(config)` at the start of `run_pipeline()`
- `clear_active_config()` when the pipeline ends

This means helper modules such as:

- `fp_filter.py`
- `agent/agent.py`
- `agent/llm_judge.py`
- `agent/test_generator.py`

can call `get_llm()` without being passed the config object explicitly, while still using the runtime config selected by the CLI or UI.

This is what makes UI-selected provider/model overrides work across the entire pipeline.

## 7. Streamlit UI

`ui_app.py` is a thin presentation layer over the same backend pipeline.

### 7.1 UI capabilities

The UI allows the user to:

- upload a JSON scan report
- provide a repo path
- choose all enabled vulnerability types or manually override the selection
- bulk-select or clear vulnerability types
- select provider and model
- change retries, FP threshold, temperature, context lines, and LLM verification mode
- run the pipeline with live log streaming
- inspect results
- view diff text
- download patch files
- approve or reject generated fixes in UI interactive mode

### 7.2 UI execution model

The UI does not reimplement the remediation logic.

Instead it:

1. Loads the base YAML config
2. Applies UI overrides to a temporary runtime config
3. Writes that runtime config to a temp file
4. Starts `main.run_pipeline()` in a background thread
5. Streams stdout/stderr back into the page through a queue

### 7.3 UI review behavior

The UI always calls the backend with `interactive=False` so the thread does not block waiting for terminal input.

Approval is handled after the run inside the UI itself by applying the chosen fix through `patch_generator.apply_patch()`.

### 7.4 UI server config

`.streamlit/config.toml` sets:

- `headless = true`
- `port = 8081`

## 8. Validation Strategy in Detail

The validator is central to project correctness.

### 8.1 Temporary repo model

SecureGuard never validates fixes directly in the original repository.

Instead, it:

1. Copies the repo into a temporary directory
2. Writes the proposed fix there
3. Runs tests against that copied repo
4. Deletes the temp directory afterward

This avoids mutating user code during validation.

### 8.2 Test discovery logic

`validator._detect_test_command()` looks for:

- `test_<filename>`
- `<name>_test.py`
- `tests/test_<filename>`
- `<dirname>/tests/test_<filename>`
- fallback test directories: `tests`, `test`, `sample_vulns/tests`
- fallback project-level pytest if `pyproject.toml` or `setup.py` is present

### 8.3 LLM Judge

`agent/llm_judge.py` runs a fresh LLM call with:

- vulnerability type
- fix strategy
- original vulnerable code
- proposed fixed code

It requests strict JSON with:

- `verdict`
- `confidence`
- `reason`

Allowed verdicts:

- `SAFE`
- `VULNERABLE`
- `UNCERTAIN`

### 8.4 LLM Test Generator

`agent/test_generator.py` runs another fresh LLM call to generate a single pytest function named `test_security_fix()`.

The generated test:

- imports the target file by absolute path using `importlib.util`
- attempts to exercise the relevant security property
- is executed in a temporary directory
- is discarded after validation

### 8.5 Current decision model

When LLM verification is enabled, `validator._ai_enhanced_validation()` combines:

- the judge result
- test evidence

The effective logic is:

- `SAFE` + passing tests -> success
- `VULNERABLE` -> failure
- `UNCERTAIN` + passing tests -> acceptable
- `UNCERTAIN` + failing tests -> failure
- inconclusive AI checks -> syntax-only fallback

## 9. Agent Tooling

`agent/tools.py` exposes four tools:

- `read_file_tool(file_path)`
- `run_tests_tool(file_path, fix_code, test_command=None)`
- `search_codebase_tool(pattern)`
- `explain_fix_tool(vulnerability_type, original_code, fixed_code)`

### 9.1 Tool purpose

- `read_file_tool` lets the LLM inspect a file before fixing it
- `run_tests_tool` allows optional in-agent validation during reasoning
- `search_codebase_tool` helps find related usage patterns in the repo
- `explain_fix_tool` produces a deterministic explanation of what changed and why

### 9.2 File restore behavior

`run_tests_tool()` writes a temporary fix into the real file, runs tests, and then restores the original content.

The current implementation is hardened:

- it reads original content into memory first
- creates an emergency backup file
- restores from memory using an atomic replace when possible
- falls back to the emergency backup if needed

## 10. Sample Repository

The `sample_vulns/` directory is a deliberately insecure mini-repository used for demos, testing, and evaluation.

### 10.1 Purpose

It provides:

- vulnerable source files for many security classes
- a demo scan target for `demo_report.json`
- baseline tests that simulate an existing unit test suite

### 10.2 Important behavior

The tests under `sample_vulns/tests` are not "security already fixed" assertions anymore.
They are baseline behavior tests intended to pass before remediation and continue passing after a correct fix.

This better matches the project requirement: validate that a security fix does not break existing functionality.

## 11. Output Artifacts

SecureGuard writes artifacts under `output/` by default.

Typical outputs:

- per-finding patch files: `*.patch`
- per-finding reports: `report_<file>_<vuln>.md`
- `summary_report.md`

There are also older generated artifacts inside `sample_vulns/output/` from previous demo runs.

## 12. Sonar Configuration

`sonar-project.properties` contains the Sonar project metadata and excludes intentionally vulnerable demo fixtures and generated output from analysis:

- `sample_vulns/**`
- `output/**`
- `venv/**`
- `**/__pycache__/**`

This prevents the demo corpus from polluting Sonar results for the actual product code.

## 13. GitHub Workflow File

The repository currently contains `build.yml` at the repo root.

It defines a Sonar scan job and an API callback step.

Important implementation note:

- GitHub Actions only auto-discovers workflow files under `.github/workflows/`
- if this file is intended to run automatically on GitHub, it should live under `.github/workflows/build.yml`

The current version uses secret references rather than plaintext tokens:

- `secrets.GIT_REPO_TOKEN`
- `secrets.SONAR_TOKEN`

## 14. Source File Map

This section explains the purpose of each important source file in the repository.

Generated output folders, caches, virtual environments, and compiled bytecode are intentionally excluded from the file-by-file breakdown.

### 14.1 Top-level application files

| File | Purpose |
|------|---------|
| `main.py` | Main CLI entry point and orchestration pipeline. Loads config, parses findings, locates code, filters false positives, runs remediation, and writes summary output. |
| `parser.py` | Normalizes scan reports from Semgrep, Bandit, or generic JSON into a common internal finding schema. |
| `locator.py` | Reads the target file, extracts code snippets and surrounding context, identifies imports, and finds the enclosing function scope. |
| `fp_filter.py` | Runs deterministic false-positive prechecks plus LLM-based false-positive analysis and response parsing. |
| `validator.py` | Applies a fix to a temp repo copy, runs tests, and optionally performs LLM-based judge and generated-test verification. |
| `patch_generator.py` | Generates unified diffs and writes patch files; also applies approved fixes in UI/interactive workflows. |
| `reporter.py` | Creates per-finding Markdown reports and the global summary report. |
| `reviewer.py` | Terminal review UI for CLI interactive mode. |
| `ui_app.py` | Streamlit UI that wraps the existing backend pipeline and streams logs/results live. |
| `demo_report.json` | Demo scan report pointing at the sample vulnerability repo. |
| `requirements.txt` | Python dependency list for the app, test tooling, Streamlit, and supported LLM providers. |
| `build.yml` | GitHub Actions workflow definition for Sonar scanning and API callback, currently stored at repo root. |
| `sonar-project.properties` | Sonar project metadata and exclusion rules. |
| `README.md` | Main user-facing documentation and project overview. |
| `USAGE_GUIDE.md` | More detailed user guidance and operational examples. |

### 14.2 `config/`

| File | Purpose |
|------|---------|
| `config/__init__.py` | Package marker. |
| `config/llm_factory.py` | Provider abstraction layer that creates the correct LangChain model instance and propagates active runtime config. |
| `config/vuln_config.yaml` | Main runtime config: provider/model settings, retry settings, FP threshold, validation mode, and enabled vulnerability metadata. |

### 14.3 `prompts/`

| File | Purpose |
|------|---------|
| `prompts/__init__.py` | Package marker. |
| `prompts/fix_templates.py` | Built-in vulnerability-specific remediation prompts. This is the main prompt library used by the remediation agent. |
| `prompts/fp_filter.py` | LLM prompt contract for false-positive filtering. Defines strict JSON output rules and decision criteria. |

### 14.4 `agent/`

| File | Purpose |
|------|---------|
| `agent/__init__.py` | Package marker. |
| `agent/agent.py` | LangGraph remediation workflow definition. Contains node logic, retry logic, escalation behavior, and patch/report transitions. |
| `agent/feedback_loop.py` | Builds first-attempt and retry prompts, cleans model output, and extracts code from responses. |
| `agent/tools.py` | Defines the LangChain tools available to the remediation agent. |
| `agent/llm_judge.py` | Independent security judge used during LLM-enhanced validation. |
| `agent/test_generator.py` | Generates and runs a temporary pytest security regression test during LLM-enhanced validation. |
| `agent/memory.py` | Conversation-memory helper for retry history. Present in the repo but not central to the current LangGraph flow, which mostly uses explicit message history in `agent.py`. |

### 14.5 `.streamlit/`

| File | Purpose |
|------|---------|
| `.streamlit/config.toml` | Streamlit runtime config, including the UI port (`8081`). |

### 14.6 `sample_vulns/` source files

| File | Purpose |
|------|---------|
| `sample_vulns/__init__.py` | Package marker for the sample repo. |
| `sample_vulns/sql_injection.py` | Example SQL injection cases used as remediation targets. |
| `sample_vulns/command_injection.py` | Example command injection cases. |
| `sample_vulns/ldap_injection.py` | Example LDAP injection cases. |
| `sample_vulns/xpath_injection.py` | Example XPath injection cases. |
| `sample_vulns/xss.py` | Example reflected/stored XSS style output rendering issues. |
| `sample_vulns/csrf.py` | Example CSRF-related insecure patterns. |
| `sample_vulns/open_redirect.py` | Example open redirect pattern. |
| `sample_vulns/xxe.py` | Example XXE parser misuse. |
| `sample_vulns/path_traversal.py` | Example path traversal file-access logic. |
| `sample_vulns/insecure_deserialization.py` | Example insecure deserialization patterns. |
| `sample_vulns/arbitrary_file_upload.py` | Example insecure file-upload handling. |
| `sample_vulns/log_injection.py` | Example unsafe log-writing behavior. |
| `sample_vulns/hardcoded_secrets.py` | Example secret-management mistakes. |
| `sample_vulns/weak_hashing.py` | Example weak password hashing or digest usage. |
| `sample_vulns/broken_jwt_auth.py` | Example JWT verification mistakes. |
| `sample_vulns/weak_randomness.py` | Example insecure randomness for tokens or identifiers. |
| `sample_vulns/insecure_eval.py` | Example `eval`/unsafe-expression execution. |
| `sample_vulns/debug_mode_in_prod.py` | Example insecure Flask debug/secret configuration. |
| `sample_vulns/overly_permissive_cors.py` | Example overly broad CORS policy. |
| `sample_vulns/missing_security_headers.py` | Example missing HTTP security headers. |
| `sample_vulns/redos.py` | Example catastrophic-regex/backtracking issues. |

### 14.7 `sample_vulns/tests/`

| File | Purpose |
|------|---------|
| `sample_vulns/tests/__init__.py` | Test package marker. |
| `sample_vulns/tests/test_sql_injection.py` | Baseline regression tests for the SQL injection sample. |
| `sample_vulns/tests/test_command_injection.py` | Baseline regression tests for the command injection sample. |
| `sample_vulns/tests/test_xss.py` | Baseline regression tests for the XSS sample. |
| `sample_vulns/tests/test_hardcoded_secrets.py` | Baseline regression tests for the hardcoded secrets sample. |
| `sample_vulns/tests/test_insecure_eval.py` | Baseline regression tests for the insecure eval sample. |
| `sample_vulns/tests/test_path_traversal.py` | Baseline regression tests for the path traversal sample. |
| `sample_vulns/tests/test_weak_randomness.py` | Baseline regression tests for the weak randomness sample. |
| `sample_vulns/tests/test_debug_mode_in_prod.py` | Baseline regression tests for the debug-mode sample. |
| `sample_vulns/tests/test_insecure_deserialization.py` | Baseline regression tests for the insecure deserialization sample. |
| `sample_vulns/tests/test_broken_jwt_auth.py` | Baseline regression tests for the broken JWT sample. |
| `sample_vulns/tests/test_redos.py` | Baseline regression tests for the regex/ReDoS sample. |

## 15. Current Design Notes and Constraints

### 15.1 Tool-calling fallback

Some model/provider combinations do not reliably emit valid structured tool calls.
To make the pipeline more robust, `agent/agent.py` includes a no-tool fallback generation path when provider-side tool calling is rejected.

### 15.2 LLM response normalization

Multiple modules now normalize provider response content because some providers return list-based content blocks rather than plain strings.
This normalization exists in:

- `agent/feedback_loop.py`
- `fp_filter.py`
- `agent/llm_judge.py`
- `agent/test_generator.py`

### 15.3 Current config vs full capability

The codebase supports more vulnerability types than are enabled in the current YAML.
The active set is controlled by `config/vuln_config.yaml`, not by the size of `prompts/fix_templates.py`.

### 15.4 Memory helper status

`agent/memory.py` exists, but the current remediation path does not rely on a persistent memory object.
Instead, previous attempt history is injected directly into prompt messages in `agent/agent.py`.

## 16. Recommended Reading Order

For someone trying to understand the project quickly, the most effective reading order is:

1. `README.md`
2. `main.py`
3. `parser.py`
4. `locator.py`
5. `fp_filter.py`
6. `agent/agent.py`
7. `validator.py`
8. `patch_generator.py`
9. `reporter.py`
10. `ui_app.py`
11. `config/vuln_config.yaml`
12. `prompts/fix_templates.py`

## 17. Summary

SecureGuard AI is currently implemented as a configurable remediation system with:

- structured parsing
- code localization
- LLM-based false-positive filtering
- LangGraph-based fix generation with retries
- local-test validation
- optional LLM judge and generated-test verification
- patch generation
- Markdown reporting
- Streamlit UI execution

The codebase is organized clearly enough that each stage is modular, but the most important runtime path is:

`main.py -> parser.py -> locator.py -> fp_filter.py -> agent/agent.py -> validator.py -> patch_generator.py -> reporter.py`

This document is intended to be self-contained and suitable for ingestion into NotebookLM or similar document-aware tools.
