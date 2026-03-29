# SecureGuard AI — Complete User Guide

> **SecureGuard AI** reads a security scanner's report, finds the vulnerable code in your project,
> uses an AI agent to generate a fix, validates the fix against your test suite, and hands you a
> PR-ready `.patch` file — all in one command.

---

## Table of Contents

1. [What You Need Before Starting](#1-what-you-need-before-starting)
2. [Installation](#2-installation)
3. [Choose Your AI Provider & Get an API Key](#3-choose-your-ai-provider--get-an-api-key)
4. [Configure the Project](#4-configure-the-project)
5. [Prepare Your Scan Report](#5-prepare-your-scan-report)
6. [Enable Vulnerability Types](#6-enable-vulnerability-types)
7. [Run SecureGuard AI](#7-run-secureguard-ai)
8. [Understanding the Output](#8-understanding-the-output)
9. [Interactive Mode (Human Review)](#9-interactive-mode-human-review)
10. [Common Problems & Fixes](#10-common-problems--fixes)
11. [Quick Reference — All CLI Flags](#11-quick-reference--all-cli-flags)
12. [Provider Summary Table](#12-provider-summary-table)

---

## 1. What You Need Before Starting

| Requirement | Details |
|-------------|---------|
| **Python** | Version **3.10 or newer** |
| **pip** | Comes with Python |
| **A terminal** | Bash, Zsh, PowerShell, or any terminal |
| **One AI API key** | Free options available — see Section 3 |
| **A SAST scan report** | JSON file from Semgrep, Bandit, or SecureGuard format |

Check your Python version:
```bash
python3 --version
# Should print: Python 3.10.x or higher
```

---

## 2. Installation

### Step 1 — Get the project

```bash
git clone <your-repo-url>
cd secureguard
```

### Step 2 — Create a virtual environment (strongly recommended)

```bash
# Create the virtual environment
python3 -m venv venv

# Activate it (Linux / macOS)
source venv/bin/activate

# Activate it (Windows Command Prompt)
venv\Scripts\activate.bat

# Activate it (Windows PowerShell)
venv\Scripts\Activate.ps1
```

You will see `(venv)` at the start of your terminal prompt when it is active.

### Step 3 — Install dependencies

```bash
pip install -r requirements.txt
```

Verify the install worked:
```bash
python3 -c "import langchain; import langgraph; print('Installation OK')"
```

---

## 3. Choose Your AI Provider & Get an API Key

SecureGuard AI supports **8 different AI providers**. You only need **one**.

---

### Option A — Groq (Recommended for Beginners — Free)

Groq gives you **free API access** to fast Llama models. No credit card required.

1. Go to **https://console.groq.com**
2. Click **Sign Up** (use Google or email)
3. Click **API Keys** in the left sidebar → **Create API Key**
4. Copy the key — it starts with `gsk_...`

**`.env` file:**
```
GROQ_API_KEY=gsk_your_key_here
```

**`config/vuln_config.yaml`:**
```yaml
llm:
  provider: groq
  model: llama-3.3-70b-versatile
```

**Other good Groq models:**
```
llama-3.1-8b-instant      # fastest, lowest latency
llama3-70b-8192           # great for complex fixes
mixtral-8x7b-32768        # good alternative
```

---

### Option B — Cerebras (Extremely Fast — Free Tier)

Cerebras runs Llama models on dedicated hardware — hundreds of tokens per second.

1. Go to **https://cloud.cerebras.ai**
2. Click **Sign Up**
3. Go to **API Keys** → **Create new API key**
4. Copy the key — it starts with `csk-...`

**`.env` file:**
```
CEREBRAS_API_KEY=csk_your_key_here
```

**`config/vuln_config.yaml`:**
```yaml
llm:
  provider: cerebras
  model: llama3.1-8b
```

**Other Cerebras models:**
```
llama3.1-70b
llama-4-scout-17b-16e-instruct
```

**Install the extra package:**
```bash
pip install langchain-cerebras
```

---

### Option C — OpenRouter (Access 200+ Models via One Key)

OpenRouter is a gateway to models from OpenAI, Anthropic, Meta, Mistral, Google — many with a **free tier**.

1. Go to **https://openrouter.ai**
2. Click **Sign In** (Google, GitHub, or email)
3. Click your profile icon → **Keys** → **Create Key**
4. Copy the key — it starts with `sk-or-...`

**`.env` file:**
```
OPENROUTER_API_KEY=sk-or-your_key_here
```

**`config/vuln_config.yaml`:**
```yaml
llm:
  provider: openrouter
  model: meta-llama/llama-3.3-70b-instruct:free
```

**Popular free OpenRouter models:**
```
meta-llama/llama-3.3-70b-instruct:free   # free Llama 70B
google/gemini-2.0-flash:free             # free Gemini Flash
deepseek/deepseek-r1:free                # free reasoning model
mistralai/mistral-7b-instruct:free       # free Mistral
```

**Popular paid OpenRouter models:**
```
openai/gpt-4o
anthropic/claude-3-5-sonnet
openai/gpt-4o-mini
```

> Browse all models at: https://openrouter.ai/models

---

### Option D — OpenAI (GPT-4o)

1. Go to **https://platform.openai.com**
2. Sign up or log in
3. Click **API Keys** → **+ Create new secret key**
4. Copy the key — starts with `sk-...` (shown only once!)

Add credits at: **Billing → Add payment method** (min $5)

**`.env` file:**
```
OPENAI_API_KEY=sk-your_key_here
```

**`config/vuln_config.yaml`:**
```yaml
llm:
  provider: openai
  model: gpt-4o
```

---

### Option E — Anthropic (Claude)

1. Go to **https://console.anthropic.com**
2. Sign up and verify your email
3. Click **API Keys** → **Create Key**
4. Copy the key — starts with `sk-ant-...`

**`.env` file:**
```
ANTHROPIC_API_KEY=sk-ant-your_key_here
```

**`config/vuln_config.yaml`:**
```yaml
llm:
  provider: anthropic
  model: claude-opus-4-5
```

**Other Claude models:**
```
claude-3-5-haiku-20241022   # fast and cheap
claude-sonnet-4-5           # balanced
```

---

### Option F — Google Gemini

1. Go to **https://aistudio.google.com**
2. Sign in with your Google account
3. Click **Get API key** → **Create API key**
4. Copy the key — starts with `AIza...`

**`.env` file:**
```
GOOGLE_API_KEY=AIza_your_key_here
```

**`config/vuln_config.yaml`:**
```yaml
llm:
  provider: gemini
  model: gemini-2.0-flash
```

---

### Option G — GitHub Models (Free with Any GitHub Account)

1. Go to **https://github.com/settings/tokens**
2. Click **Generate new token (classic)**
3. Give it a name, no special scopes needed → **Generate token**
4. Copy the token — starts with `ghp_...`

**`.env` file:**
```
GITHUB_TOKEN=ghp_your_token_here
```

**`config/vuln_config.yaml`:**
```yaml
llm:
  provider: github
  model: gpt-4o
```

**Other GitHub Models:**
```
gpt-4o-mini
Meta-Llama-3.1-70B-Instruct
Mistral-large
```

---

### Option H — Ollama (100% Local, No Internet, No Key)

Ollama runs AI models completely on your computer. No API key, no internet, completely private.

1. Download from **https://ollama.ai** and install
2. Pull a model:
   ```bash
   ollama pull llama3:8b
   ```
3. Verify it works:
   ```bash
   ollama run llama3:8b "Say hello"
   ```

**`.env` file:**
```
# No key needed for Ollama
```

**`config/vuln_config.yaml`:**
```yaml
llm:
  provider: ollama
  model: llama3:8b
```

**Other Ollama models:**
```bash
ollama pull codellama:13b
ollama pull deepseek-coder-v2
ollama pull qwen2.5-coder:7b
```

> **Note:** Requires 8GB RAM for 7b models, 16GB for 13b models.

---

## 4. Configure the Project

### Step 1 — Create your `.env` file

```bash
cp .env.example .env
```

Open `.env` in any text editor and add your API key. Example for Groq:
```
GROQ_API_KEY=gsk_your_actual_key_here
```

### Step 2 — Set your provider in `config/vuln_config.yaml`

```yaml
llm:
  provider: groq                      # ← your chosen provider
  model: llama-3.3-70b-versatile      # ← matching model name
  temperature: 0
  max_retries: 6
```

---

## 5. Prepare Your Scan Report

### Using Semgrep (Free)

```bash
pip install semgrep
semgrep --config=auto ./your-project --json -o scan_report.json
```

### Using Bandit (Python projects)

```bash
pip install bandit
bandit -r ./your-project -f json -o scan_report.json
```

### Use the built-in demo report

A ready-made report (`demo_report.json`) is already included:
```bash
ls demo_report.json   # already there
```

### Manual custom format

```json
{
  "vulnerabilities": [
    {
      "type": "sql_injection",
      "file_path": "app/database.py",
      "line_number": 42,
      "severity": "HIGH",
      "description": "SQL query built with string concatenation"
    }
  ]
}
```

---

## 6. Enable Vulnerability Types

Open `config/vuln_config.yaml` and scroll to `vulnerabilities:`.

By default only `sql_injection` is enabled. To enable more, **uncomment** the lines (remove the `#`):

```yaml
vulnerabilities:
  sql_injection:
    category: Injection
    severity: HIGH
    fix_strategy: "String concat in queries -> parameterized statements"
    prompt_key: sql_injection
    sample_file: sample_vulns/sql_injection.py

  xss:
    category: Web
    severity: HIGH
    fix_strategy: "Unescaped output -> HTML escape"
    prompt_key: xss
    sample_file: sample_vulns/xss.py
```

**All 24 built-in vulnerability types:**

| Category | Types |
|----------|-------|
| Injection | `sql_injection`, `command_injection`, `ldap_injection`, `xpath_injection` |
| Web | `xss`, `csrf`, `open_redirect`, `xxe` |
| File & Data | `path_traversal`, `insecure_deserialization`, `arbitrary_file_upload`, `log_injection` |
| Auth & Crypto | `hardcoded_secrets`, `weak_hashing`, `broken_jwt_auth`, `weak_randomness` |
| Code & Config | `insecure_eval`, `debug_mode_in_prod`, `overly_permissive_cors`, `missing_security_headers` |
| Resource & Memory | `buffer_overflow`, `use_after_free`, `integer_overflow`, `redos` |

> **Important:** Only vulnerabilities that appear in the scan report **AND** are enabled in `vuln_config.yaml` will be processed. Disabled types are completely ignored.

---

## 7. Run SecureGuard AI

### Basic run

```bash
python main.py --scan demo_report.json --repo .
```

### Run on your own project

```bash
python main.py --scan scan_report.json --repo ./my-web-app
```

### Verbose output (see AI reasoning)

```bash
python main.py --scan demo_report.json --repo . --verbose
```

### Specific vulnerability types only

```bash
python main.py --scan demo_report.json --repo . --vuln-types sql_injection,xss
```

### Interactive mode (review each fix)

```bash
python main.py --scan demo_report.json --repo . --interactive
```

### More retries per vulnerability

```bash
python main.py --scan demo_report.json --repo . --max-retries 5
```

### Custom config file

```bash
python main.py --scan demo_report.json --repo . --config ./my_config.yaml
```

---

## 8. Understanding the Output

### Terminal output explained

```
[Stage 1] Parsing scan report...
  Found 8 vulnerability findings in report
  1 finding(s) match enabled vulnerability types: ['sql_injection']
```
→ 8 total in report, 1 matches what is enabled in config.

```
[Stage 2] Locating vulnerable code...
  ✅ sql_injection at sample_vulns/sql_injection.py:15
```
→ Found the exact file and line.

```
[Stage 3] Filtering false positives...
  1 true positives, 0 false positives filtered
```
→ LLM confirmed it's a real vulnerability.

```
[Agent] Generating fix - Attempt 1
[Validate] Testing fix (attempt 1)...
  Passed: 5, Failed: 0
Result: VERIFIED
```
→ Fix generated and all tests pass.

### Output files

```
output/
├── summary_report.md          ← Overall summary
├── report_..._sql_injection.md ← Per-vulnerability Markdown report
└── ...sql_injection_...patch  ← Git-ready patch file
```

Apply the patch:
```bash
git apply output/your_patch_file.patch
```

### Status meanings

| Status | Meaning |
|--------|---------|
| ✅ VERIFIED | Fix generated and all tests passed |
| ⚠️ UNVERIFIED | Fix generated but tests still fail — review manually |
| ⏭️ SKIPPED | You rejected the fix in interactive mode |
| 🔍 SYNTAX-ONLY | No test suite found; fix passed syntax check only |

---

## 9. Interactive Mode (Human Review)

```bash
python main.py --scan demo_report.json --repo . --interactive
```

You will see a color-coded diff for each fix and a prompt:
```
  Approve this fix? [y/n]:
```
- `y` → Patch file is generated
- `n` → Vulnerability is skipped

---

## 10. Common Problems & Fixes

### "No findings match the enabled vulnerability types"

The scan report has findings but none match what is enabled in config.

**Fix:** Enable the right types in `config/vuln_config.yaml`, or use:
```bash
python main.py --scan report.json --repo . --vuln-types xss,command_injection
```

---

### "GROQ_API_KEY environment variable not set"

**Fix:**
```bash
cp .env.example .env
# Then edit .env and add: GROQ_API_KEY=gsk_...
```

Make sure you run the command from inside the `secureguard/` folder.

---

### "ModuleNotFoundError: No module named 'langchain_cerebras'"

**Fix:**
```bash
pip install langchain-cerebras
```

---

### The fix keeps failing tests (UNVERIFIED)

1. Try a larger model in `config/vuln_config.yaml`
2. Increase `--max-retries 5`
3. Check `output/report_*.md` — it shows each attempt and the exact test failure
4. If no tests exist in the repo, the result will be `SYNTAX-ONLY-VERIFIED` which is expected

---

### OpenRouter: model not found

Make sure the model ID is exact. Copy it from https://openrouter.ai/models:
```yaml
model: meta-llama/llama-3.3-70b-instruct:free   # note the :free suffix
```

---

## 11. Quick Reference — All CLI Flags

```
python main.py [flags]

Required:
  --scan REPORT.JSON     Path to the SAST scan report
  --repo ./PROJECT       Path to the target repository

Optional:
  --interactive          Pause and ask approval before each patch is applied
  --verbose              Show detailed agent reasoning
  --max-retries N        Fix retry limit per vulnerability (default: 3)
  --vuln-types TYPE,...  Comma-separated list to override config (e.g. sql_injection,xss)
  --config CONFIG.YAML   Use a different config file

Examples:
  python main.py --scan report.json --repo ./myapp
  python main.py --scan report.json --repo ./myapp --interactive --verbose --max-retries 5
  python main.py --scan report.json --repo ./myapp --vuln-types sql_injection,xss
  python main.py --scan demo_report.json --repo .
```

---

## 12. Provider Summary Table

| Provider | Free? | Speed | Best For | Env Var Needed |
|----------|-------|-------|----------|----------------|
| **Groq** | ✅ Free tier | ⚡ Very fast | Getting started | `GROQ_API_KEY` |
| **Cerebras** | ✅ Free tier | ⚡⚡ Fastest | Speed | `CEREBRAS_API_KEY` |
| **OpenRouter** | ✅ Many free models | Varies | Model flexibility | `OPENROUTER_API_KEY` |
| **OpenAI** | ❌ Paid | Fast | Best accuracy | `OPENAI_API_KEY` |
| **Anthropic** | ❌ Paid | Fast | Long context | `ANTHROPIC_API_KEY` |
| **Gemini** | ✅ Free tier | Fast | Google ecosystem | `GOOGLE_API_KEY` |
| **GitHub Models** | ✅ Free | Fast | GitHub users | `GITHUB_TOKEN` |
| **Ollama** | ✅ Free (local) | Hardware dependent | Privacy / offline | None needed |

---

*SecureGuard AI — Scan report in. PR-ready fix out.*
