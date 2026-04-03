"""
ui_app.py — Streamlit UI for SecureGuard AI.

Launch:
    streamlit run ui_app.py

Integrates directly with the existing backend (main.py, agent, patch_generator, etc.)
without duplicating any business logic.
"""

import os
import sys
import io
import json
import tempfile
import traceback
import threading
import queue
import time

import streamlit as st
import yaml
from dotenv import load_dotenv

# ── Load .env so all API keys are available ──
load_dotenv()

# ── Ensure project root is on sys.path ──
PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)


# ────────────────────────────────────────────────────────────────────
# Page config
# ────────────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="SecureGuard AI",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ────────────────────────────────────────────────────────────────────
# Custom CSS
# ────────────────────────────────────────────────────────────────────
st.markdown("""
<style>
    /* ── Header ── */
    .main-header {
        background: linear-gradient(135deg, #0f0c29, #302b63, #24243e);
        padding: 2rem 2.5rem;
        border-radius: 12px;
        margin-bottom: 1.5rem;
        color: #ffffff;
    }
    .main-header h1 {
        margin: 0;
        font-size: 2rem;
        font-weight: 700;
        letter-spacing: -0.5px;
    }
    .main-header p {
        margin: 0.3rem 0 0 0;
        opacity: 0.75;
        font-size: 0.95rem;
    }

    /* ── Section headers ── */
    .section-header {
        border-left: 4px solid #6366f1;
        padding-left: 12px;
        margin: 1.5rem 0 1rem 0;
        font-size: 1.15rem;
        font-weight: 600;
    }

    /* ── Status badges ── */
    .badge {
        display: inline-block;
        padding: 4px 14px;
        border-radius: 20px;
        font-size: 0.85rem;
        font-weight: 600;
        margin-right: 6px;
    }
    .badge-verified   { background: #064e3b; color: #6ee7b7; }
    .badge-unverified { background: #78350f; color: #fcd34d; }
    .badge-skipped    { background: #1e3a5f; color: #93c5fd; }
    .badge-error      { background: #7f1d1d; color: #fca5a5; }
    .badge-syntax     { background: #312e81; color: #a5b4fc; }

    /* ── Stat card ── */
    .stat-card {
        background: #1e1e2e;
        border: 1px solid #333;
        border-radius: 10px;
        padding: 1rem 1.2rem;
        text-align: center;
    }
    .stat-card .number {
        font-size: 2rem;
        font-weight: 700;
        color: #818cf8;
    }
    .stat-card .label {
        font-size: 0.8rem;
        color: #9ca3af;
        text-transform: uppercase;
        letter-spacing: 1px;
    }

    /* tighten spacing */
    .block-container { padding-top: 1.5rem; }
</style>
""", unsafe_allow_html=True)


# ────────────────────────────────────────────────────────────────────
# All 24 supported vulnerability types (grouped for the multiselect)
# ────────────────────────────────────────────────────────────────────
ALL_VULN_TYPES = {
    "Injection": ["sql_injection", "command_injection", "ldap_injection", "xpath_injection"],
    "Web": ["xss", "csrf", "open_redirect", "xxe"],
    "File & Data": ["path_traversal", "insecure_deserialization", "arbitrary_file_upload", "log_injection"],
    "Auth & Crypto": ["hardcoded_secrets", "weak_hashing", "broken_jwt_auth", "weak_randomness"],
    "Code & Config": ["insecure_eval", "debug_mode_in_prod", "overly_permissive_cors", "missing_security_headers"],
    "Resource & Memory": ["buffer_overflow", "use_after_free", "integer_overflow", "redos"],
}
ALL_VULN_FLAT = [v for group in ALL_VULN_TYPES.values() for v in group]
PROVIDER_OPTIONS = ["github", "groq", "openai", "anthropic", "gemini", "cerebras", "openrouter", "ollama"]


# ────────────────────────────────────────────────────────────────────
# Helpers
# ────────────────────────────────────────────────────────────────────
def _status_badge(status: str) -> str:
    """Return an HTML badge for a result status."""
    css = {
        "VERIFIED": "badge-verified",
        "UNVERIFIED": "badge-unverified",
        "SKIPPED": "badge-skipped",
        "ERROR": "badge-error",
        "SYNTAX-ONLY-VERIFIED": "badge-syntax",
    }
    label = {
        "VERIFIED": "✅ Verified",
        "UNVERIFIED": "⚠️ Unverified",
        "SKIPPED": "⏭️ Skipped",
        "ERROR": "❌ Error",
        "SYNTAX-ONLY-VERIFIED": "🔍 Syntax Only",
    }
    cls = css.get(status, "badge-error")
    txt = label.get(status, status)
    return f'<span class="badge {cls}">{txt}</span>'


def _load_ui_base_config() -> dict:
    """Load the default YAML so the UI starts from the same values as the CLI."""
    config_path = os.path.join(PROJECT_ROOT, "config", "vuln_config.yaml")
    if not os.path.exists(config_path):
        return {}

    with open(config_path, "r") as f:
        return yaml.safe_load(f) or {}


def _set_vuln_selection(value: bool) -> None:
    """Bulk toggle all vulnerability checkboxes in session state."""
    for vtype in ALL_VULN_FLAT:
        st.session_state[f"vuln_cb_{vtype}"] = value


class QueueWriter(io.TextIOBase):
    """A file-like object that pushes each write() into a thread-safe queue.
    This replaces stdout/stderr so that the pipeline's print() calls can be
    read in real-time by the main Streamlit thread."""

    def __init__(self, log_queue: queue.Queue):
        self._q = log_queue

    def write(self, text: str):
        if text:  # skip empty writes
            self._q.put(text)
        return len(text) if text else 0

    def flush(self):
        pass


def _run_pipeline_in_thread(
    scan_path: str,
    repo_path: str,
    config_path: str,
    max_retries: int,
    vuln_types: list,
    log_queue: queue.Queue,
    result_holder: dict,
):
    """Target function for the background thread. Runs the pipeline,
    redirecting stdout/stderr into the shared queue so the UI can
    stream logs in real-time."""
    old_out, old_err = sys.stdout, sys.stderr
    writer = QueueWriter(log_queue)
    sys.stdout = writer
    sys.stderr = writer
    try:
        from main import run_pipeline
        results = run_pipeline(
            scan_report=scan_path,
            repo_path=repo_path,
            interactive=False,  # never block in UI; we handle review ourselves
            config_path=config_path,
            max_retries=max_retries,
            vuln_types=vuln_types if vuln_types else None,
            verbose=True,
        )
        result_holder["results"] = results
    except Exception:
        result_holder["error"] = traceback.format_exc()
    finally:
        sys.stdout = old_out
        sys.stderr = old_err
        log_queue.put(None)  # sentinel: "thread is done"


# ────────────────────────────────────────────────────────────────────
# Header
# ────────────────────────────────────────────────────────────────────
st.markdown("""
<div class="main-header">
    <h1>🛡️ SecureGuard AI</h1>
    <p>AI-Powered Security Vulnerability Detection &amp; Code Remediation</p>
</div>
""", unsafe_allow_html=True)


# ────────────────────────────────────────────────────────────────────
# Session state defaults
# ────────────────────────────────────────────────────────────────────
DEFAULTS = {
    "pipeline_results": None,
    "pipeline_logs": "",
    "pipeline_error": None,
    "pipeline_running": False,
    "approval_decisions": {},  # keyed by result index
}
for key, val in DEFAULTS.items():
    if key not in st.session_state:
        st.session_state[key] = val


# ────────────────────────────────────────────────────────────────────
# SECTION 1 — INPUTS (sidebar)
# ────────────────────────────────────────────────────────────────────
ui_base_config = _load_ui_base_config()
ui_llm_defaults = ui_base_config.get("llm", {})
ui_settings_defaults = ui_base_config.get("settings", {})
default_provider = ui_llm_defaults.get("provider", "github")
default_model = ui_llm_defaults.get("model", "gpt-4o")
default_provider_index = PROVIDER_OPTIONS.index(default_provider) if default_provider in PROVIDER_OPTIONS else 0
default_review_mode = "interactive" if ui_settings_defaults.get("interactive_mode", False) else "automatic"

with st.sidebar:
    st.markdown("### ⚙️ Configuration")

    # -- Upload scan report --
    st.markdown('<div class="section-header">📄 Scan Report</div>', unsafe_allow_html=True)
    uploaded_file = st.file_uploader(
        "Upload Scan Report",
        type=["json"],
        help="JSON output from Semgrep, Bandit, or SecureGuard format.",
    )
    if uploaded_file:
        st.success(f"Loaded: **{uploaded_file.name}**")

    # -- Repository path --
    st.markdown('<div class="section-header">📁 Repository</div>', unsafe_allow_html=True)
    repo_path = st.text_input(
        "Repository Path",
        value=".",
        help="Absolute or relative path to the target project.",
    )

    # -- Vulnerability type selector --
    st.markdown('<div class="section-header">🎯 Vulnerability Types</div>', unsafe_allow_html=True)
    vuln_select_mode = st.radio(
        "Which vulnerabilities to scan?",
        options=["All types from config", "Select specific types"],
        index=0,
        help=(
            "Use the config option if you want the UI to respect the enabled types in "
            "`config/vuln_config.yaml`. Use the specific option when you want to override "
            "that list for this run."
        ),
        label_visibility="collapsed",
    )

    selected_vuln_types = []
    if vuln_select_mode == "Select specific types":
        st.caption("Use `Select all types` to start with every option checked, then untick the few you want to exclude.")
        bulk_col1, bulk_col2 = st.columns(2)
        with bulk_col1:
            if st.button("Select all types", key="select_all_vuln_types", use_container_width=True):
                _set_vuln_selection(True)
        with bulk_col2:
            if st.button("Clear all", key="clear_all_vuln_types", use_container_width=True):
                _set_vuln_selection(False)

        # Show grouped checkboxes for each category
        for category, types in ALL_VULN_TYPES.items():
            with st.expander(f"📂 {category}", expanded=False):
                for vtype in types:
                    display_name = vtype.replace("_", " ").title()
                    checkbox_key = f"vuln_cb_{vtype}"
                    if checkbox_key not in st.session_state:
                        st.session_state[checkbox_key] = False
                    if st.checkbox(display_name, key=checkbox_key):
                        selected_vuln_types.append(vtype)

        if selected_vuln_types:
            st.info(f"**{len(selected_vuln_types)}** type(s) selected: {', '.join(selected_vuln_types)}")
        else:
            st.warning("No types selected — select at least one.")

    # -- Config panel --
    st.markdown('<div class="section-header">🔧 LLM &amp; Pipeline</div>', unsafe_allow_html=True)
    with st.expander("Advanced Configuration", expanded=False):
        st.info(
            "These controls affect how SecureGuard reasons about the scan, generates fixes, "
            "and decides whether a proposed patch is safe enough to present."
        )
        provider = st.selectbox(
            "LLM Provider",
            options=PROVIDER_OPTIONS,
            index=default_provider_index,
            key="ui_provider",
            help=(
                "This chooses which AI service SecureGuard talks to. Pick the provider that "
                "matches the API key you already configured in `.env`. If you choose the wrong "
                "provider, the run will fail before remediation starts."
            ),
        )
        st.caption(
            "Provider = the company or runtime serving the model. Example: `openai` uses "
            "`OPENAI_API_KEY`, `groq` uses `GROQ_API_KEY`, and `ollama` uses your local model server."
        )
        model = st.text_input(
            "Model Name",
            value=default_model,
            key="ui_model",
            help=(
                "Enter the exact model identifier for the selected provider. Larger models "
                "are usually better at reasoning about fixes, but they are often slower and cost more."
            ),
        )
        st.caption(
            "Model = the specific AI engine. This must be a valid name for the provider above, "
            "for example `gpt-4o`, `claude-sonnet-4-6`, or `llama-3.3-70b-versatile`."
        )
        max_retries = st.slider(
            "Max Retries",
            min_value=1,
            max_value=10,
            value=int(ui_settings_defaults.get("max_retries", 3)),
            key="ui_max_retries",
            help=(
                "How many repair attempts SecureGuard can make for the same finding. If the "
                "first patch breaks tests or fails validation, the agent will try again until this limit is reached."
            ),
        )
        st.caption("Higher values give the agent more chances to recover from a bad patch, but each extra attempt increases runtime and token usage.")
        review_mode = st.selectbox(
            "Review Mode",
            options=["automatic", "interactive"],
            index=0 if default_review_mode == "automatic" else 1,
            key="ui_review_mode",
            help=(
                "Automatic mode runs the full pipeline end to end. Interactive mode pauses on each proposed fix "
                "so you can approve or reject it from the UI before anything is applied."
            ),
        )
        st.caption("Choose `interactive` if you want a manual checkpoint before applying a generated fix.")
        fp_threshold = st.slider(
            "FP Confidence Threshold",
            min_value=0.0,
            max_value=1.0,
            value=float(ui_settings_defaults.get("confidence_threshold", 0.75)),
            step=0.05,
            key="ui_fp_threshold",
            help=(
                "This controls how strict the false-positive filter is. Higher values mean the model "
                "must be more confident that a finding is real before SecureGuard keeps it for remediation."
            ),
        )
        st.caption("If you raise this too much, real findings may be filtered out. If you lower it too much, more noisy findings will reach the fix stage.")
        temperature = st.slider(
            "Temperature",
            min_value=0.0,
            max_value=1.0,
            value=float(ui_llm_defaults.get("temperature", 0.0)),
            step=0.05,
            key="ui_temperature",
            help=(
                "Controls how predictable the model is. Lower values keep output consistent and are usually "
                "better for code fixes. Higher values allow more variation, which can help exploration but may reduce stability."
            ),
        )
        st.caption("For remediation work, `0.0` to `0.2` is usually safest because you want repeatable code, not creative phrasing.")
        context_lines = st.slider(
            "Context Lines",
            min_value=5,
            max_value=50,
            value=int(ui_settings_defaults.get("context_lines", 20)),
            key="ui_context_lines",
            help=(
                "How much code around the reported line is sent into the pipeline. More context helps the model "
                "understand surrounding functions and imports, but it also increases prompt size."
            ),
        )
        st.caption("If fixes look too narrow or miss nearby helper code, increase this. If prompts are too large, reduce it.")
        enable_llm_fix_verification = st.checkbox(
            "Enable LLM Fix Verification",
            value=bool(ui_settings_defaults.get("enable_llm_fix_verification", True)),
            key="ui_enable_llm_fix_verification",
            help=(
                "When enabled, SecureGuard does more than just run tests. It also asks an independent LLM judge "
                "to review the patch, and when no local tests exist it can generate a security-focused test for extra validation."
            ),
        )
        st.caption(
            "Turn this off if you want validation to rely only on the repository's existing tests. "
            "If no local tests exist and this is off, the fix stays unverified."
        )

    interactive = review_mode == "interactive"


# ────────────────────────────────────────────────────────────────────
# SECTION 2 — RUN BUTTON
# ────────────────────────────────────────────────────────────────────
col_run, col_clear = st.columns([3, 1])
with col_run:
    run_clicked = st.button("🚀 Run SecureGuard", use_container_width=True, type="primary")
with col_clear:
    if st.button("🗑️ Clear Results", use_container_width=True):
        for key, val in DEFAULTS.items():
            st.session_state[key] = val
        st.rerun()

if run_clicked:
    # ── Validate inputs ──
    errors = []
    if uploaded_file is None:
        errors.append("Please upload a scan report (JSON).")
    if not repo_path or not repo_path.strip():
        errors.append("Please enter a repository path.")
    elif not os.path.isdir(repo_path):
        errors.append(f"Repository path does not exist: `{repo_path}`")
    if vuln_select_mode == "Select specific types" and not selected_vuln_types:
        errors.append("Please select at least one vulnerability type.")

    if errors:
        for e in errors:
            st.error(e)
    else:
        # ── Save uploaded file to temp location ──
        tmp_dir = tempfile.mkdtemp(prefix="sg_scan_")
        scan_path = os.path.join(tmp_dir, uploaded_file.name)
        with open(scan_path, "wb") as f:
            f.write(uploaded_file.getvalue())

        # ── Build a temporary config override ──
        base_config_path = os.path.join(PROJECT_ROOT, "config", "vuln_config.yaml")
        if os.path.exists(base_config_path):
            with open(base_config_path, "r") as f:
                runtime_config = yaml.safe_load(f) or {}
        else:
            runtime_config = {}

        # Override LLM section with sidebar values
        runtime_config.setdefault("llm", {})
        runtime_config["llm"]["provider"] = provider
        runtime_config["llm"]["model"] = model

        # Override LLM temperature
        runtime_config["llm"]["temperature"] = temperature

        # Override settings
        runtime_config.setdefault("settings", {})
        runtime_config["settings"]["max_retries"] = max_retries
        runtime_config["settings"]["confidence_threshold"] = fp_threshold
        runtime_config["settings"]["interactive_mode"] = interactive
        runtime_config["settings"]["context_lines"] = context_lines
        runtime_config["settings"]["enable_llm_fix_verification"] = enable_llm_fix_verification

        # If user selected specific vuln types, override the config's
        # vulnerabilities section to contain ONLY those types.
        if vuln_select_mode == "Select specific types" and selected_vuln_types:
            vuln_overrides = {}
            for vtype in selected_vuln_types:
                vuln_overrides[vtype] = {
                    "category": "User Selected",
                    "severity": "HIGH",
                    "prompt_key": vtype,
                }
            runtime_config["vulnerabilities"] = vuln_overrides

        config_path = os.path.join(tmp_dir, "runtime_config.yaml")
        with open(config_path, "w") as f:
            yaml.safe_dump(runtime_config, f, sort_keys=False)

        # ── Determine vuln_types to pass to pipeline ──
        vuln_types_arg = selected_vuln_types if (vuln_select_mode == "Select specific types" and selected_vuln_types) else None

        # ── Reset session state ──
        st.session_state["pipeline_running"] = True
        st.session_state["pipeline_results"] = None
        st.session_state["pipeline_error"] = None
        st.session_state["pipeline_logs"] = ""
        st.session_state["approval_decisions"] = {}

        # ── Run pipeline in a background thread with live log streaming ──
        log_queue = queue.Queue()
        result_holder = {}  # shared dict: thread writes results here

        bg_thread = threading.Thread(
            target=_run_pipeline_in_thread,
            args=(scan_path, repo_path, config_path, max_retries, vuln_types_arg, log_queue, result_holder),
            daemon=True,
        )

        # Show a live-updating status block
        with st.status("🔄 Running SecureGuard AI pipeline…", expanded=True) as status_box:
            log_area = st.empty()      # will hold the streaming log text
            all_logs = []              # accumulate log lines

            bg_thread.start()

            while True:
                try:
                    chunk = log_queue.get(timeout=0.3)
                except queue.Empty:
                    # No new output yet — check if thread is still alive
                    if not bg_thread.is_alive():
                        break
                    continue

                if chunk is None:
                    # Sentinel: thread finished
                    break

                all_logs.append(chunk)
                # Update the live display (last 120 lines for performance)
                full_text = "".join(all_logs)
                display_lines = full_text.splitlines()
                tail = "\n".join(display_lines[-120:])
                log_area.code(tail, language="text")

            bg_thread.join(timeout=5)

            # ── Collect final results ──
            full_log = "".join(all_logs)
            st.session_state["pipeline_logs"] = full_log

            if "error" in result_holder:
                st.session_state["pipeline_error"] = result_holder["error"]
                status_box.update(label="❌ Pipeline failed", state="error", expanded=True)
            elif "results" in result_holder:
                st.session_state["pipeline_results"] = result_holder["results"]
                n = len(result_holder["results"])
                status_box.update(label=f"✅ Pipeline complete — {n} vulnerability(ies) processed", state="complete", expanded=False)
            else:
                st.session_state["pipeline_error"] = "Pipeline finished without returning results."
                status_box.update(label="⚠️ Pipeline finished unexpectedly", state="error", expanded=True)

        st.session_state["pipeline_running"] = False
        st.rerun()  # refresh to render results sections below


# ────────────────────────────────────────────────────────────────────
# SECTION 3 — EXECUTION LOGS (post-run, always available)
# ────────────────────────────────────────────────────────────────────
logs = st.session_state.get("pipeline_logs", "")
error = st.session_state.get("pipeline_error")

if logs or error:
    st.markdown('<div class="section-header">📜 Execution Logs</div>', unsafe_allow_html=True)
    with st.expander("View full pipeline logs", expanded=bool(error)):
        st.code(logs if logs else "(no output captured)", language="text")

    if error:
        st.error("❌  Pipeline encountered an error")
        with st.expander("Stack trace"):
            st.code(error, language="python")


# ────────────────────────────────────────────────────────────────────
# SECTION 4 — RESULTS  +  SECTION 5 — DIFF  +  SECTION 6 — APPROVAL
# ────────────────────────────────────────────────────────────────────
results = st.session_state.get("pipeline_results")

if results is not None:
    # ── Summary stats ──
    st.markdown('<div class="section-header">📊 Results Summary</div>', unsafe_allow_html=True)

    verified   = sum(1 for r in results if r.get("status") == "VERIFIED")
    unverified = sum(1 for r in results if r.get("status") == "UNVERIFIED")
    skipped    = sum(1 for r in results if r.get("status") == "SKIPPED")
    errored    = sum(1 for r in results if r.get("status") == "ERROR")
    syntax     = sum(1 for r in results if r.get("status") == "SYNTAX-ONLY-VERIFIED")
    total      = len(results)
    accuracy   = f"{verified / total * 100:.0f}%" if total else "N/A"

    c1, c2, c3, c4, c5 = st.columns(5)
    for col, num, lbl in [
        (c1, total, "Total"),
        (c2, verified, "Verified"),
        (c3, unverified, "Unverified"),
        (c4, skipped, "Skipped"),
        (c5, accuracy, "Accuracy"),
    ]:
        col.markdown(
            f'<div class="stat-card"><div class="number">{num}</div>'
            f'<div class="label">{lbl}</div></div>',
            unsafe_allow_html=True,
        )

    st.markdown("---")

    # ── Per-vulnerability detail cards ──
    for idx, result in enumerate(results):
        vuln = result.get("vulnerability", {})
        vuln_type = vuln.get("vuln_type", "unknown")
        file_path = vuln.get("file_path", "unknown")
        line_num  = vuln.get("line_number", "?")
        severity  = vuln.get("severity", "MEDIUM")
        status    = result.get("status", "UNKNOWN")
        diff_text = result.get("diff_text", "")
        attempts  = result.get("attempts", [])
        patch_path = result.get("patch_file_path", "")
        current_fix = result.get("current_fix", "")

        with st.container(border=True):
            # ── Title row ──
            hdr_col, badge_col = st.columns([4, 1])
            hdr_col.markdown(f"#### 🔒 {vuln_type}")
            badge_col.markdown(_status_badge(status), unsafe_allow_html=True)

            # ── Info table ──
            info_col1, info_col2, info_col3 = st.columns(3)
            info_col1.markdown(f"**File:** `{file_path}:{line_num}`")
            info_col2.markdown(f"**Severity:** `{severity}`")
            info_col3.markdown(f"**Attempts:** `{len(attempts)}`")

            # ── Test results from last attempt ──
            if attempts:
                last = attempts[-1]
                tp = last.get("tests_passed", 0)
                tf = last.get("tests_failed", 0)
                st.markdown(f"**Tests:** {tp} passed, {tf} failed")

            # ── Diff view ──
            if diff_text:
                with st.expander("📝 View Patch Diff", expanded=True):
                    st.code(diff_text, language="diff")

            # ── Attempt history ──
            if len(attempts) > 1:
                with st.expander(f"🔁 Attempt History ({len(attempts)} attempts)"):
                    for a in attempts:
                        anum = a.get("attempt", "?")
                        ap   = a.get("tests_passed", 0)
                        af   = a.get("tests_failed", 0)
                        st.markdown(f"**Attempt {anum}** — {ap} passed, {af} failed")
                        if a.get("test_output"):
                            st.code(a["test_output"][-600:], language="text")

            # ── Error detail ──
            if status == "ERROR":
                err_detail = result.get("error", "Unknown error")
                st.error(f"Pipeline error: {err_detail}")

            # ── Approval buttons (interactive mode) ──
            if interactive and status in ("VERIFIED", "UNVERIFIED", "SYNTAX-ONLY-VERIFIED"):
                decision_key = f"decision_{idx}"
                prev_decision = st.session_state["approval_decisions"].get(idx)

                if prev_decision == "APPROVED":
                    st.success("✅ Patch applied successfully.")
                elif prev_decision == "REJECTED":
                    st.warning("⏭️ You rejected this fix — patch was not applied.")
                else:
                    btn_col1, btn_col2, _ = st.columns([1, 1, 3])
                    with btn_col1:
                        if st.button("✅ Approve Fix", key=f"approve_{idx}", type="primary"):
                            # Apply patch
                            try:
                                from patch_generator import apply_patch
                                success = apply_patch(
                                    file_path=file_path,
                                    fix_code=current_fix,
                                    repo_path=repo_path,
                                )
                                if success:
                                    st.session_state["approval_decisions"][idx] = "APPROVED"
                                else:
                                    st.session_state["approval_decisions"][idx] = "ERROR"
                            except Exception as exc:
                                st.session_state["approval_decisions"][idx] = "ERROR"
                                st.error(f"Patch apply failed: {exc}")
                            st.rerun()
                    with btn_col2:
                        if st.button("❌ Reject Fix", key=f"reject_{idx}"):
                            st.session_state["approval_decisions"][idx] = "REJECTED"
                            st.rerun()

            # ── Patch file download ──
            if patch_path and os.path.exists(patch_path):
                with open(patch_path, "r") as pf:
                    patch_content = pf.read()
                st.download_button(
                    label="⬇️ Download .patch",
                    data=patch_content,
                    file_name=os.path.basename(patch_path),
                    mime="text/plain",
                    key=f"dl_{idx}",
                )

    # ── Report download ──
    report_dir = os.path.join(os.path.abspath(repo_path), "output")
    summary_report = os.path.join(report_dir, "summary_report.md")
    if os.path.exists(summary_report):
        st.markdown("---")
        with open(summary_report, "r") as rf:
            report_md = rf.read()

        st.markdown('<div class="section-header">📋 Summary Report</div>', unsafe_allow_html=True)
        with st.expander("View full summary report"):
            st.markdown(report_md)

        st.download_button(
            label="⬇️ Download Summary Report",
            data=report_md,
            file_name="summary_report.md",
            mime="text/markdown",
            key="dl_summary",
        )

elif not st.session_state.get("pipeline_running") and not error:
    # ── Empty state ──
    st.markdown("---")
    st.info(
        "👈 Upload a scan report and configure settings in the sidebar, then click **Run SecureGuard**."
    )
