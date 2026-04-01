"""
agent/agent.py - Defines LangGraph workflow (nodes and transitions).
Creates the graph executor, registers LangChain tools, defines the system prompt,
and runs the remediation pipeline.

LangGraph models the pipeline as:
  parse -> filter -> locate -> generate_fix -> validate -> review -> patch -> report

Conditional edges:
  validate -> PASS -> review (or patch if review disabled)
  validate -> FAIL -> generate_fix (retry)
  retry_count ≥ 3 -> escalate
  review -> APPROVED -> patch
  review -> REJECTED -> skip
"""
import os
import sys
from typing import TypedDict, Annotated, Literal, Any

from langgraph.graph import StateGraph, END
from langgraph.prebuilt import create_react_agent
from langchain_core.messages import HumanMessage, SystemMessage

from config.llm_factory import get_llm, get_provider_name
from agent.tools import get_all_tools, set_repo_path
from agent.feedback_loop import build_initial_prompt, build_retry_prompt, extract_code_from_response
from prompts.fix_templates import get_system_prompt


# ── Agent system prompt ─────────────────────────────────────────────

AGENT_SYSTEM_PROMPT = '''
You are an expert security engineer and code remediator.
You have been given a vulnerability finding from a security scanner.
Your job is to: (1) verify the finding is real, (2) understand the full code context,
(3) generate a minimal targeted fix, (4) validate it passes tests.
Think step by step. Use your tools. Explain your reasoning at each step.
Return ONLY valid code in your fix. No markdown, no explanation in the fix itself.
'''


# ── LangGraph State ──────────────────────────────────────────────────

class RemediationState(TypedDict):
    """State passed between LangGraph nodes."""
    vulnerability: dict             # The current vulnerability finding
    repo_path: str                  # Path to the target repo
    interactive_mode: bool          # Whether human review is enabled
    max_retries: int                # Max fix attempts (default 3)
    enable_llm_fix_verification: bool  # Whether to run LLM-based fix verification

    # Accumulated during execution
    attempt_number: int             # Current attempt (1-indexed)
    attempts: list                  # List of all attempt dicts
    current_fix: str                # The latest proposed fix code
    fix_explanation: str            # Plain-English explanation of the current fix
    reasoning_chain: list           # Agent reasoning steps

    # Validation results
    tests_passed: int
    tests_failed: int
    test_output: str
    validation_status: str          # Status returned by the validator
    status: str                     # VERIFIED | UNVERIFIED | SKIPPED | PENDING

    # Review
    review_decision: str            # APPROVED | REJECTED | SKIPPED

    # Output
    patch_file_path: str
    diff_text: str
    report_file_path: str
    summary: str
    error: str


# ── Node functions ───────────────────────────────────────────────────

def _invoke_without_tools(llm, full_system: str, messages: list[HumanMessage], error_text: str) -> dict:
    """Fallback path when provider-side tool calling fails."""
    fallback_messages = [
        SystemMessage(
            content=(
                full_system
                + "\n\nTool calling is unavailable for this attempt. "
                + "Do not call tools. Do not emit function tags or XML-like syntax. "
                + "Use only the vulnerability context and prior failure history already provided. "
                + "Return ONLY the complete fixed file content."
            )
        ),
        *messages,
        HumanMessage(
            content=(
                "The provider rejected your previous response because tool calling failed.\n"
                f"Provider error:\n{error_text}\n\n"
                "Do not attempt any tool calls in this response. Return only the full fixed file."
            )
        ),
    ]
    response = llm.invoke(fallback_messages)
    return {"messages": [response]}

def generate_fix_node(state: RemediationState) -> dict:
    """Core agent reasoning node. Calls LLM with tools to generate a fix."""
    vuln = state["vulnerability"]
    attempt_num = state.get("attempt_number", 0) + 1
    attempts = state.get("attempts", [])

    print(f"\n{'='*60}")
    print(f"[Agent] Generating fix - Attempt {attempt_num}")
    print(f"  Vuln: {vuln['vuln_type']} in {vuln['file_path']}:{vuln['line_number']}")
    print(f"{'='*60}")

    # Get vulnerability-specific system prompt
    vuln_prompt = get_system_prompt(vuln['vuln_type'])
    full_system = AGENT_SYSTEM_PROMPT + "\n\n" + vuln_prompt

    # Create LangGraph react agent with tools (provider from config)
    llm = get_llm()
    tools = get_all_tools()

    react_agent = create_react_agent(
        model=llm,
        tools=tools,
        prompt=full_system,
    )

    # Build message history with previous failure context
    messages = []
    for prev in attempts:
        messages.append(HumanMessage(
            content=f"Attempt {prev['attempt']} fix:\n{prev['fix_code']}"
        ))
        messages.append(HumanMessage(
            content=(
                f"[TEST RESULT] {prev['tests_failed']} test(s) failed.\n"
                f"Output:\n{prev['test_output']}"
            )
        ))

    # Build the input prompt
    if attempt_num == 1:
        input_msg = build_initial_prompt(vuln)
    else:
        last_failure = attempts[-1]["test_output"] if attempts else ""
        input_msg = build_retry_prompt(vuln, attempts, last_failure)

    messages.append(HumanMessage(content=input_msg))

    try:
        result = react_agent.invoke({"messages": messages})
    except Exception as e:
        err_str = str(e)
        if "tool_use_failed" in err_str or "400" in err_str:
            print("  [Agent] Tool call rejected by provider. Falling back to no-tool generation...")
            try:
                result = _invoke_without_tools(llm, full_system, messages, err_str)
            except Exception as e2:
                print(f"  [Agent] Error during fallback generation: {e2}")
                fix_code = ""
                fix_explanation = ""
                reasoning = [f"Error: {e2}"]
                return {
                    "attempt_number": attempt_num,
                    "current_fix": fix_code,
                    "fix_explanation": fix_explanation,
                    "reasoning_chain": reasoning,
                    "status": "PENDING",
                }
        else:
            print(f"  [Agent] Error during generation: {e}")
            fix_code = ""
            fix_explanation = ""
            reasoning = [f"Error: {e}"]
            return {
                "attempt_number": attempt_num,
                "current_fix": fix_code,
                "fix_explanation": fix_explanation,
                "reasoning_chain": reasoning,
                "status": "PENDING",
            }

    # Extract the final AI message content
    ai_messages = [m for m in result["messages"] if hasattr(m, 'content') and m.type == 'ai' and m.content]
    response_text = ai_messages[-1].content if ai_messages else ""
    fix_code = extract_code_from_response(response_text)
    if fix_code:
        from agent.tools import explain_fix_tool
        fix_explanation = explain_fix_tool.invoke({
            "vulnerability_type": vuln["vuln_type"],
            "original_code": vuln.get("code_snippet", ""),
            "fixed_code": fix_code,
        })
    else:
        fix_explanation = ""
    reasoning = [str(m.content)[:200] for m in result["messages"] if m.type == 'ai']

    return {
        "attempt_number": attempt_num,
        "current_fix": fix_code,
        "fix_explanation": fix_explanation,
        "reasoning_chain": reasoning,
        "status": "PENDING",
    }


def validate_node(state: RemediationState) -> dict:
    """Run tests on the proposed fix. Returns pass/fail counts."""
    from validator import validate_fix

    vuln = state["vulnerability"]
    fix_code = state.get("current_fix", "")
    attempt_num = state.get("attempt_number", 1)

    print(f"\n[Validate] Testing fix (attempt {attempt_num})...")

    if not fix_code:
        return {
            "tests_passed": 0,
            "tests_failed": 1,
            "test_output": "No fix code generated",
            "attempts": state.get("attempts", []) + [{
                "attempt": attempt_num,
                "fix_code": "",
                "tests_passed": 0,
                "tests_failed": 1,
                "test_output": "No fix code generated",
                "reasoning": state.get("reasoning_chain", []),
            }],
        }

    result = validate_fix(
        file_path=vuln["file_path"],
        fix_code=fix_code,
        repo_path=state.get("repo_path", "."),
        original_code=vuln.get("code_snippet", ""),
        vuln_type=vuln.get("vuln_type", ""),
        fix_strategy=vuln.get("fix_strategy", ""),
        enable_llm_fix_verification=state.get("enable_llm_fix_verification", True),
    )

    attempt_record = {
        "attempt": attempt_num,
        "fix_code": fix_code,
        "fix_explanation": state.get("fix_explanation", ""),
        "tests_passed": result["tests_passed"],
        "tests_failed": result["tests_failed"],
        "test_output": result["test_output"],
        "reasoning": state.get("reasoning_chain", []),
    }

    print(f"  Passed: {result['tests_passed']}, Failed: {result['tests_failed']}")

    return {
        "tests_passed": result["tests_passed"],
        "tests_failed": result["tests_failed"],
        "test_output": result["test_output"],
        "validation_status": result.get("status", ""),
        "attempts": state.get("attempts", []) + [attempt_record],
    }


def review_node(state: RemediationState) -> dict:
    """Human-in-the-loop review step. Shows diff and gets approval."""
    from reviewer import present_review

    vuln = state["vulnerability"]
    fix_code = state.get("current_fix", "")

    print(f"\n[Review] Presenting fix for developer approval...")

    decision = present_review(
        vuln_type=vuln["vuln_type"],
        file_path=vuln["file_path"],
        line_number=vuln["line_number"],
        original_code=vuln.get("code_snippet", ""),
        fixed_code=fix_code,
        test_output=state.get("test_output", ""),
        attempt_number=state.get("attempt_number", 1),
    )

    return {"review_decision": decision}


def patch_node(state: RemediationState) -> dict:
    """Generate a .patch file from the fix."""
    from patch_generator import generate_patch

    vuln = state["vulnerability"]
    fix_code = state.get("current_fix", "")

    print(f"\n[Patch] Generating patch file...")

    result = generate_patch(
        file_path=vuln["file_path"],
        fix_code=fix_code,
        repo_path=state.get("repo_path", "."),
    )

    return {
        "patch_file_path": result["patch_file_path"],
        "diff_text": result["diff_text"],
        "status": (
            "UNVERIFIED"
            if state.get("validation_status") == "NO_TESTS"
            else ("VERIFIED" if state.get("tests_failed", 0) == 0 else "UNVERIFIED")
        ),
    }


def report_node(state: RemediationState) -> dict:
    """Generate a Markdown report for this vulnerability fix."""
    from reporter import generate_report

    vuln = state["vulnerability"]

    print(f"\n[Report] Generating report...")

    result = generate_report(
        vulnerability=vuln,
        status=state.get("status", "UNVERIFIED"),
        attempts=state.get("attempts", []),
        fix_explanation=state.get("fix_explanation", ""),
        diff_text=state.get("diff_text", ""),
        patch_file_path=state.get("patch_file_path", ""),
        repo_path=state.get("repo_path", "."),
    )

    return {
        "report_file_path": result["report_file_path"],
        "summary": result["summary"],
    }


def escalate_node(state: RemediationState) -> dict:
    """Mark as unverified after max retries exhausted."""
    attempts = state.get("attempts", [])
    best = min(attempts, key=lambda a: a.get("tests_failed", 999)) if attempts else {}

    print(f"\n[Escalate] Max retries exhausted. Best attempt: {best.get('attempt', '?')}")
    print(f"  Best result: {best.get('tests_failed', '?')} test(s) failed")

    return {
        "status": "UNVERIFIED",
        "current_fix": best.get("fix_code", ""),
        "fix_explanation": best.get("fix_explanation", ""),
    }


def skip_node(state: RemediationState) -> dict:
    """Developer rejected the fix."""
    print(f"\n[Skip] Fix rejected by developer.")
    return {"status": "SKIPPED"}


# ── Conditional edge functions ───────────────────────────────────────

def should_retry_or_proceed(state: RemediationState) -> str:
    """After validation: retry, review, patch, or escalate."""
    tests_failed = state.get("tests_failed", 1)
    attempt_num = state.get("attempt_number", 1)
    max_retries = state.get("max_retries", 3)
    validation_status = state.get("validation_status", "")

    if validation_status == "NO_TESTS":
        if state.get("interactive_mode", False):
            return "review"
        return "patch"

    if tests_failed == 0:
        # Tests passed - go to review or patch
        if state.get("interactive_mode", False):
            return "review"
        return "patch"
    elif attempt_num >= max_retries:
        return "escalate"
    else:
        return "retry"


def after_review(state: RemediationState) -> str:
    """After review: patch if approved, skip if rejected."""
    decision = state.get("review_decision", "APPROVED")
    if decision == "APPROVED":
        return "patch"
    return "skip"


# ── Build the LangGraph workflow ─────────────────────────────────────

def build_remediation_graph() -> StateGraph:
    """
    Build the LangGraph workflow for the remediation pipeline.

    Graph structure:
      generate_fix -> validate -> [retry | review | patch | escalate]
      review -> [patch | skip]
      patch -> report -> END
      escalate -> patch -> report -> END
      skip -> report -> END
    """
    graph = StateGraph(RemediationState)

    # Add nodes
    graph.add_node("generate_fix", generate_fix_node)
    graph.add_node("validate", validate_node)
    graph.add_node("review", review_node)
    graph.add_node("patch", patch_node)
    graph.add_node("report", report_node)
    graph.add_node("escalate", escalate_node)
    graph.add_node("skip", skip_node)

    # Set entry point
    graph.set_entry_point("generate_fix")

    # Add edges
    graph.add_edge("generate_fix", "validate")

    # Conditional: after validation
    graph.add_conditional_edges(
        "validate",
        should_retry_or_proceed,
        {
            "retry": "generate_fix",
            "review": "review",
            "patch": "patch",
            "escalate": "escalate",
        },
    )

    # Conditional: after review
    graph.add_conditional_edges(
        "review",
        after_review,
        {
            "patch": "patch",
            "skip": "skip",
        },
    )

    # Linear edges to report and END
    graph.add_edge("patch", "report")
    graph.add_edge("escalate", "patch")
    graph.add_edge("skip", "report")
    graph.add_edge("report", END)

    return graph


def create_remediation_workflow():
    """Compile and return the LangGraph workflow."""
    graph = build_remediation_graph()
    return graph.compile()


def run_remediation(
    vulnerability: dict,
    repo_path: str = ".",
    interactive_mode: bool = False,
    max_retries: int = 3,
    enable_llm_fix_verification: bool = True,
) -> dict:
    """
    Run the full remediation pipeline on a single vulnerability.
    Returns the final state dict with status, patch, and report.
    """
    set_repo_path(repo_path)

    workflow = create_remediation_workflow()

    initial_state: RemediationState = {
        "vulnerability": vulnerability,
        "repo_path": os.path.abspath(repo_path),
        "interactive_mode": interactive_mode,
        "max_retries": max_retries,
        "enable_llm_fix_verification": enable_llm_fix_verification,
        "attempt_number": 0,
        "attempts": [],
        "current_fix": "",
        "fix_explanation": "",
        "reasoning_chain": [],
        "tests_passed": 0,
        "tests_failed": 0,
        "test_output": "",
        "validation_status": "",
        "status": "PENDING",
        "review_decision": "",
        "patch_file_path": "",
        "diff_text": "",
        "report_file_path": "",
        "summary": "",
        "error": "",
    }

    print(f"\n{'#'*60}")
    print(f"# SecureGuard AI - Remediation Pipeline")
    print(f"# Vulnerability: {vulnerability['vuln_type']}")
    print(f"# File: {vulnerability['file_path']}:{vulnerability['line_number']}")
    print(f"# Mode: {'Interactive' if interactive_mode else 'Automatic'}")
    print(f"{'#'*60}")

    final_state = workflow.invoke(initial_state)
    return final_state
