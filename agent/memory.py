"""
agent/memory.py - Manages conversation memory for the remediation agent.
Stores fix attempt history and test failure messages so the agent
has full context on retry. Uses LangChain message types for compatibility
with LangGraph's message-based state.
"""
from langchain_core.messages import HumanMessage, AIMessage


class ConversationMemory:
    """Simple conversation memory backed by a list of LangChain messages."""

    def __init__(self):
        self.messages = []

    def add_user_message(self, text: str) -> None:
        self.messages.append(HumanMessage(content=text))

    def add_ai_message(self, text: str) -> None:
        self.messages.append(AIMessage(content=text))

    def get_messages(self) -> list:
        return list(self.messages)

    def clear(self) -> None:
        self.messages.clear()


def create_memory() -> ConversationMemory:
    """Create a fresh ConversationMemory for a remediation session."""
    return ConversationMemory()


def inject_failure_context(memory: ConversationMemory, attempt: dict) -> None:
    """
    Inject a test failure into memory so the agent sees what went wrong
    on its next retry attempt.
    """
    failure_msg = (
        f"[SYSTEM] Your previous fix (attempt {attempt['attempt']}) failed.\n"
        f"Tests passed: {attempt['tests_passed']}, Tests failed: {attempt['tests_failed']}\n"
        f"Test output:\n{attempt['test_output']}\n"
        f"Your fix was:\n{attempt['fix_code']}\n"
        f"Revise your fix to address the failing tests."
    )
    memory.add_user_message(failure_msg)


def get_attempt_history_text(attempts: list) -> str:
    """Format all previous attempts into a text block for the retry prompt."""
    if not attempts:
        return ""
    lines = []
    for a in attempts:
        lines.append(f"Attempt {a['attempt']}:")
        lines.append(f"  Your fix:\n{a['fix_code']}")
        lines.append(f"  Test result: {a['tests_failed']} test(s) failed")
        lines.append(f"  Failure output:\n{a['test_output']}")
        lines.append("")
    return "\n".join(lines)
