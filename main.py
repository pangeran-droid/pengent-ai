from pathlib import Path
import json
import os
import re
import shutil
import sys
import httpx

from tools.guardrail import ScopeManager, ScopeError
from tools.executor import execute_tool_call
from tools.schema import TOOLS


class ChatAPIError(Exception):
    def __init__(self, message, *, retryable=False):
        super().__init__(message)
        self.retryable = retryable


def colorize(text, color_code):
    if sys.stdout.isatty() and "NO_COLOR" not in os.environ:
        return f"\033[{color_code}m{text}\033[0m"
    return text


def _strip_ansi(text: str) -> str:
    return re.sub(r"\033\[[0-9;]*m", "", text)


def _box_line(content: str, width: int) -> str:
    """content may already contain ANSI color codes; padding is computed
    from the visible (non-ANSI) length so the box stays aligned."""
    visible_len = len(_strip_ansi(content))
    pad = max(width - visible_len - 2, 0)
    return f"│ {content}{' ' * pad} │"


def print_banner(scope_manager: ScopeManager | None = None, tool_count: int = 0, model_names: list | None = None):
    term_width = shutil.get_terminal_size(fallback=(80, 24)).columns
    width = min(max(term_width - 4, 50), 70)

    logo_lines = [
        ("██████╗ ███████╗███╗   ██╗ ██████╗ ███████╗███╗   ██╗████████╗","    ","█████╗ ██╗"),
        ("██╔══██╗██╔════╝████╗  ██║██╔════╝ ██╔════╝████╗  ██║╚══██╔══╝","   ","██╔══██╗██║"),
        ("██████╔╝█████╗  ██╔██╗ ██║██║  ███╗█████╗  ██╔██╗ ██║   ██║","█████╗","███████║██║"),
        ("██╔═══╝ ██╔══╝  ██║╚██╗██║██║   ██║██╔══╝  ██║╚██╗██║   ██║","╚════╝","██╔══██║██║"),
        ("██║     ███████╗██║ ╚████║╚██████╔╝███████╗██║ ╚████║   ██║","      ","██║  ██║██║"),
        ("╚═╝     ╚══════╝╚═╝  ╚═══╝ ╚═════╝ ╚══════╝╚═╝  ╚═══╝   ╚═╝","      ","╚═╝  ╚═╝╚═╝"),
    ]

    print()
    for pengent_part, dash_part, ai_part in logo_lines:
        print(colorize(pengent_part, "0;31") + colorize(dash_part, "2") + colorize(ai_part, "1;36"))
    print()

    print(colorize("┌" + "─" * width + "┐", "2"))

    title = colorize("PENGENT AI", "0;31") + colorize("  —  Offensive Security Assistant", "2")
    print(_box_line(title, width))
    print(_box_line(colorize("github.com/pangeran-droid/pengent-ai", "1;36"), width))
    print(_box_line(colorize("t.me/pangeran1337", "1;36"), width))
    print(colorize("├" + "─" * width + "┤", "2"))

    if scope_manager and scope_manager.authorized:
        targets = sorted(scope_manager.allowed_domains | scope_manager.allowed_ips)
        scope_text = colorize(", ".join(targets) if targets else "none", "1;32")
    else:
        scope_text = colorize("none (run /scope <target> to authorize)", "1;33")
    print(_box_line(colorize("Scope:  ", "2") + scope_text, width))

    if tool_count:
        print(_box_line(colorize("Tools:  ", "2") + colorize(f"{tool_count} available", "1;36"), width))
    if model_names:
        models_text = ", ".join(m.split("/")[-1] for m in model_names)
        print(_box_line(colorize("Models: ", "2") + colorize(models_text, "1;36"), width))

    print(colorize("├" + "─" * width + "┤", "2"))
    print(_box_line(colorize("Authorized labs and explicitly scoped assessments only.", "0;33"), width))
    commands = (
        colorize("/scope <t>", "1;32") + colorize(" set scope   ", "2") +
        colorize("/scope", "1;32") + colorize(" show scope   ", "2") +
        colorize("exit", "1;32") + colorize(" quit", "2")
    )
    print(_box_line(commands, width))
    print(colorize("└" + "─" * width + "┘", "2"))
    print()


def load_system_prompt(file_path="system/system_prompt.txt"):
    path = Path(file_path)
    if not path.is_absolute():
        path = Path(__file__).resolve().parent / path
    if not path.is_file():
        raise FileNotFoundError(f"System prompt file not found: {path}")

    content = path.read_text(encoding="utf-8").strip()
    if not content:
        raise ValueError(f"System prompt file is empty: {path}")

    return [{"role": "developer", "content": content}]


# Only models here are assumed to support OpenAI-style tool calling.
# Gemma (google/gemma-4-*) is intentionally excluded from this chain:
# its tool-calling support via OpenRouter is inconsistent at the time
# of writing. Test any new model manually before trusting its tool_calls.
TOOL_CAPABLE_MODELS = [
    "google/gemini-2.5-flash-lite",
    "qwen/qwen-2.5-72b-instruct",
    "deepseek/deepseek-v3.2",
]

RETRYABLE_STATUS_CODES = {402, 408, 429, 500, 502, 503, 504}

MAX_TOOL_ROUNDS = 6
TOOL_LOG_PREVIEW_CHARS = 300


def _is_quota_or_retryable_error(error: Exception) -> bool:
    if isinstance(error, httpx.HTTPStatusError):
        return error.response.status_code in RETRYABLE_STATUS_CODES
    if isinstance(error, (httpx.TimeoutException, httpx.RequestError)):
        return True
    if isinstance(error, ChatAPIError):
        if error.retryable:
            return True
        msg = str(error).lower()
        return any(
            phrase in msg
            for phrase in (
                "quota",
                "credit",
                "rate limit",
                "429",
                "402",
                "stream ended",
                "temporarily unavailable",
                "overloaded",
            )
        )
    return False


def _call_single_model_nonstream(model_name: str, conversation_messages: list, api_key: str, tools=None) -> dict:
    """
    Non-streaming call so we can inspect the full message object, including
    tool_calls, before deciding what to print or execute. Returns the
    assistant message dict as given by the API (role/content/tool_calls).
    """
    api_url = "https://openrouter.ai/api/v1/chat/completions"
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }
    payload = {
        "model": model_name,
        "messages": conversation_messages,
        "stream": False,
    }
    if tools:
        payload["tools"] = tools

    try:
        response = httpx.post(api_url, headers=headers, json=payload, timeout=180.0)
        response.raise_for_status()
    except httpx.TimeoutException as error:
        raise ChatAPIError("Request timed out while waiting for the API.", retryable=True) from error
    except httpx.HTTPStatusError as error:
        raise ChatAPIError(
            f"API returned HTTP {error.response.status_code}. Check the API key, model, and account quota.",
            retryable=_is_quota_or_retryable_error(error),
        ) from error
    except httpx.RequestError as error:
        raise ChatAPIError(f"Network error while contacting the API: {error}", retryable=True) from error

    try:
        data = response.json()
    except json.JSONDecodeError as error:
        raise ChatAPIError("API returned invalid JSON response.") from error

    if "error" in data:
        error_info = data["error"]
        message = error_info.get("message") if isinstance(error_info, dict) else None
        code = error_info.get("code") if isinstance(error_info, dict) else None
        err = ChatAPIError(message or "API reported an error.")
        retryable = (
            str(code) in {str(status) for status in RETRYABLE_STATUS_CODES}
            or _is_quota_or_retryable_error(err)
        )
        raise ChatAPIError(str(err), retryable=retryable)

    choices = data.get("choices")
    if not isinstance(choices, list) or not choices:
        raise ChatAPIError("API response had no choices.")

    message = choices[0].get("message")
    if not isinstance(message, dict):
        raise ChatAPIError("API returned an unexpected message format.")

    return message


def _stream_single_model(model_name: str, conversation_messages: list, api_key: str) -> str:
    """Plain streaming call, no tool support. Used as a fallback path for
    models in MODELS_NO_TOOLS or when tool-calling is disabled."""
    api_url = "https://openrouter.ai/api/v1/chat/completions"
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }
    payload = {
        "model": model_name,
        "messages": conversation_messages,
        "stream": True,
    }

    full_reply = []
    started_printing = False

    try:
        with httpx.stream("POST", api_url, headers=headers, json=payload, timeout=180.0) as response:
            response.raise_for_status()
            received_done = False

            for line in response.iter_lines():
                if not line or not line.startswith("data:"):
                    continue

                raw_data = line[len("data:"):].strip()
                if raw_data == "[DONE]":
                    received_done = True
                    break

                try:
                    chunk = json.loads(raw_data)
                except json.JSONDecodeError as error:
                    raise ChatAPIError("API returned invalid streaming data.") from error

                if not isinstance(chunk, dict):
                    raise ChatAPIError("API returned an unexpected streaming response.")
                if chunk.get("error"):
                    error_info = chunk["error"]
                    message = error_info.get("message") if isinstance(error_info, dict) else None
                    code = error_info.get("code") if isinstance(error_info, dict) else None
                    error = ChatAPIError(message or "API reported a streaming error.")
                    retryable = (
                        str(code) in {str(status) for status in RETRYABLE_STATUS_CODES}
                        or _is_quota_or_retryable_error(error)
                    )
                    raise ChatAPIError(str(error), retryable=retryable)

                choices = chunk.get("choices")
                if not isinstance(choices, list) or not choices:
                    continue
                first_choice = choices[0]
                if not isinstance(first_choice, dict):
                    raise ChatAPIError("API returned an unexpected streaming response.")
                delta = first_choice.get("delta", {})
                if not isinstance(delta, dict):
                    raise ChatAPIError("API returned an unexpected streaming response.")
                content_piece = delta.get("content")

                if content_piece:
                    if not isinstance(content_piece, str):
                        raise ChatAPIError("API returned content in an unsupported format.")
                    if not started_printing:
                        print(colorize(f"assistant ({model_name})> ", "1;35"), end="", flush=True)
                        started_printing = True
                    print(content_piece, end="", flush=True)
                    full_reply.append(content_piece)

            if started_printing:
                print()

            if not received_done:
                raise ChatAPIError(
                    "Stream ended before completion; the partial response was not saved.",
                    retryable=True,
                )
    except httpx.TimeoutException as error:
        raise ChatAPIError("Request timed out while waiting for the API.", retryable=True) from error
    except httpx.HTTPStatusError as error:
        raise ChatAPIError(
            f"API returned HTTP {error.response.status_code}. Check the API key, model, and account quota.",
            retryable=_is_quota_or_retryable_error(error),
        ) from error
    except httpx.RequestError as error:
        raise ChatAPIError(f"Network error while contacting the API: {error}", retryable=True) from error

    if not full_reply:
        raise ChatAPIError("API completed the request but returned no text.")
    return "".join(full_reply)


def stream_chat_response_with_tools(conversation_messages, scope_manager: ScopeManager, project_root: Path, models=None):
    """
    Runs the tool-calling loop against the first tool-capable model that
    succeeds, falling back to the next model on quota/retryable errors
    (same fallback philosophy as the original stream_chat_response).

    Returns the final assistant text and the list of newly appended
    messages (assistant tool_call messages + tool result messages +
    final assistant message) so the caller can extend conversation history.
    """
    api_key = os.environ.get("OPENROUTER_API_KEY")
    if not api_key:
        raise ChatAPIError("OPENROUTER_API_KEY is not set.")

    models = models or TOOL_CAPABLE_MODELS
    last_error = None

    for idx, model_name in enumerate(models):
        messages = list(conversation_messages)
        new_messages = []

        try:
            for _round in range(MAX_TOOL_ROUNDS):
                message = _call_single_model_nonstream(model_name, messages, api_key, tools=TOOLS)

                tool_calls = message.get("tool_calls")
                if not tool_calls:
                    content = message.get("content") or ""
                    print(colorize(f"assistant ({model_name})> ", "1;35") + content)
                    new_messages.append({"role": "assistant", "content": content})
                    return content, new_messages

                # Model requested tool execution(s)
                messages.append(message)
                new_messages.append(message)

                for call in tool_calls:
                    fn_name = call.get("function", {}).get("name", "")
                    raw_args = call.get("function", {}).get("arguments", "{}")
                    try:
                        fn_args = json.loads(raw_args)
                    except json.JSONDecodeError:
                        fn_args = {}

                    print(colorize(f"[tool call] {fn_name}({fn_args})", "2"))
                    result = execute_tool_call(fn_name, fn_args, scope_manager, project_root)
                    preview = result if len(result) <= TOOL_LOG_PREVIEW_CHARS else result[:TOOL_LOG_PREVIEW_CHARS] + "..."
                    print(colorize(f"[tool result] {preview}", "0;36"))

                    tool_message = {
                        "role": "tool",
                        "tool_call_id": call.get("id", ""),
                        "content": result,
                    }
                    messages.append(tool_message)
                    new_messages.append(tool_message)

            raise ChatAPIError(
                f"Model '{model_name}' exceeded {MAX_TOOL_ROUNDS} tool-calling rounds without a final answer.",
                retryable=False,
            )

        except ChatAPIError as error:
            last_error = error
            has_next = idx < len(models) - 1
            if has_next and _is_quota_or_retryable_error(error):
                next_model = models[idx + 1]
                print(colorize(f"\n[!] '{model_name}' failed ({error}). Switch to '{next_model}'...", "1;33"))
                continue
            raise

    raise last_error or ChatAPIError("All tool-capable models failed.")


def handle_scope_command(user_input: str, scope_manager: ScopeManager) -> bool:
    """Returns True if input was a /scope command (handled), else False."""
    stripped = user_input.strip()
    if not stripped.startswith("/scope"):
        return False

    rest = stripped[len("/scope"):].strip()
    if not rest:
        if scope_manager.authorized:
            current = sorted(scope_manager.allowed_domains | scope_manager.allowed_ips)
            print(colorize(f"Current scope: {current}", "1;36"))
        else:
            print(colorize("No scope set. Usage: /scope example.com,10.0.0.0/24", "1;33"))
        return True

    print(colorize(
        f"You are about to authorize testing against: {rest}\n"
        "Type 'yes' to confirm you own this target or have explicit written authorization:",
        "1;33",
    ))
    try:
        confirm = input("> ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        print(colorize("\nScope not set.", "1;31"))
        return True

    try:
        scope_manager.set_scope(rest, confirm_authorized=(confirm == "yes"))
        print(colorize(f"Scope set: {rest}", "1;32"))
    except ScopeError as error:
        print(colorize(f"Scope not set: {error}", "1;31"))
    return True


def build_system_messages(base_system: list, scope_manager: ScopeManager) -> list:
    """
    Re-injects the CURRENT scope state into the system message on every
    single turn, instead of relying on conversation history (which gets
    truncated to the last 20 messages and never actually contained the
    /scope exchange in the first place — that command is handled locally
    in Python and was never part of the message list sent to the model).

    Without this, the model has no way to know scope was set and will
    keep hallucinating "please set scope first" even after the user did.
    """
    if scope_manager.authorized:
        targets = sorted(scope_manager.allowed_domains | scope_manager.allowed_ips)
        scope_block = (
            "\n\n# CURRENT SESSION SCOPE (live, authoritative — not something the user typed to you)\n"
            f"Authorized targets right now: {targets}\n"
            "Tool calls against any of these will succeed at the executor layer. "
            "Do not ask the user to run /scope again for a target already listed here — "
            "just call the tool. If a tool call still fails with a scope error, trust that "
            "error over your own assumption and report it plainly."
        )
    else:
        scope_block = (
            "\n\n# CURRENT SESSION SCOPE (live, authoritative)\n"
            "No scope is currently authorized. Tool calls will fail. "
            "Ask the user to run /scope <target> before attempting any tool call."
        )

    base_content = base_system[0]["content"]
    return [{"role": base_system[0]["role"], "content": base_content + scope_block}]


def main():
    if not os.environ.get("OPENROUTER_API_KEY"):
        raise SystemExit(
            "Error: OPENROUTER_API_KEY has not been set. Set this environment variable before running the application.\n"
            "example: export OPENROUTER_API_KEY='your_api_key_here'"
        )

    try:
        base_system = load_system_prompt("system/system_prompt.txt")
    except (OSError, UnicodeError, ValueError) as error:
        raise SystemExit(f"System prompt error: {error}") from None

    scope_manager = ScopeManager()
    project_root = Path(__file__).resolve().parent
    conversation_history = []

    print_banner(scope_manager, tool_count=len(TOOLS), model_names=TOOL_CAPABLE_MODELS)

    while True:
        try:
            user_input = input(colorize("prompt> ", "1;32"))
        except EOFError:
            print()
            break
        except KeyboardInterrupt:
            print("\nExiting.")
            break

        if user_input.strip().lower() == "exit":
            break

        if handle_scope_command(user_input, scope_manager):
            continue

        temp_history = conversation_history + [{"role": "user", "content": user_input}]
        system = build_system_messages(base_system, scope_manager)
        messages_to_send = system + temp_history[-20:]

        try:
            _final_text, new_messages = stream_chat_response_with_tools(
                messages_to_send, scope_manager, project_root
            )
        except ChatAPIError as error:
            print(f"\n{colorize('API error:', '1;31')} {error}")
            continue

        conversation_history = temp_history + new_messages


if __name__ == "__main__":
    main()