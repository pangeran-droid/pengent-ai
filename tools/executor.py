"""
executor.py
Actually runs the tools the model asked for. Every function:
  1. Validates target against ScopeManager
  2. Runs with a hard timeout
  3. Returns a bounded-size string (truncated) so we don't blow the context window
"""

import re
import subprocess
from pathlib import Path

from .guardrail import ScopeManager, ScopeError

MAX_OUTPUT_CHARS = 8000
DEFAULT_TIMEOUT = 60

# Nuclei templates above this severity are never allowed through this tool,
# regardless of what the model requests.
BLOCKED_NUCLEI_SEVERITIES = {"high", "critical"}

# Wordlists ffuf is allowed to use. Keys must match schema.WORDLIST_CHOICES.
# Paths are resolved relative to this file's directory, not the CWD or any
# model-supplied path — the model can never point ffuf at an arbitrary file.
_WORDLIST_DIR = Path(__file__).resolve().parent / "wordlists"
ALLOWED_WORDLISTS = {
    "common": _WORDLIST_DIR / "common.txt",
    "api-endpoints": _WORDLIST_DIR / "api-endpoints.txt",
    "parameters": _WORDLIST_DIR / "parameters.txt",
}

FFUF_MAX_TIME_SECONDS = 90


class ToolExecutionError(Exception):
    pass


def _truncate(text: str) -> str:
    if len(text) > MAX_OUTPUT_CHARS:
        return text[:MAX_OUTPUT_CHARS] + "\n...[truncated]"
    return text


def _run(cmd: list[str], timeout: int = DEFAULT_TIMEOUT, input_data: str | None = None) -> str:
    try:
        result = subprocess.run(
            cmd,
            input=input_data,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        output = result.stdout or ""
        if result.returncode != 0 and result.stderr:
            output += f"\n[stderr]\n{result.stderr}"
        return _truncate(output.strip() or "(no output)")
    except FileNotFoundError:
        raise ToolExecutionError(f"Tool binary not found: {cmd[0]}. Is it installed and in PATH?")
    except subprocess.TimeoutExpired:
        raise ToolExecutionError(f"Command timed out after {timeout}s: {' '.join(cmd)}")


def _extract_host_from_fuzz_url(url: str) -> str:
    """Pulls the host out of a URL that may contain the FUZZ placeholder,
    so scope.check() can validate it without choking on the placeholder."""
    cleaned = url.replace("FUZZ", "x")
    return cleaned


def run_subfinder(scope: ScopeManager, domain: str) -> str:
    scope.check(domain)
    return _run(["subfinder", "-d", domain, "-silent"], timeout=90)


def run_dnsx(scope: ScopeManager, hosts: list[str]) -> str:
    for h in hosts:
        scope.check(h)
    input_data = "\n".join(hosts)
    return _run(["dnsx", "-silent", "-a", "-cname", "-resp"], timeout=60, input_data=input_data)


def run_httpx(scope: ScopeManager, hosts: list[str]) -> str:
    for h in hosts:
        scope.check(h)
    input_data = "\n".join(hosts)
    return _run(
        ["httpx", "-silent", "-status-code", "-title", "-tech-detect"],
        timeout=90,
        input_data=input_data,
    )


def run_gau(scope: ScopeManager, domain: str) -> str:
    # Passive only — gau queries archive.org / otx / etc, never the live
    # target — but we still enforce scope so results stay on-topic and the
    # model can't fish for unrelated domains.
    scope.check(domain)
    return _run(["gau", domain], timeout=60)


def run_nuclei(scope: ScopeManager, target: str, severity: str = "info") -> str:
    scope.check(target)
    if severity in BLOCKED_NUCLEI_SEVERITIES:
        raise ToolExecutionError(
            f"Severity '{severity}' is blocked by policy. "
            f"Only info/low/medium templates run through this tool. "
            f"High/critical findings require manual verification."
        )
    return _run(
        ["nuclei", "-u", target, "-severity", severity, "-silent", "-timeout", "10"],
        timeout=120,
    )


def run_ffuf(scope: ScopeManager, url: str, wordlist: str) -> str:
    if "FUZZ" not in url:
        raise ToolExecutionError("URL must contain the literal FUZZ placeholder.")

    scope.check(_extract_host_from_fuzz_url(url))

    wordlist_path = ALLOWED_WORDLISTS.get(wordlist)
    if wordlist_path is None:
        raise ToolExecutionError(
            f"Unknown wordlist '{wordlist}'. Allowed: {sorted(ALLOWED_WORDLISTS)}"
        )
    if not wordlist_path.is_file():
        raise ToolExecutionError(
            f"Wordlist file missing on disk: {wordlist_path}. "
            f"Add it to tools/wordlists/ before this tool can be used."
        )

    return _run(
        [
            "ffuf",
            "-w", str(wordlist_path),
            "-u", url,
            "-ac",                      # always auto-calibrate (skill's "THE ONE RULE")
            "-mc", "200,201,204,301,302,307,401,403",
            "-maxtime", str(FFUF_MAX_TIME_SECONDS),
            "-rate", "20",              # stay polite / avoid looking like an attack
            "-s",                       # silent, just results
        ],
        timeout=FFUF_MAX_TIME_SECONDS + 15,
    )


def run_arjun(scope: ScopeManager, url: str) -> str:
    scope.check(url)
    return _run(["arjun", "-u", url, "--stable"], timeout=90)


def http_request(scope: ScopeManager, url: str, method: str, headers: dict | None = None) -> str:
    scope.check(url)
    if method not in {"GET", "HEAD", "OPTIONS"}:
        raise ToolExecutionError(f"Method '{method}' not permitted. Only GET/HEAD/OPTIONS.")

    cmd = ["curl", "-s", "-i", "-X", method, "--max-time", "15"]
    if headers:
        for k, v in headers.items():
            if "\n" in k or "\n" in v or "\r" in k or "\r" in v:
                raise ToolExecutionError("Header injection attempt blocked.")
            cmd += ["-H", f"{k}: {v}"]
    cmd.append(url)
    return _run(cmd, timeout=20)


def read_source_file(project_root: Path, path: str) -> str:
    candidate = (project_root / path).resolve()
    if not str(candidate).startswith(str(project_root.resolve())):
        raise ToolExecutionError(f"Path traversal blocked: {path}")
    if not candidate.is_file():
        raise ToolExecutionError(f"File not found: {path}")
    try:
        return _truncate(candidate.read_text(encoding="utf-8", errors="replace"))
    except Exception as error:
        raise ToolExecutionError(f"Failed to read file: {error}")


DISPATCH = {
    "run_subfinder": lambda scope, args, **_: run_subfinder(scope, args["domain"]),
    "run_dnsx": lambda scope, args, **_: run_dnsx(scope, args["hosts"]),
    "run_httpx": lambda scope, args, **_: run_httpx(scope, args["hosts"]),
    "run_gau": lambda scope, args, **_: run_gau(scope, args["domain"]),
    "run_nuclei": lambda scope, args, **_: run_nuclei(scope, args["target"], args.get("severity", "info")),
    "run_ffuf": lambda scope, args, **_: run_ffuf(scope, args["url"], args["wordlist"]),
    "run_arjun": lambda scope, args, **_: run_arjun(scope, args["url"]),
    "http_request": lambda scope, args, **_: http_request(
        scope, args["url"], args["method"], args.get("headers")
    ),
    "read_source_file": lambda scope, args, project_root=None, **_: read_source_file(
        project_root, args["path"]
    ),
}


def execute_tool_call(name: str, args: dict, scope: ScopeManager, project_root: Path | None = None) -> str:
    handler = DISPATCH.get(name)
    if handler is None:
        return f"Error: unknown tool '{name}'"
    try:
        return handler(scope, args, project_root=project_root)
    except (ScopeError, ToolExecutionError) as error:
        return f"Error: {error}"