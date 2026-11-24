"""
schema.py
JSON Schema tool definitions sent to the model via the `tools` param.
Keep this list to recon/validation tools only — read-only or low-impact
operations. Exploit execution stays out of tool-calling by design;
the model can still *explain* PoCs in text, it just can't auto-fire them.
"""

# Keep this in sync with executor.ALLOWED_WORDLISTS keys.
WORDLIST_CHOICES = ["common", "api-endpoints", "parameters"]

TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "run_subfinder",
            "description": "Passive subdomain enumeration for a domain already in scope.",
            "parameters": {
                "type": "object",
                "properties": {
                    "domain": {"type": "string", "description": "Root domain, e.g. example.com"}
                },
                "required": ["domain"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "run_dnsx",
            "description": "Resolve a list of hostnames to their current DNS records (A/CNAME).",
            "parameters": {
                "type": "object",
                "properties": {
                    "hosts": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "List of hostnames to resolve",
                    }
                },
                "required": ["hosts"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "run_httpx",
            "description": "Probe a list of hosts for liveness, status code, title, and tech stack.",
            "parameters": {
                "type": "object",
                "properties": {
                    "hosts": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "List of hostnames or URLs to probe",
                    }
                },
                "required": ["hosts"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "run_gau",
            "description": (
                "Passively collect known URLs for a domain from web archives (no requests "
                "are sent to the live target — this only queries archive services)."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "domain": {"type": "string"}
                },
                "required": ["domain"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "run_nuclei",
            "description": "Run nuclei templates (info/low/medium severity only) against a single in-scope host.",
            "parameters": {
                "type": "object",
                "properties": {
                    "target": {"type": "string"},
                    "severity": {
                        "type": "string",
                        "enum": ["info", "low", "medium"],
                        "description": "Max severity allowed; high/critical templates are blocked by the executor.",
                    },
                },
                "required": ["target"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "run_ffuf",
            "description": (
                "Fuzz a URL for hidden paths or parameters. Insert the literal token FUZZ "
                "where the wordlist should be substituted, e.g. "
                "'https://target.com/FUZZ' or 'https://target.com/api?FUZZ=test'. "
                "Auto-calibration is always enabled to reduce noise."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {
                        "type": "string",
                        "description": "Target URL containing the FUZZ placeholder",
                    },
                    "wordlist": {
                        "type": "string",
                        "enum": WORDLIST_CHOICES,
                        "description": "Which built-in wordlist to use",
                    },
                },
                "required": ["url", "wordlist"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "run_arjun",
            "description": "Discover hidden GET parameters accepted by an endpoint.",
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {"type": "string"}
                },
                "required": ["url"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "http_request",
            "description": (
                "Send a single safe, non-destructive HTTP request (GET/HEAD/OPTIONS only) "
                "to an in-scope target to inspect headers, responses, or behavior. "
                "No POST/PUT/DELETE — this is for observation, not state-changing actions."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {"type": "string"},
                    "method": {"type": "string", "enum": ["GET", "HEAD", "OPTIONS"]},
                    "headers": {
                        "type": "object",
                        "description": "Optional extra headers, e.g. for testing header-based bypasses",
                    },
                },
                "required": ["url", "method"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "read_source_file",
            "description": "Read a local source code file for static analysis (when auditing a repo the user owns).",
            "parameters": {
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "Path relative to the authorized project root"}
                },
                "required": ["path"],
            },
        },
    },
]