"""
guardrail.py
Validates that a target is explicitly in-scope before any tool executes.
This does NOT replace human judgment / legal authorization — it's a
basic safety net so the AI can't silently pivot to an out-of-scope host.
"""

import re
import ipaddress
from urllib.parse import urlparse


class ScopeError(Exception):
    pass


class ScopeManager:
    """
    Holds the current engagement's allowed domains/IPs for the session.
    Must be set explicitly by the user (e.g. via a `/scope` command)
    before any tool call is permitted.
    """

    def __init__(self):
        self.allowed_domains: set[str] = set()
        self.allowed_ips: set[str] = set()
        self.authorized: bool = False

    def set_scope(self, raw_targets: str, confirm_authorized: bool):
        """
        raw_targets: comma/space separated domains or IPs, e.g.
            "example.com, *.example.com, 10.0.0.0/24"
        confirm_authorized: must be True, forces an explicit user
            confirmation step in the CLI before scope is accepted.
        """
        if not confirm_authorized:
            raise ScopeError(
                "Scope rejected: you must explicitly confirm you are "
                "authorized to test these targets."
            )

        self.allowed_domains.clear()
        self.allowed_ips.clear()

        for token in re.split(r"[,\s]+", raw_targets.strip()):
            if not token:
                continue
            token = token.lower().lstrip("*.")
            try:
                ipaddress.ip_network(token, strict=False)
                self.allowed_ips.add(token)
            except ValueError:
                self.allowed_domains.add(token)

        self.authorized = True

    def clear(self):
        self.allowed_domains.clear()
        self.allowed_ips.clear()
        self.authorized = False

    def _host_matches_domain(self, host: str) -> bool:
        host = host.lower()
        for domain in self.allowed_domains:
            if host == domain or host.endswith("." + domain):
                return True
        return False

    def _host_matches_ip(self, host: str) -> bool:
        try:
            ip = ipaddress.ip_address(host)
        except ValueError:
            return False
        for net in self.allowed_ips:
            try:
                if ip in ipaddress.ip_network(net, strict=False):
                    return True
            except ValueError:
                continue
        return False

    def check(self, target: str):
        """
        Raises ScopeError if target (URL, domain, or IP) is not
        explicitly in the current scope.
        """
        if not self.authorized:
            raise ScopeError(
                "No scope has been set for this session. "
                "Use /scope to authorize targets before running any tool."
            )

        # Normalize: accept raw domains, IPs, or full URLs
        if "://" in target:
            host = urlparse(target).hostname or ""
        else:
            host = target.split("/")[0].split(":")[0]

        if not host:
            raise ScopeError(f"Could not parse a host from target: {target}")

        if self._host_matches_domain(host) or self._host_matches_ip(host):
            return host

        raise ScopeError(
            f"Target '{host}' is not in the authorized scope "
            f"({sorted(self.allowed_domains | self.allowed_ips)}). Refusing to run."
        )