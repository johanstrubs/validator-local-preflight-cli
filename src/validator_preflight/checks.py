from __future__ import annotations

import asyncio
import json
import shutil
import socket
import ssl
import subprocess
import sys
import tomllib
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import httpx

DEFAULT_RPC_ENDPOINT = "http://127.0.0.1:5005"
UPGRADES_API_URL = "https://dashboard.pftoligarchy.com/api/upgrades"
POSTFIAT_SCHEMA_DOC = "POSTFIAT_SCHEMA.md"
WELL_KNOWN_PATH = "/.well-known/postfiat.toml"
HEALTHY_STATES = {"proposing", "full"}
PASS = "pass"
WARN = "warn"
FAIL = "fail"
SKIP = "skip"


@dataclass
class CheckResult:
    name: str
    category: str
    status: str
    detected_value: str
    expected_value: str
    remediation: str

    def as_dict(self) -> dict[str, str]:
        return {
            "name": self.name,
            "category": self.category,
            "status": self.status,
            "detected_value": self.detected_value,
            "expected_value": self.expected_value,
            "remediation": self.remediation,
        }


def _parse_semver(version: str | None) -> tuple[int, int, int, int, str] | None:
    if not version:
        return None
    raw = version.strip().lstrip("vV")
    base, dash, suffix = raw.partition("-")
    parts = base.split(".")
    if len(parts) != 3 or not all(part.isdigit() for part in parts):
        return None
    major, minor, patch = (int(part) for part in parts)
    is_final = 1 if not dash else 0
    return major, minor, patch, is_final, suffix


def _normalize_version(version: str | None) -> str | None:
    parsed = _parse_semver(version)
    if not parsed:
        return version.strip() if version else None
    major, minor, patch, is_final, suffix = parsed
    base = f"{major}.{minor}.{patch}"
    return base if is_final else f"{base}-{suffix}"


def _color(text: str, color_code: str, enabled: bool = True) -> str:
    if not enabled:
        return text
    return f"\033[{color_code}m{text}\033[0m"


def render_summary(checks: list[dict[str, Any]], *, color: bool = True) -> str:
    counts = {PASS: 0, WARN: 0, FAIL: 0, SKIP: 0}
    for check in checks:
        counts[check["status"]] = counts.get(check["status"], 0) + 1
    lines = [
        _color("Validator Local Preflight Summary", "1;37", color),
        f"pass={counts[PASS]} warn={counts[WARN]} fail={counts[FAIL]} skip={counts[SKIP]}",
        "",
    ]
    palette = {PASS: "32", WARN: "33", FAIL: "31", SKIP: "36"}
    for check in checks:
        label = _color(check["status"].upper(), palette.get(check["status"], "37"), color)
        lines.append(f"[{label}] {check['name']}: {check['detected_value']} (expected {check['expected_value']})")
        if check.get("remediation"):
            lines.append(f"  remediation: {check['remediation']}")
    return "\n".join(lines)


async def _post_json(client: httpx.AsyncClient, endpoint: str, payload: dict[str, Any]) -> tuple[dict[str, Any] | None, str | None]:
    try:
        response = await client.post(
            endpoint,
            json=payload,
            headers={"Content-Type": "application/json"},
        )
        response.raise_for_status()
        return response.json(), None
    except Exception as exc:
        return None, str(exc)


async def _fetch_json(client: httpx.AsyncClient, endpoint: str) -> tuple[dict[str, Any] | None, str | None]:
    try:
        response = await client.get(endpoint)
        response.raise_for_status()
        return response.json(), None
    except Exception as exc:
        return None, str(exc)


def _best_effort_port_2559() -> CheckResult:
    port = 2559
    tools = [["ss", "-ltn"], ["netstat", "-ltn"]]
    for cmd in tools:
        if shutil.which(cmd[0]) is None:
            continue
        try:
            completed = subprocess.run(cmd, check=False, capture_output=True, text=True, timeout=5)
        except Exception as exc:
            return CheckResult(
                "Peer port 2559 listening",
                "local",
                WARN,
                f"{cmd[0]} failed: {exc}",
                "port 2559 listening on a local interface",
                "Confirm postfiatd is bound to the peer port and try the check again with local system tools available.",
            )
        output = completed.stdout + completed.stderr
        if f":{port}" in output:
            return CheckResult(
                "Peer port 2559 listening",
                "local",
                PASS,
                "port 2559 detected in listening sockets",
                "port 2559 listening on a local interface",
                "",
            )
        return CheckResult(
            "Peer port 2559 listening",
            "local",
            FAIL,
            "port 2559 not present in listening sockets",
            "port 2559 listening on a local interface",
            "Start or reconfigure postfiatd so the peer port is exposed locally, then verify any reverse proxy or host-networking setup.",
        )
    return CheckResult(
        "Peer port 2559 listening",
        "local",
        SKIP,
        "no supported socket tool found",
        "ss or netstat available for socket inspection",
        "Install `ss` or `netstat`, or inspect listening sockets manually if your environment hides host networking details.",
    )


def _best_effort_firewall() -> CheckResult:
    candidates = [
        ("ufw", ["ufw", "status"]),
        ("firewall-cmd", ["firewall-cmd", "--list-ports"]),
        ("nft", ["nft", "list", "ruleset"]),
        ("iptables", ["iptables", "-S"]),
    ]
    for name, cmd in candidates:
        if shutil.which(name) is None:
            continue
        try:
            completed = subprocess.run(cmd, check=False, capture_output=True, text=True, timeout=8)
            output = (completed.stdout + completed.stderr).lower()
        except Exception as exc:
            return CheckResult(
                "Firewall accessibility",
                "local",
                WARN,
                f"{name} check failed: {exc}",
                "best-effort confirmation that tcp/2559 is not blocked",
                "Review host and cloud firewall rules manually, especially inbound TCP/2559 and any validator-specific allowlists.",
            )
        if "2559" in output:
            return CheckResult(
                "Firewall accessibility",
                "local",
                PASS,
                f"{name} output references 2559",
                "best-effort confirmation that tcp/2559 is not blocked",
                "",
            )
        return CheckResult(
            "Firewall accessibility",
            "local",
            WARN,
            f"{name} output did not explicitly reference 2559",
            "best-effort confirmation that tcp/2559 is not blocked",
            "Double-check host firewall and cloud ingress rules for TCP/2559. This check is advisory and may miss indirect allow rules.",
        )
    return CheckResult(
        "Firewall accessibility",
        "local",
        SKIP,
        "no supported firewall tool found",
        "best-effort confirmation that tcp/2559 is not blocked",
        "Run the firewall check on a Linux host with `ufw`, `nft`, `iptables`, or `firewall-cmd`, or review cloud firewall settings manually.",
    )


def _free_disk_check() -> CheckResult:
    usage = shutil.disk_usage(Path.cwd())
    free_gb = usage.free / (1024 ** 3)
    status = PASS if free_gb >= 10 else FAIL
    return CheckResult(
        "Free disk space",
        "extended",
        status,
        f"{free_gb:.1f} GB free",
        ">= 10.0 GB free",
        "" if status == PASS else "Free additional disk space before onboarding. Validator history, ledgers, and logs need headroom to stay healthy.",
    )


async def _dns_lookup(domain: str) -> tuple[list[str] | None, str | None]:
    try:
        loop = asyncio.get_running_loop()
        infos = await loop.getaddrinfo(domain, 443, type=socket.SOCK_STREAM)
        return sorted({info[4][0] for info in infos if info[4] and info[4][0]}), None
    except Exception as exc:
        return None, str(exc)


async def _tls_details(domain: str) -> tuple[dict[str, Any] | None, str | None]:
    def worker() -> dict[str, Any]:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as tls:
                cert = tls.getpeercert()
                not_after = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=UTC)
                return {
                    "issuer": dict(item[0] for item in cert.get("issuer", [])),
                    "expires_at": not_after.isoformat(),
                    "days_until_expiry": (not_after - datetime.now(UTC)).days,
                }

    try:
        return await asyncio.to_thread(worker), None
    except Exception as exc:
        return None, str(exc)


async def _fetch_well_known(domain: str) -> tuple[str | None, str | None]:
    url = f"https://{domain}{WELL_KNOWN_PATH}"
    try:
        async with httpx.AsyncClient(timeout=10.0, follow_redirects=True) as client:
            response = await client.get(url)
            response.raise_for_status()
            return response.text, None
    except Exception as exc:
        return None, str(exc)


def _parse_well_known(doc_text: str) -> list[dict[str, Any]] | None:
    try:
        parsed = tomllib.loads(doc_text)
    except Exception:
        return None
    validators = parsed.get("VALIDATORS")
    return validators if isinstance(validators, list) else None


def _extract_public_key(server_info: dict[str, Any]) -> str | None:
    return server_info.get("pubkey_validator") if server_info.get("pubkey_validator") not in (None, "", "none") else None


def _expected_network(endpoint: str) -> str:
    host = urlparse(endpoint).hostname or ""
    return "mainnet" if "main" in host else "testnet"


def _docker_check() -> tuple[CheckResult, CheckResult]:
    if shutil.which("docker") is None:
        skip_status = CheckResult(
            "Docker container status",
            "extended",
            SKIP,
            "docker not installed",
            "running postfiatd container with restart policy",
            "Install Docker or run the CLI on the validator host if you want container-specific checks.",
        )
        skip_restart = CheckResult(
            "Docker restart policy",
            "extended",
            SKIP,
            "docker not installed",
            "restart policy of unless-stopped or always",
            "Install Docker or run the CLI on the validator host if you want container-specific checks.",
        )
        return skip_status, skip_restart
    try:
        ps = subprocess.run(
            ["docker", "ps", "--format", "{{.Names}}\t{{.Image}}\t{{.Status}}"],
            check=False,
            capture_output=True,
            text=True,
            timeout=8,
        )
        lines = [line for line in ps.stdout.splitlines() if "postfiatd" in line.lower()]
        if not lines:
            status_check = CheckResult(
                "Docker container status",
                "extended",
                WARN,
                "no running postfiatd container detected",
                "running postfiatd container",
                "If you use Docker, confirm the container name/image and re-run on the validator host. If you do not use Docker, this check can be ignored.",
            )
            restart_check = CheckResult(
                "Docker restart policy",
                "extended",
                SKIP,
                "container not found",
                "restart policy of unless-stopped or always",
                "Run the CLI on the Docker host after the validator container is up if you want restart-policy validation.",
            )
            return status_check, restart_check

        container_name = lines[0].split("\t", 1)[0]
        inspect = subprocess.run(
            ["docker", "inspect", container_name, "--format", "{{.HostConfig.RestartPolicy.Name}}"],
            check=False,
            capture_output=True,
            text=True,
            timeout=8,
        )
        policy = inspect.stdout.strip() or "unknown"
        status_check = CheckResult(
            "Docker container status",
            "extended",
            PASS,
            lines[0],
            "running postfiatd container",
            "",
        )
        restart_status = PASS if policy in {"unless-stopped", "always"} else WARN
        restart_check = CheckResult(
            "Docker restart policy",
            "extended",
            restart_status,
            policy,
            "restart policy of unless-stopped or always",
            "" if restart_status == PASS else "Update the container restart policy so a host reboot or transient exit does not leave the validator offline.",
        )
        return status_check, restart_check
    except Exception as exc:
        warn = CheckResult(
            "Docker container status",
            "extended",
            WARN,
            f"docker check failed: {exc}",
            "running postfiatd container with restart policy",
            "Re-run on the validator host with Docker access if you want container-specific checks.",
        )
        warn_restart = CheckResult(
            "Docker restart policy",
            "extended",
            WARN,
            f"docker check failed: {exc}",
            "restart policy of unless-stopped or always",
            "Re-run on the validator host with Docker access if you want restart-policy validation.",
        )
        return warn, warn_restart


async def _crawl_check(endpoint: str, rpc_info: dict[str, Any]) -> CheckResult:
    parsed = urlparse(endpoint)
    host = parsed.hostname
    if not host:
        return CheckResult(
            "Crawl pubkey_validator",
            "extended",
            SKIP,
            "could not derive crawl host from RPC endpoint",
            "https://<host>:2559/crawl exposes pubkey_validator",
            "Provide an RPC endpoint with a resolvable host if you want the crawl cross-check.",
        )
    url = f"https://{host}:2559/crawl"
    try:
        async with httpx.AsyncClient(timeout=10.0, verify=False) as client:
            response = await client.get(url)
            response.raise_for_status()
            data = response.json()
    except Exception as exc:
        return CheckResult(
            "Crawl pubkey_validator",
            "extended",
            WARN,
            f"{url} unreachable: {exc}",
            "https://<host>:2559/crawl exposes server.pubkey_validator",
            "Confirm the crawl endpoint is intentionally exposed and reachable from the local environment. This check is advisory.",
        )
    crawl_key = (((data or {}).get("server") or {}).get("pubkey_validator"))
    expected = _extract_public_key(rpc_info)
    if not expected:
        return CheckResult(
            "Crawl pubkey_validator",
            "extended",
            SKIP,
            str(crawl_key or "missing"),
            "server_info exposes pubkey_validator for comparison",
            "The crawl endpoint responded, but server_info did not expose pubkey_validator. Treat this as advisory and confirm key mapping manually if needed.",
        )
    if crawl_key and expected and crawl_key == expected:
        return CheckResult(
            "Crawl pubkey_validator",
            "extended",
            PASS,
            crawl_key,
            expected,
            "",
        )
    return CheckResult(
        "Crawl pubkey_validator",
        "extended",
        WARN,
        str(crawl_key or "missing"),
        expected or "server_info pubkey_validator",
        "Compare /crawl output with server_info and your validator metadata. If they differ, double-check which host and key pair are actually exposed.",
    )


async def _upload_report(report: dict[str, Any], upload_url: str | None) -> CheckResult:
    if not upload_url:
        return CheckResult(
            "Upload report",
            "upload",
            SKIP,
            "no --upload-url provided",
            "optional HTTPS endpoint provided by the caller",
            "Pass --upload-url https://example.com/endpoint if you want to forward the full JSON report.",
        )
    if not upload_url.startswith("https://"):
        return CheckResult(
            "Upload report",
            "upload",
            WARN,
            upload_url,
            "HTTPS endpoint",
            "Use an HTTPS upload URL so the optional report transfer is encrypted in transit.",
        )
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.post(upload_url, json=report)
        response.raise_for_status()
        return CheckResult(
            "Upload report",
            "upload",
            PASS,
            f"HTTP {response.status_code}",
            "successful HTTPS POST within 10 seconds",
            "",
        )
    except Exception as exc:
        return CheckResult(
            "Upload report",
            "upload",
            WARN,
            str(exc),
            "successful HTTPS POST within 10 seconds",
            "The preflight run is still valid locally. Check the remote endpoint, auth expectations, TLS, and network egress before retrying upload.",
        )


async def run_preflight(
    rpc_endpoint: str,
    *,
    domain: str | None = None,
    full: bool = False,
    upload_url: str | None = None,
) -> dict[str, Any]:
    started_at = datetime.now(UTC).isoformat()
    checks: list[CheckResult] = []
    metadata: dict[str, Any] = {
        "rpc_endpoint": rpc_endpoint,
        "domain": domain,
        "full": full,
        "upload_url": upload_url,
        "started_at": started_at,
    }

    rpc_timeout = 10.0
    server_info: dict[str, Any] | None = None
    async with httpx.AsyncClient(timeout=rpc_timeout) as client:
        rpc_payload, rpc_error = await _post_json(client, rpc_endpoint, {"method": "server_info", "params": [{}]})
        if rpc_error:
            checks.append(CheckResult(
                "RPC reachability",
                "core",
                FAIL,
                rpc_error,
                "server_info responds within 10 seconds",
                "Confirm the RPC URL, host reachability, reverse proxy, and local validator process before retrying.",
            ))
            checks.extend([
                CheckResult("Server state", "core", SKIP, "RPC unavailable", "proposing or full", "Fix RPC reachability first."),
                CheckResult("Version freshness", "core", SKIP, "RPC unavailable", "comparable build version", "Fix RPC reachability first."),
                CheckResult("Validated ledger age", "core", SKIP, "RPC unavailable", "<= 10 seconds", "Fix RPC reachability first."),
                CheckResult("Peer count", "core", SKIP, "RPC unavailable", ">= 5 peers", "Fix RPC reachability first."),
            ])
        else:
            server_info = (((rpc_payload or {}).get("result") or {}).get("info") or {})
            checks.append(CheckResult(
                "RPC reachability",
                "core",
                PASS,
                "server_info responded",
                "server_info responds within 10 seconds",
                "",
            ))

            state = str(server_info.get("server_state") or "unknown")
            checks.append(CheckResult(
                "Server state",
                "core",
                PASS if state in HEALTHY_STATES else FAIL,
                state,
                "proposing or full",
                "" if state in HEALTHY_STATES else "Wait for sync and inspect validator logs until the node returns to `proposing` or `full`.",
            ))

            version = server_info.get("build_version") or "unknown"
            upgrades_payload, upgrades_error = await _fetch_json(client, UPGRADES_API_URL)
            if upgrades_error or not upgrades_payload or not upgrades_payload.get("latest_version"):
                checks.append(CheckResult(
                    "Version freshness",
                    "core",
                    SKIP,
                    version,
                    "compare against public upgrades API latest_version",
                    "The public upgrades API could not be queried. Re-run with internet access if you want cohort version comparison.",
                ))
            else:
                latest_version = upgrades_payload["latest_version"]
                current_parsed = _parse_semver(str(version))
                latest_parsed = _parse_semver(str(latest_version))
                fresh = bool(current_parsed and latest_parsed and current_parsed >= latest_parsed)
                checks.append(CheckResult(
                    "Version freshness",
                    "core",
                    PASS if fresh else WARN,
                    str(version),
                    str(latest_version),
                    "" if fresh else "Upgrade to the current cohort version. Illustrative example: `docker compose pull && docker compose up -d`.",
                ))

            ledger_age = (((server_info.get("validated_ledger") or {}).get("age")))
            if ledger_age is None:
                checks.append(CheckResult(
                    "Validated ledger age",
                    "core",
                    WARN,
                    "missing",
                    "<= 10 seconds",
                    "The RPC response did not include validated ledger age. Check server_info output and confirm the node is fully synced.",
                ))
            else:
                checks.append(CheckResult(
                    "Validated ledger age",
                    "core",
                    PASS if float(ledger_age) <= 10 else FAIL,
                    f"{float(ledger_age):.1f}s",
                    "<= 10.0s",
                    "" if float(ledger_age) <= 10 else "Investigate ledger lag before onboarding. Review sync status, disk, and network health.",
                ))

            peers = server_info.get("peers")
            peer_count_ok = peers is not None and int(peers) >= 5
            checks.append(CheckResult(
                "Peer count",
                "core",
                PASS if peer_count_ok else FAIL,
                str(peers if peers is not None else "missing"),
                ">= 5 peers",
                "" if peer_count_ok else "Open or verify peer connectivity on TCP/2559 and confirm the validator has healthy upstream peers.",
            ))

        checks.append(_best_effort_port_2559())
        checks.append(_best_effort_firewall())

        if domain:
            dns_ips, dns_error = await _dns_lookup(domain)
            if dns_error:
                checks.append(CheckResult(
                    "Domain DNS resolution",
                    "domain",
                    FAIL,
                    dns_error,
                    "domain resolves successfully",
                    "Fix DNS records for the validator domain before onboarding.",
                ))
            else:
                checks.append(CheckResult(
                    "Domain DNS resolution",
                    "domain",
                    PASS,
                    ", ".join(dns_ips or []),
                    "domain resolves successfully",
                    "",
                ))

            tls_info, tls_error = await _tls_details(domain)
            if tls_error:
                checks.append(CheckResult(
                    "TLS validity",
                    "domain",
                    FAIL,
                    tls_error,
                    "valid TLS certificate with >30 days until expiry",
                    "Repair TLS issuance or renewal so the validator domain serves a valid HTTPS certificate.",
                ))
            else:
                days = int(tls_info["days_until_expiry"])
                status = PASS if days > 30 else WARN
                checks.append(CheckResult(
                    "TLS validity",
                    "domain",
                    status,
                    f"expires in {days} days ({tls_info['expires_at']})",
                    "valid TLS certificate with >30 days until expiry",
                    "" if status == PASS else "Renew the certificate soon so domain attestation does not fail during onboarding.",
                ))

            well_known_text, well_known_error = await _fetch_well_known(domain)
            if well_known_error:
                checks.append(CheckResult(
                    "Well-known attestation fetch",
                    "domain",
                    FAIL,
                    well_known_error,
                    f"https://{domain}{WELL_KNOWN_PATH} returns HTTP 200",
                    f"Publish the attestation file at {WELL_KNOWN_PATH} and re-run the CLI.",
                ))
            else:
                checks.append(CheckResult(
                    "Well-known attestation fetch",
                    "domain",
                    PASS,
                    f"https://{domain}{WELL_KNOWN_PATH} reachable",
                    f"https://{domain}{WELL_KNOWN_PATH} returns HTTP 200",
                    "",
                ))
                validators = _parse_well_known(well_known_text or "")
                expected_pubkey = _extract_public_key(server_info or {})
                expected_network = _expected_network(rpc_endpoint)
                if not validators:
                    checks.append(CheckResult(
                        "Well-known attestation contents",
                        "domain",
                        FAIL,
                        "VALIDATORS list missing or unparsable",
                        "VALIDATORS entry with matching public_key and network",
                        f"Use the documented schema in {POSTFIAT_SCHEMA_DOC} and include a [[VALIDATORS]] entry for this validator.",
                    ))
                else:
                    match = None
                    for entry in validators:
                        if not isinstance(entry, dict):
                            continue
                        if expected_pubkey and entry.get("public_key") == expected_pubkey:
                            match = entry
                            break
                    if not match:
                        checks.append(CheckResult(
                            "Well-known attestation contents",
                            "domain",
                            FAIL,
                            "no VALIDATORS entry matched server_info pubkey_validator",
                            "VALIDATORS entry with matching public_key and network",
                            f"Add the validator public key reported by server_info to {WELL_KNOWN_PATH}. See {POSTFIAT_SCHEMA_DOC}.",
                        ))
                    else:
                        network = str(match.get("network", "")).lower()
                        status = PASS if network in {expected_network, ""} else WARN
                        checks.append(CheckResult(
                            "Well-known attestation contents",
                            "domain",
                            status,
                            f"public_key={match.get('public_key')} network={network or 'missing'}",
                            f"public_key={expected_pubkey or 'server_info pubkey_validator'} network={expected_network}",
                            "" if status == PASS else "Update the `network` field so the attestation matches the validator environment reported by server_info.",
                        ))

        if full:
            if server_info:
                checks.append(await _crawl_check(rpc_endpoint, server_info))
            else:
                checks.append(CheckResult("Crawl pubkey_validator", "extended", SKIP, "RPC unavailable", "https://<host>:2559/crawl exposes pubkey_validator", "Fix RPC reachability first."))
            docker_status, docker_restart = _docker_check()
            checks.extend([docker_status, docker_restart, _free_disk_check()])

    report = {
        "tool": "validator-local-preflight",
        "version": "0.1.0",
        "generated_at": datetime.now(UTC).isoformat(),
        "rpc_endpoint": rpc_endpoint,
        "domain": domain,
        "full": full,
        "checks": [check.as_dict() for check in checks],
    }
    upload_check = await _upload_report(report, upload_url)
    report["checks"].append(upload_check.as_dict())
    return report
