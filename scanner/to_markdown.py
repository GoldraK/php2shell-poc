#!/usr/bin/env python3
"""
Convert scanner/results.json → markdown report.

Usage:
    python3 scanner/to_markdown.py scanner/results.json > report.md
    python3 scanner/to_markdown.py scanner/results.json --out report.md
    python3 scanner/to_markdown.py --input results.json --out docs/scan-report.md
"""

import argparse
import json
import sys
from pathlib import Path


def version_label(tag):
    """Short label for display (strip -fpm suffix for cleaner look)."""
    return tag.replace("-fpm", "")


def chain_status(vuln, uid):
    if vuln:
        return f"✅ **VULNERABLE** (uid={uid})" if uid else "✅ **VULNERABLE**"
    return "❌ Patched / Not exploitable"


def format_chain_result(chain):
    vuln = chain.get("vulnerable", False)
    uid = chain.get("uid", "N/A") or "N/A"
    err = chain.get("error", "")
    exit_code = chain.get("exit_code", "N/A")

    lines = []

    if err:
        lines.append(f"- **Status:** {chain_status(vuln, uid)}")
        lines.append(f"- **Error:** `{err}`")
    else:
        lines.append(f"- **Status:** {chain_status(vuln, uid)}")
        lines.append(f"- **UID:** {uid}")
        lines.append(f"- **Exit code:** {exit_code}")

    if chain.get("details"):
        snippet = chain["details"][:200].replace("`", "\\`")
        lines.append(f"- **Output:** `{snippet.strip()[:80]}...`" if len(snippet) > 80 else f"- **Output:** `{snippet.strip()}`")

    return "\n".join(lines)


def build_report(data):
    lines = []

    # Header
    lines.append("# PHP 2Shell — Version Scan Report")
    lines.append("")

    meta = data.get("scan_metadata", {})
    summary = data.get("summary", {})

    lines.append("## Summary")
    lines.append("")
    lines.append(f"| Metric | Value |")
    lines.append(f"|--------|-------|")
    lines.append(f"| Total versions tested | {summary.get('total_tested', 0)} |")
    lines.append(f"| Vulnerable | {summary.get('total_vulnerable', 0)} |")
    lines.append(f"| Patched / Not exploitable | {summary.get('total_patched', 0)} |")
    lines.append(f"| Exploitability rate | {summary['total_vulnerable'] / summary['total_tested'] * 100:.1f}% |" if summary.get('total_tested', 0) else "")
    lines.append("")

    # Version table
    lines.append("## Results by Version")
    lines.append("")
    lines.append("| PHP Version | Chain A | Chain C | Chain E | Status | Error |")
    lines.append("|-------------|---------|---------|---------|--------|-------|")

    for r in data.get("results", []):
        ver = version_label(r.get("php_version", "?"))
        chains = r.get("chains", {})

        chain_a = chain_status(chains.get("A", {}).get("vulnerable", False), chains.get("A", {}).get("uid", "N/A"))
        chain_c = chain_status(chains.get("C", {}).get("vulnerable", False), chains.get("C", {}).get("uid", "N/A"))
        chain_e = chain_status(chains.get("E", {}).get("vulnerable", False), chains.get("E", {}).get("uid", "N/A"))

        if any(chains.get(c, {}).get("vulnerable", False) for c in ("A", "C", "E")):
            overall = "⚠️ VULNERABLE"
        elif r.get("error"):
            overall = "⚠️ Error"
        else:
            overall = "✅ Patched"

        err = r.get("error", "") or ""

        # Escape pipe chars in error
        err = err.replace("|", "\\|")[:60]
        if err:
            err = f"[{err}]"

        lines.append(f"| {ver} | {chain_a} | {chain_c} | {chain_e} | {overall} | {err} |")

    lines.append("")

    # Vulnerable versions section
    vuln_results = [r for r in data.get("results", [])
                    if any(r.get("chains", {}).get(c, {}).get("vulnerable", False) for c in ("A", "C", "E"))]
    patched_results = [r for r in data.get("results", [])
                       if not any(r.get("chains", {}).get(c, {}).get("vulnerable", False) for c in ("A", "C", "E"))]

    if vuln_results:
        lines.append("## Vulnerable Versions")
        lines.append("")
        lines.append("The following versions are exploitable on at least one chain:")
        lines.append("")
        for r in vuln_results:
            ver = version_label(r.get("php_version", "?"))
            vuln_chains = [c for c in ("A", "C", "E") if r.get("chains", {}).get(c, {}).get("vulnerable", False)]
            uid = r["chains"].get("A", {}).get("uid", r["chains"].get("C", {}).get("uid", ""))
            lines.append(f"- **{ver}** — chains: {', '.join(vuln_chains)}" + (f" (uid={uid})" if uid else ""))
        lines.append("")

    if patched_results:
        lines.append("## Patched / Not Exploitable Versions")
        lines.append("")
        lines.append("The following versions did not yield RCE on any chain:")
        lines.append("")
        for r in patched_results:
            ver = version_label(r.get("php_version", "?"))
            err = r.get("error", "")
            lines.append(f"- **{ver}**" + (f" — `{err}`" if err else ""))
        lines.append("")

    # Per-version details
    lines.append("## Detailed Per-Version Results")
    lines.append("")

    for r in data.get("results", []):
        ver = version_label(r.get("php_version", "?"))
        vuln_count = sum(1 for c in r.get("chains", {}).values() if c.get("vulnerable", False))
        has_error = bool(r.get("error"))

        if vuln_count == 3:
            emoji = "🔴"
        elif vuln_count >= 1:
            emoji = "🟠"
        else:
            emoji = "🟢"

        lines.append(f"### {emoji} PHP {ver}")
        lines.append("")

        if has_error:
            lines.append(f"**Error:** `{r['error']}`\n")

        for chain_id in ("A", "C", "E"):
            chain = r.get("chains", {}).get(chain_id, {})
            if chain:
                lines.append(f"**Chain {chain_id}** ({chain_id_map[chain_id]})")
                lines.append(format_chain_result(chain))
                lines.append("")

        if vuln_count >= 1:
            lines.append(f"> ⚠️ **{vuln_count}/3 chains exploitable** — PHP {ver} is vulnerable.")
            lines.append("")

    # Footer
    lines.append("---")
    lines.append(f"*Generated by `scanner/to_markdown.py` from `scanner/results.json`*")

    return "\n".join(lines)


chain_id_map = {
    "A": "session injection + LFI → RCE",
    "C": "handler mismatch → __destruct → RCE",
    "E": "decode failure → __destruct → RCE",
}


def main():
    ap = argparse.ArgumentParser(description="Convert scanner results JSON → markdown report")
    ap.add_argument("input", nargs="?", help="Path to results.json")
    ap.add_argument("--results", "-r", dest="input", help="Path to results.json")
    ap.add_argument("--out", "-o", type=str, default=None, help="Write to file instead of stdout")
    args = ap.parse_args()

    input_path = args.input or "scanner/results.json"
    with open(input_path) as f:
        data = json.load(f)

    md = build_report(data)

    if args.out:
        Path(args.out).write_text(md)
        print(f"[✓] Report written to {args.out}", file=sys.stderr)
    else:
        print(md)


if __name__ == "__main__":
    main()