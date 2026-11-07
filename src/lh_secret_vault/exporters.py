# ==============================================================================
# Product:       lh-secret-vault (lh-vault)
# Module:        src.lh_secret_vault.exporters
# Role:          SARIF, JSON & Rich Terminal Table Exporters
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""Report exporters for lh-secret-vault: Rich Table, JSON, and OASIS SARIF v2.1.0."""

from __future__ import annotations

import json
from typing import Any

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from lh_secret_vault.models import (
    RULES_REGISTRY,
    FindingSeverity,
    VaultReport,
)


def severity_to_style(severity: FindingSeverity) -> str:
    """Return Rich markup style for severity rating."""
    mapping = {
        FindingSeverity.CRITICAL: "bold red",
        FindingSeverity.HIGH: "red",
        FindingSeverity.MEDIUM: "yellow",
        FindingSeverity.LOW: "blue",
    }
    return mapping.get(severity, "white")


def severity_to_sarif_level(severity: FindingSeverity) -> str:
    """Map FindingSeverity to OASIS SARIF 2.1.0 level."""
    mapping = {
        FindingSeverity.CRITICAL: "error",
        FindingSeverity.HIGH: "error",
        FindingSeverity.MEDIUM: "warning",
        FindingSeverity.LOW: "note",
    }
    return mapping.get(severity, "note")


def render_table_report(report: VaultReport, console: Console | None = None) -> None:
    # --- Rich Terminal Table Presentation Layout ---
    # Renders structured security findings with ANSI color highlights,
    # severity-coded badges, file locations, and executive posture summaries.
    """Render an enterprise Rich table report of secret vault audit findings."""
    con = console or Console()

    if not report.findings:
        con.print(
            Panel(
                f"[bold green]No secret vault vulnerabilities or policy misconfigurations "
                f"detected across {report.files_scanned} file(s) in '{report.target}'.[/]",
                title="[bold green]Scan Clean[/]",
                border_style="green",
            )
        )
        return

    table = Table(
        title=f"lh-secret-vault Audit Report ({report.findings_count} Findings)",
        header_style="bold cyan",
        show_lines=True,
    )
    table.add_column("Rule ID", style="bold", width=14)
    table.add_column("Severity", width=10, justify="center")
    table.add_column("Category", width=18)
    table.add_column("Target / Key", width=22)
    table.add_column("Description", width=46)

    for f in report.findings:
        sev_style = severity_to_style(f.severity)
        key_label = f"{f.secret_key or f.target}"
        if f.line_number:
            key_label += f":{f.line_number}"
        table.add_row(
            f.rule_id,
            f"[{sev_style}]{f.severity.value}[/]",
            f.category,
            key_label,
            f.description,
        )

    con.print(table)

    summary_text = (
        f"[bold red]Critical:[/] {report.summary.get('critical', 0)} | "
        f"[red]High:[/] {report.summary.get('high', 0)} | "
        f"[yellow]Medium:[/] {report.summary.get('medium', 0)} | "
        f"[blue]Low:[/] {report.summary.get('low', 0)} | "
        f"[bold]Total Scanned:[/] {report.files_scanned} files"
    )
    con.print(Panel(summary_text, title="[bold]Severity Summary[/]", border_style="cyan"))


def export_json(report: VaultReport, indent: int = 2) -> str:
    """Export audit report as structured JSON document."""
    data: dict[str, Any] = {
        "schema_version": "1.0.0",
        "scanner": "lh-secret-vault",
        "target": report.target,
        "files_scanned": report.files_scanned,
        "vault_manifests_analyzed": report.vault_manifests_analyzed,
        "findings_count": report.findings_count,
        "summary": report.summary,
        "findings": [f.to_dict() for f in report.findings],
    }
    return json.dumps(data, indent=indent)


def export_sarif(report: VaultReport, indent: int = 2) -> str:
    # --- OASIS SARIF v2.1.0 Compliance Exporter ---
    # Serializes audit results into standard SARIF JSON format for native
    # GitHub Code Scanning, GitLab Security Dashboard, and IDE integrations.
    """Export audit report as OASIS SARIF v2.1.0 document."""
    rules_dict: dict[str, dict[str, Any]] = {}
    for rule_id, rule_def in RULES_REGISTRY.items():
        rules_dict[rule_id] = {
            "id": rule_id,
            "name": rule_def.title.replace(" ", ""),
            "shortDescription": {"text": rule_def.title},
            "fullDescription": {"text": rule_def.description},
            "defaultConfiguration": {"level": severity_to_sarif_level(rule_def.severity)},
            "help": {"text": f"Remediation: {rule_def.remediation}"},
        }

    results: list[dict[str, Any]] = []
    for f in report.findings:
        res = {
            "ruleId": f.rule_id,
            "level": severity_to_sarif_level(f.severity),
            "message": {"text": f"[{f.category}] {f.description} (Target: {f.target})"},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": f.target},
                        "region": {"startLine": f.line_number or 1},
                    }
                }
            ],
            "properties": {
                "secretKey": f.secret_key,
                "remediation": f.remediation,
                "snippet": f.snippet,
            },
        }
        results.append(res)

    sarif_doc: dict[str, Any] = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "lh-secret-vault",
                        "version": "0.1.0",
                        "informationUri": "https://github.com/Logihertz-Systems-OPC-Pvt-Ltd/lh-secret-vault",
                        "rules": list(rules_dict.values()),
                    }
                },
                "results": results,
            }
        ],
    }
    return json.dumps(sarif_doc, indent=indent)
