import json
from pathlib import Path

from .models import AuditReport


def write_reports(report: AuditReport, output_dir: str | Path) -> tuple[Path, Path]:
    directory = Path(output_dir)
    directory.mkdir(parents=True, exist_ok=True)
    stamp = report.generated_at.replace(":", "-").replace("+", "_")
    json_path = directory / f"system-audit-{stamp}.json"
    md_path = directory / f"system-audit-{stamp}.md"
    json_path.write_text(json.dumps(report.to_dict(), indent=2), encoding="utf-8")

    counts: dict[str, int] = {}
    for item in report.results:
        counts[item.status] = counts.get(item.status, 0) + 1
    lines = [
        "# System Vulnerability Audit Report", "",
        f"- **Generated (UTC):** {report.generated_at}",
        f"- **Host:** {report.hostname}",
        f"- **Operating system:** {report.operating_system}",
        "", "> This is an educational baseline review, not a penetration test or certification.",
        "", "## Summary", "",
    ]
    lines.extend(f"- **{status}:** {count}" for status, count in sorted(counts.items()))
    lines += ["", "## Results", ""]
    for item in report.results:
        lines += [f"### {item.check_id} — {item.title}", "", f"- **Status:** {item.status}", f"- **Details:** {item.details}", f"- **Recommendation:** {item.recommendation}"]
        if item.evidence:
            lines += ["- **Evidence:**", "", "```text", item.evidence.replace("```", "'''"), "```"]
        lines.append("")
    lines += ["## Analyst notes", "", "Add at least three verified findings, evidence, impact, risk rating, remediation, and post-remediation verification. Do not include secrets.", ""]
    md_path.write_text("\n".join(lines), encoding="utf-8")
    return md_path, json_path
