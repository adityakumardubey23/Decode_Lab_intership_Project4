import argparse
import platform
import socket

from .checks import manual_checklist, run_audit
from .models import AuditReport
from .reporting import write_reports


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="sysaudit", description="Read-only defensive system checklist")
    sub = parser.add_subparsers(dest="command", required=True)
    audit = sub.add_parser("audit", help="Run supported checks and write reports")
    audit.add_argument("--output", default="reports", help="Report directory (default: reports)")
    sub.add_parser("checklist", help="Print the manual review checklist")
    return parser


def main() -> None:
    args = build_parser().parse_args()
    if args.command == "checklist":
        for item in manual_checklist():
            print(f"[{item.check_id}] {item.title}\n  {item.recommendation}\n")
        return
    results = run_audit()
    report = AuditReport.create(socket.gethostname(), f"{platform.system()} {platform.release()}", results)
    md_path, json_path = write_reports(report, args.output)
    print("System audit completed. Review UNKNOWN and MANUAL items rather than treating them as PASS.")
    print(f"Markdown report: {md_path}")
    print(f"JSON report:     {json_path}")
    for item in results:
        print(f"{item.status:7} {item.check_id} {item.title}")


if __name__ == "__main__":
    main()
