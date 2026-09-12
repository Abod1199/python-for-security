"""Main entry point for LogShield."""

from pathlib import Path

from rich.console import Console

from .parser import load_events
from .triage import build_report
from .utils import save_json, validate_file


console = Console()


def main():
    """Run the LogShield security analysis."""
    base_dir = Path(__file__).resolve().parent.parent

    log_path = base_dir / "data" / "sample_logs.txt"
    report_path = base_dir / "reports" / "triage_report.json"

    console.print("=" * 45)
    console.print("          LOGSHIELD")
    console.print("     Security Log Analyzer")
    console.print("=" * 45)

    try:
        validate_file(log_path)

        console.print(
            "\n[+] Log file loaded successfully."
        )

        events = load_events(log_path)

        if not events:
            console.print(
                "[-] No valid log events found."
            )
            return

        report = build_report(events)

        console.print(
            "[+] Log analysis completed."
        )

        console.print(
            f"\nTotal Events: {report['total_events']}"
        )

        console.print(
            f"INFO: {report['log_levels']['INFO']}"
        )

        console.print(
            f"WARNING: {report['log_levels']['WARNING']}"
        )

        console.print(
            f"ERROR: {report['log_levels']['ERROR']}"
        )

        console.print("\nSuspicious IPs:")

        if report["suspicious_ips"]:
            for ip, count in report["suspicious_ips"].items():
                console.print(
                    f"- {ip}: {count} failed login attempts"
                )
        else:
            console.print("- None detected")

        console.print(
            f"\nThreat Score: {report['threat_score']}"
        )

        console.print(
            f"Threat Level: {report['threat_level']}"
        )

        save_json(report, report_path)

        console.print(
            f"\n[+] Report saved to: {report_path}"
        )

    except FileNotFoundError as error:
        console.print(f"[-] {error}")

    except PermissionError:
        console.print(
            "[-] Permission denied while accessing a file."
        )

    except OSError as error:
        console.print(
            f"[-] File system error: {error}"
        )


if __name__ == "__main__":
    main()