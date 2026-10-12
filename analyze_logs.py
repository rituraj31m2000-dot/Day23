#!/usr/bin/env python3
"""Day 23: Authentication Log Analysis for synthetic or authorized CSV logs."""
import argparse
import csv
from collections import Counter
from datetime import datetime
from pathlib import Path
import sys

VALID_STATUSES = {"SUCCESS", "FAILED"}
REQUIRED_COLUMNS = {"timestamp", "username", "source_ip", "status", "service"}


def main():
    parser = argparse.ArgumentParser(description="Summarize authentication events and flag repeated failures.")
    parser.add_argument("csv_file", nargs="?", default="auth_logs.csv", help="CSV input (default: auth_logs.csv)")
    parser.add_argument("--threshold", type=int, default=3, help="Minimum failures per username/IP pair to flag")
    parser.add_argument("--output", default="analysis_summary.txt", help="Summary output filename")
    args = parser.parse_args()
    if args.threshold < 1:
        parser.error("--threshold must be at least 1")

    path = Path(args.csv_file)
    if not path.is_file():
        print(f"Error: CSV file not found: {path}", file=sys.stderr)
        return 1

    events = []
    try:
        with path.open(newline="", encoding="utf-8-sig") as f:
            reader = csv.DictReader(f)
            if not reader.fieldnames:
                print("Error: CSV is empty or missing a header.", file=sys.stderr)
                return 1
            missing = REQUIRED_COLUMNS - set(reader.fieldnames)
            if missing:
                print("Error: missing required columns: " + ", ".join(sorted(missing)), file=sys.stderr)
                return 1
            for line_no, row in enumerate(reader, start=2):
                status = (row.get("status") or "").strip().upper()
                try:
                    timestamp = datetime.fromisoformat((row.get("timestamp") or "").strip())
                except ValueError:
                    print(f"Warning: skipping line {line_no}: invalid timestamp", file=sys.stderr)
                    continue
                username = (row.get("username") or "").strip()
                source_ip = (row.get("source_ip") or "").strip()
                service = (row.get("service") or "").strip()
                if status not in VALID_STATUSES or not username or not source_ip or not service:
                    print(f"Warning: skipping line {line_no}: invalid or missing field", file=sys.stderr)
                    continue
                events.append({"timestamp": timestamp, "username": username, "source_ip": source_ip,
                               "status": status, "service": service})
    except OSError as exc:
        print(f"Error reading CSV: {exc}", file=sys.stderr)
        return 1

    if not events:
        print("No valid authentication events found.")
        return 0

    status_counts = Counter(e["status"] for e in events)
    users = Counter(e["username"] for e in events)
    ips = Counter(e["source_ip"] for e in events)
    failures_by_ip = Counter(e["source_ip"] for e in events if e["status"] == "FAILED")
    failures_by_pair = Counter((e["username"], e["source_ip"]) for e in events if e["status"] == "FAILED")
    service_status = Counter((e["service"], e["status"]) for e in events)
    total = len(events)
    failed = status_counts["FAILED"]

    lines = ["DAY 23 — AUTHENTICATION LOG ANALYSIS", "=" * 40,
             f"Input file: {path}", f"Valid events analyzed: {total}",
             f"Successful logins: {status_counts['SUCCESS']}", f"Failed logins: {failed}",
             f"Failure rate: {failed / total * 100:.1f}%", "", "EVENTS BY USERNAME:"]
    lines.extend(f"  {user}: {count}" for user, count in users.most_common())
    lines.extend(["", "EVENTS BY SOURCE IP:"])
    lines.extend(f"  {ip}: {count} total event(s), {failures_by_ip[ip]} failure(s)" for ip, count in ips.most_common())
    lines.extend(["", f"REPEATED FAILURES (threshold: {args.threshold} per username/IP pair):"])
    flagged = [(user, ip, count) for (user, ip), count in failures_by_pair.most_common() if count >= args.threshold]
    if flagged:
        lines.extend(f"  REVIEW: username={user}, source_ip={ip}, failed_attempts={count}" for user, ip, count in flagged)
    else:
        lines.append("  No username/IP pair reached the threshold.")
    lines.extend(["", "EVENTS BY SERVICE AND STATUS:"])
    lines.extend(f"  {service} / {status}: {count}" for (service, status), count in sorted(service_status.items()))
    lines.extend(["", "INTERPRETATION:",
                  "- Repeated failures may be caused by mistyped credentials, a misconfigured service, or a possible attack.",
                  "- Investigate context and correlate with other logs before concluding an event is malicious.",
                  "- This script summarizes events; it does not block accounts or change system settings."])
    report = "\n".join(lines) + "\n"
    print(report)
    try:
        Path(args.output).write_text(report, encoding="utf-8")
    except OSError as exc:
        print(f"Error writing summary: {exc}", file=sys.stderr)
        return 1
    print(f"Summary saved to: {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
