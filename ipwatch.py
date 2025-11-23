#!/usr/bin/env python3

import json
import urllib.request
import urllib.error
from datetime import datetime
import csv
import os
import argparse
import sys
from typing import List, NamedTuple
import platform


class IPRecord(NamedTuple):
    timestamp: str
    ip: str
    isp: str
    comment: str


def get_log_path():
    LOG_FILENAME = "ipwatch_log.csv"

    # Попытка 1: Windows — через реестр
    if platform.system() == "Windows":
        try:
            import winreg
            key_path = r"Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders"
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path) as key:
                docs_dir, _ = winreg.QueryValueEx(key, "Personal")
                if os.path.isdir(docs_dir):
                    return os.path.join(docs_dir, LOG_FILENAME)
        except Exception:
            pass
    
    home = os.path.expanduser("~")
    # Попытка 2: ~/Documents (актуально для десктопов)
    docs_path = os.path.join(home, "Documents")
    if os.path.isdir(docs_path):
        return os.path.join(docs_path, LOG_FILENAME)

    # Попытка 3: fallback в ~/.ipwatch/
    fallback_dir = os.path.join(home, ".ipwatch")
    os.makedirs(fallback_dir, exist_ok=True)
    return os.path.join(fallback_dir, LOG_FILENAME)


class CSVStorage:
    def __init__(self):
        self.filename = get_log_path()
        os.makedirs(os.path.dirname(self.filename), exist_ok=True)
        self._ensure_file_exists()

    def _ensure_file_exists(self) -> None:
        if not os.path.exists(self.filename):
            with open(self.filename, "w", newline="") as f:
                writer = csv.writer(f, delimiter="\t")
                writer.writerow(["Timestamp", "IP Address", "ISP", "Comment"])

    def read_all_rows(self) -> List[List[str]]:
        rows = []
        if not os.path.exists(self.filename):
            return rows
        try:
            with open(self.filename, "r", newline="") as f:
                reader = csv.reader(f, delimiter="\t")
                next(reader, None)
                for row in reader:
                    if len(row) >= 4:
                        rows.append(row)
        except Exception as e:
            print(f"Error reading file: {e}", file=sys.stderr)
        return rows

    def save(self, record: IPRecord) -> None:
        with open(self.filename, "a", newline="") as f:
            writer = csv.writer(f, delimiter="\t")
            writer.writerow([record.timestamp, record.ip, record.isp, record.comment])


class TablePresenter:
    def _make_headers(self) -> List[str]:
        return ["Timestamp", "IP Address", "ISP", "Comment"]

    def _print_table(self, headers: List[str], rows: List[List[str]]) -> None:
        if not rows:
            return
        col_widths = [
            max(len(str(row[i])) for row in [headers] + rows)
            for i in range(len(headers))
        ]
        format_str = " | ".join([f"{{:<{width}}}" for width in col_widths])
        separator = "-" * (sum(col_widths) + 3 * (len(col_widths) - 1))

        print(separator, file=sys.stderr)
        print(format_str.format(*headers), file=sys.stderr)
        print(separator, file=sys.stderr)
        for row in rows:
            print(format_str.format(*row), file=sys.stderr)
        print(separator, file=sys.stderr)

    def display_current(self, record: IPRecord) -> None:
        headers = self._make_headers()
        rows = [[record.timestamp, record.ip, record.isp, record.comment]]
        self._print_table(headers, rows)

    def display_matches(self, records: List[IPRecord]) -> None:
        headers = self._make_headers()
        rows = [[r.timestamp, r.ip, r.isp, r.comment] for r in records]
        print("\n ⚠️\t IP matches found:", file=sys.stderr)
        self._print_table(headers, rows)

    def display_no_match(self) -> None:
        print("\n ✅\t No IP matches", file=sys.stderr)

    def display_list(self, rows: List[List[str]]) -> None:
        if not rows:
            print("No IP records found.", file=sys.stderr)
            return
        headers = self._make_headers()
        self._print_table(headers, rows)


def fetch_ip_from_api() -> dict:
    url = "http://ip-api.com/json/?fields=query,isp"
    with urllib.request.urlopen(url, timeout=10) as response:
        return json.loads(response.read().decode())


def format_record(data: dict, comment: str = "") -> IPRecord:
    return IPRecord(
        timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        ip=data.get("query", "N/A"),
        isp=data.get("isp", "N/A"),
        comment=comment or "N/A"
    )


def main():
    examples = """
examples:
  ipwatch                              # only display current IP (no save)
  ipwatch -s                           # save IP without comment
  ipwatch -c "connected to cafe Wi-Fi" # save IP with comment
  ipwatch -l                           # list all logged IPs
  LOG=$(ipwatch --show-log-path)       # get log file path for scripts
  ipwatch --show-log-path              # show log path and exit
"""
    parser = argparse.ArgumentParser(
        description="Watch your public IP and optionally log it with a comment.",
        epilog=examples,
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        "-c", "--comment",
        type=str,
        default=None,
        help="Save current IP with a comment"
    )
    parser.add_argument(
        "-s", "--save",
        action="store_true",
        help="Save current IP without comment"
    )
    parser.add_argument(
        "-l", "--list",
        action="store_true",
        help="Display all logged IP records"
    )
    parser.add_argument(
        "--show-log-path",
        action="store_true",
        help="Show the path to the log file and exit"
)
    args = parser.parse_args()

    storage = CSVStorage()
    if args.show_log_path:
        print(storage.filename)
        sys.exit(0)

    presenter = TablePresenter()
    if args.list:
        all_rows = storage.read_all_rows()
        presenter.display_list(all_rows)
        sys.exit(0)

    # Определяем, нужно ли сохранять
    should_save = args.comment is not None or args.save
    comment = args.comment if args.comment is not None else ""

    try:
        raw_data = fetch_ip_from_api()
        record = format_record(raw_data, comment)
        current_ip = record.ip

        all_rows = storage.read_all_rows()
        existing_ips = {row[1] for row in all_rows}
        is_new = current_ip not in existing_ips

        presenter.display_current(record)

        if not is_new:
            matches = [
                IPRecord(row[0], row[1], row[2], row[3])
                for row in all_rows if row[1] == current_ip
            ]
            presenter.display_matches(matches)
        else:
            presenter.display_no_match()

        if should_save:
            storage.save(record)
            print("✅ IP saved to log.", file=sys.stderr)

        sys.exit(0 if is_new else 1)

    except urllib.error.URLError as e:
        print(f"Network error: unable to reach IP provider ({e})", file=sys.stderr)
    except json.JSONDecodeError as e:
        print(f"Invalid response from IP provider: {e}", file=sys.stderr)
    except Exception as e:
        print(f"Unexpected error: {e}", file=sys.stderr)

    sys.exit(1)


if __name__ == "__main__":
    main()