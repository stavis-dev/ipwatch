#!/usr/bin/env python3

import json
import urllib.request
import urllib.error
from datetime import datetime
from abc import ABC, abstractmethod
import csv
import os
import argparse
import sys
from typing import Dict, Any, List, NamedTuple
import platform

class IPRecord(NamedTuple):
    timestamp: str
    ip: str
    isp: str
    comment: str


class DataProvider(ABC):
    @abstractmethod
    def fetch_data(self) -> Dict[str, Any]:
        pass


class IPAPIProvider(DataProvider):
    def __init__(self, url: str = "http://ip-api.com/json/?fields=query,isp"):
        self.url = url

    def fetch_data(self) -> Dict[str, Any]:
        with urllib.request.urlopen(self.url, timeout=10) as response:
            return json.loads(response.read().decode())


class DataFormatter(ABC):
    @abstractmethod
    def format(self, data: Dict[str, Any], comment: str = "") -> IPRecord:
        pass


class IPDataFormatter(DataFormatter):
    def format(self, data: Dict[str, Any], comment: str = "") -> IPRecord:
        return IPRecord(
            timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            ip=data.get("query", "N/A"),
            isp=data.get("isp", "N/A"),
            comment=comment or "N/A"
        )


class DataStorage(ABC):
    @abstractmethod
    def save(self, record: IPRecord) -> None:
        pass

    @abstractmethod
    def read_all_rows(self) -> List[List[str]]:
        pass

    @abstractmethod
    def find_records_by_ip(self, ip: str) -> List[IPRecord]:
        pass


def get_documents_path():
    system = platform.system()
    if system == "Windows":
        try:
            import winreg
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders") as key:
                documents_dir, _ = winreg.QueryValueEx(key, "Personal")
                return documents_dir
        except Exception:
            pass
    # fallback для Linux/macOS
    home = os.path.expanduser("~")
    return os.path.join(home, "Documents")


class CSVDataStorage(DataStorage):
    def __init__(self, filename: str = None):
        if filename is None:
            filename = os.path.join(get_documents_path(), "ipwatch_log.csv")
        self.filename = filename
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

    def find_records_by_ip(self, ip: str) -> List[IPRecord]:
        rows = self.read_all_rows()
        return [
            IPRecord(row[0], row[1], row[2], row[3])
            for row in rows if row[1] == ip
        ]

    def save(self, record: IPRecord) -> None:
        with open(self.filename, "a", newline="") as f:
            writer = csv.writer(f, delimiter="\t")
            writer.writerow([record.timestamp, record.ip, record.isp, record.comment])


class DataPresenter(ABC):
    @abstractmethod
    def display(self, record: IPRecord) -> None:
        pass

    @abstractmethod
    def display_match_found(self, records: List[IPRecord]) -> None:
        pass

    @abstractmethod
    def display_no_match(self) -> None:
        pass


class TableDataPresenter(DataPresenter):
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

    def display(self, record: IPRecord) -> None:
        headers = ["Timestamp", "IP Address", "ISP", "Comment"]
        rows = [[record.timestamp, record.ip, record.isp, record.comment]]
        self._print_table(headers, rows)

    def display_match_found(self, records: List[IPRecord]) -> None:
        if not records:
            return
        headers = ["Timestamp", "IP Address", "ISP", "Comment"]
        rows = [[r.timestamp, r.ip, r.isp, r.comment] for r in records]
        print("\n ⚠️\t IP matches found:", file=sys.stderr)
        self._print_table(headers, rows)

    def display_no_match(self) -> None:
        print("\n ✅\t No IP matches", file=sys.stderr)


class IPInfoService:
    def __init__(
        self,
        provider: DataProvider,
        formatter: DataFormatter,
        storage: DataStorage,
        presenter: DataPresenter,
    ):
        self.provider = provider
        self.formatter = formatter
        self.storage = storage
        self.presenter = presenter

    def run(self, comment: str = "") -> bool:
        """
        Returns:
            True if IP is NEW (exit code 0),
            False if IP was seen before (exit code 1).
        """
        try:
            raw_data = self.provider.fetch_data()
            record = self.formatter.format(raw_data, comment=comment)
            current_ip = record.ip

            all_rows = self.storage.read_all_rows()
            existing_ips = {row[1] for row in all_rows}

            has_match = current_ip in existing_ips

            self.presenter.display(record)

            if has_match:
                matches = self.storage.find_records_by_ip(current_ip)
                self.presenter.display_match_found(matches)
            else:
                self.presenter.display_no_match()

            self.storage.save(record)

            return not has_match  # True = new IP

        except urllib.error.URLError as e:
            print(f"Network error: unable to reach IP provider ({e})", file=sys.stderr)
        except json.JSONDecodeError as e:
            print(f"Invalid response from IP provider: {e}", file=sys.stderr)
        except Exception as e:
            print(f"Unexpected error: {e}", file=sys.stderr)

        # В случае ошибки — считаем, что IP не проверен → не новый
        return False


def main():
    parser = argparse.ArgumentParser(description="Watch and log your public IP. Exit code: 0 = new IP, 1 = repeated IP.")
    parser.add_argument(
        "-c", "--comment",
        type=str,
        default="",
        help="Optional comment to attach to this log entry"
    )
    args = parser.parse_args()

    service = IPInfoService(
        provider=IPAPIProvider(),
        formatter=IPDataFormatter(),
        storage=CSVDataStorage(),
        presenter=TableDataPresenter(),
    )

    is_new = service.run(comment=args.comment)
    sys.exit(0 if is_new else 1)


if __name__ == "__main__":
    main()