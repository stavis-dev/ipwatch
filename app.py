#!/usr/bin/env python3

import json
import urllib.request
from datetime import datetime
from abc import ABC, abstractmethod
import csv
import os
from typing import Dict, Any, List, Set


class DataProvider(ABC):
    @abstractmethod
    def fetch_data(self) -> Dict[str, Any]:
        pass


class IPAPIProvider(DataProvider):
    def __init__(self, url: str = "http://ip-api.com/json/?fields=query,isp"):
        self.url = url

    def fetch_data(self) -> Dict[str, Any]:
        with urllib.request.urlopen(self.url) as response:
            return json.loads(response.read().decode())


class DataFormatter(ABC):
    @abstractmethod
    def format(self, data: Dict[str, Any]) -> Dict[str, Any]:
        pass


class IPDataFormatter(DataFormatter):
    def format(self, data: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "isp": data.get("isp", "N/A"),
            "ip": data.get("query", "N/A")
        }


class DataStorage(ABC):
    @abstractmethod
    def save(self, data: Dict[str, Any]) -> None:
        pass
    
    @abstractmethod
    def get_all_ips(self) -> Set[str]:
        pass


class CSVDataStorage(DataStorage):
    def __init__(self, filename: str = "ip_data.csv"):
        self.filename = filename
        self._ensure_file_exists()

    def _ensure_file_exists(self) -> None:
        if not os.path.exists(self.filename):
            with open(self.filename, "w", newline="") as f:
                writer = csv.writer(f, delimiter="\t")
                writer.writerow(["Timestamp", "ISP", "IP Address"])

    def _read_all_rows(self) -> List[List[str]]:
        """Reads all data rows (excluding header) from the file"""
        rows = []
        if not os.path.exists(self.filename):
            return rows
        try:
            with open(self.filename, "r", newline="") as f:
                reader = csv.reader(f, delimiter="\t")
                next(reader, None)  # Skip header
                for row in reader:
                    if len(row) >= 3:
                        rows.append(row)
        except Exception as e:
            print(f"Error reading file: {e}")
        return rows

    def save(self, data: Dict[str, Any]) -> None:
        with open(self.filename, "a", newline="") as f:
            writer = csv.writer(f, delimiter="\t")
            writer.writerow([data["timestamp"], data["isp"], data["ip"]])

    def get_all_ips(self) -> Set[str]:
        """Returns a set of all IP addresses from the file"""
        return {row[2] for row in self._read_all_rows()}


class DataPresenter(ABC):
    @abstractmethod
    def display(self, data: Dict[str, Any]) -> None:
        pass
    
    @abstractmethod
    def display_match_found(self, matched_data: List[List[str]]) -> None:
        pass
    
    @abstractmethod
    def display_no_match(self) -> None:
        pass


class TableDataPresenter(DataPresenter):
    def _print_table(self, headers: List[str], rows: List[List[str]]) -> None:
        """Prints a table with given headers and rows"""
        if not rows:
            return
        # Calculate maximum width for each column
        col_widths = [
            max(len(str(row[i])) for row in [headers] + rows)
            for i in range(len(headers))
        ]
        # Format string
        format_str = " | ".join([f"{{:<{width}}}" for width in col_widths])
        separator = "-" * (sum(col_widths) + 3 * (len(col_widths) - 1))

        print(separator)
        print(format_str.format(*headers))
        print(separator)
        for row in rows:
            print(format_str.format(*row))
        print(separator)

    def display(self, data: Dict[str, Any]) -> None:
        headers = ["Timestamp", "ISP", "IP Address"]
        rows = [[data["timestamp"], data["isp"], data["ip"]]]
        self._print_table(headers, rows)

    def display_match_found(self, matched_data: List[List[str]]) -> None:
        if not matched_data:
            return
        headers = ["Timestamp", "ISP", "IP Address"]
        print("\n ⚠️\t IP matches found:")
        self._print_table(headers, matched_data)

    def display_no_match(self) -> None:
        print("\n ✅\t No IP matches")


class IPChecker(ABC):
    @abstractmethod
    def check_ip(self, ip: str, existing_ips: Set[str]) -> bool:
        pass


class SimpleIPChecker(IPChecker):
    def check_ip(self, ip: str, existing_ips: Set[str]) -> bool:
        return ip in existing_ips


class MatchFinder(ABC):
    @abstractmethod
    def find_matches(self, ip: str, storage: DataStorage) -> List[List[str]]:
        pass


class CSVMatchFinder(MatchFinder):
    def find_matches(self, ip: str, storage: DataStorage) -> List[List[str]]:
        if not isinstance(storage, CSVDataStorage):
            raise TypeError("Storage must be CSVDataStorage for CSVMatchFinder")
        return [row for row in storage._read_all_rows() if row[2] == ip]


class IPInfoService:
    def __init__(
        self,
        provider: DataProvider,
        formatter: DataFormatter,
        storage: DataStorage,
        presenter: DataPresenter,
        checker: IPChecker,
        match_finder: MatchFinder
    ):
        self.provider = provider
        self.formatter = formatter
        self.storage = storage
        self.presenter = presenter
        self.checker = checker
        self.match_finder = match_finder

    def run(self) -> None:
        try:
            # Fetch and format data
            raw_data = self.provider.fetch_data()
            formatted_data = self.formatter.format(raw_data)
            current_ip = formatted_data["ip"]
            
            # Check for matches
            existing_ips = self.storage.get_all_ips()
            has_match = self.checker.check_ip(current_ip, existing_ips)
            
            # Display current data
            self.presenter.display(formatted_data)
            
            # Handle match result
            if has_match:
                matches = self.match_finder.find_matches(current_ip, self.storage)
                self.presenter.display_match_found(matches)
            else:
                self.presenter.display_no_match()
            
            # Save data regardless
            self.storage.save(formatted_data)
            
        except Exception as e:
            print(f"Error occurred: {e}")


def main():
    service = IPInfoService(
        provider=IPAPIProvider(),
        formatter=IPDataFormatter(),
        storage=CSVDataStorage(),
        presenter=TableDataPresenter(),
        checker=SimpleIPChecker(),
        match_finder=CSVMatchFinder()
    )
    service.run()


if __name__ == "__main__":
    main()