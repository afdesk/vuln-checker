from pathlib import Path


class FileConfig:
    DEFAULT_DATABASES_PATH = Path.cwd() / "vuln-list"
    VULNERABILITIES_PATH = Path.cwd() / "vulnerabilities"
    GROUPED_ADVISORIES_DB_PATH = Path.cwd() / "database"
    HASHED_REPORTS_PATH = VULNERABILITIES_PATH / "dump.csv"
    TEXT_REPORT_PATH = Path.cwd() / "report.txt"
    COMBINED_VULNS_PATH = VULNERABILITIES_PATH / "combined.json"