import argparse
import csv
import json
import logging
import sys
from abc import ABC, abstractmethod
from pathlib import Path

from vuln_checker.config import FileConfig, GithubConfig
from vuln_checker.gh.report import export_report_to_github, create_initial_report_to_github, update_gist
from vuln_checker.load import prepare_databases
from vuln_checker.model import hash_report, Report, HashedReports
from vuln_checker.pipline import analyze
from vuln_checker.report import print_report_as_table, export_report_to_text_file, report_as_text

logging.basicConfig(
    format="%(asctime)s %(levelname)s %(message)s",
    level=logging.INFO,
    stream=sys.stdout,
)


class HashedReportsPersister(ABC):
    @abstractmethod
    def dump(self, advisories: HashedReports): pass

    @abstractmethod
    def load(self) -> HashedReports: pass


class HashedReportsCsvPersister(HashedReportsPersister):
    def __init__(self, file: Path):
        self.file = file

    def dump(self, advisories: HashedReports):
        with self.file.open("w") as f:
            writer = csv.writer(f, delimiter=',', quotechar='|', quoting=csv.QUOTE_MINIMAL)
            writer.writerow(["hash", "payload"])
            for _hash, k in advisories.items():
                writer.writerow([_hash, json.dumps(k)])

    def load(self) -> HashedReports:
        with self.file.open("r") as f:
            reader = csv.reader(f, delimiter=',', quotechar='|')
            next(reader)  # skip header
            return {int(_hash): json.loads(payload) for _hash, payload in reader}


def init_cli() -> argparse.ArgumentParser:
    example = """Examples:
    
    # Analyze advisories and export report to github
    ❯ poetry run vuln-checker --export-type "github"

    # Example for development, skip updating and converting advisories, report only
    ❯ poetry run vuln-checker --skip-update --skip-convert --skip-init --export-type "github,table"
    
    """
    parser = argparse.ArgumentParser(
        epilog=example,
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        "--skip-convert", action="store_true",
        help="Skip convert and dump advisories", default=False
    )
    parser.add_argument(
        "--skip-update", action="store_true",
        help="Skip updating the databases.", default=False
    )
    parser.add_argument(
        "--export-type", action="store",
        help="Export type, comma separated. Available: table, text, github", default="table"
    )
    parser.add_argument(
        "--skip-init", action="store_true",
        help="Skip initializing the github report.", default=False
    )

    return parser


def main():
    parser = init_cli()
    args = parser.parse_args()

    FileConfig.VULNS_PATH.mkdir(exist_ok=True)

    if args.skip_update:
        logging.info("Skipping the update of the databases.")
    else:
        logging.info("Updating the databases.")
        prepare_databases(FileConfig.DEFAULT_DATABASES_PATH)

    if not FileConfig.DEFAULT_DATABASES_PATH.exists():
        raise FileNotFoundError(
            f"The databases {FileConfig.DEFAULT_DATABASES_PATH} are not present. "
            f"Please run the script without --skip-update."
        )

    differences = analyze(
        FileConfig.DEFAULT_DATABASES_PATH,
        FileConfig.VULNS_PATH,
        FileConfig.COMBINED_VULNS_PATH,
        args.skip_dump
    )

    logging.info("Total count of different advisories: " + str(len(differences)))

    reports: HashedReports = {
        hash_report(a): a for a in differences
    }

    hashed_reports_persister = HashedReportsCsvPersister(FileConfig.HASHED_REPORTS_PATH)

    if not FileConfig.HASHED_REPORTS_PATH.exists():
        FileConfig.HASHED_REPORTS_PATH.touch()
        logging.info("Dumping differences advisories to a file.")
        hashed_reports_persister.dump(reports)

        if args.skip_init:
            logging.info("Skipping the initial report to GitHub.")
            return

        logging.info("Creating initial report to GitHub.")
        create_initial_report_to_github(
            GithubConfig.GITHUB_TOKEN,
            GithubConfig.GITHUB_DISCUSSIONS_CATEGORY_NAME,
            GithubConfig.GITHUB_REPO,
            GithubConfig.GITHUB_GIST_ID,
            GithubConfig.GITHUB_GIST_FILENAME,
            reports.values()
        )
        logging.info("Initial report to GitHub created.")
        return

    else:
        logging.info("Loading differences advisories from a file.")
        cached_reports = hashed_reports_persister.load()

    import random
    for _ in range(1):

        random_hash = random.choice(list(cached_reports.keys()))
        del cached_reports[random_hash]

        random_hash = random.choice(list(reports.keys()))
        del reports[random_hash]

    new_reports, resolved_reports, not_resolved_reports = get_reports(cached_reports, reports)

    count_of_new_differences = len(new_reports)
    count_of_resolved_differences = len(resolved_reports)

    logging.info(f"Count of new differences: {count_of_new_differences}")
    logging.info(f"Count of resolved differences: {count_of_resolved_differences}")

    if count_of_new_differences == 0 and count_of_resolved_differences == 0:
        logging.info("No new or resolved advisories.")
        return

    export_type = args.export_type.split(",")

    for export_type in export_type:
        match export_type:
            case "table":
                if count_of_new_differences > 0:
                    print_report_as_table(new_reports, title="New reports")
                if count_of_resolved_differences > 0:
                    print_report_as_table(resolved_reports, title="Resolved reports")
            case "text":
                export_report_to_text_file(new_reports, FileConfig.TEXT_REPORT_PATH)
            case "github":
                logging.info("Exporting new reports to GitHub.")

                export_report_to_github(
                    GithubConfig.GITHUB_REPO,
                    GithubConfig.GITHUB_DISCUSSIONS_CATEGORY_NAME,
                    new_reports, resolved_reports
                )

                reports = {
                    **{hash_report(a): a for a in new_reports},
                    **{hash_report(a): a for a in not_resolved_reports}
                }

                text_report = report_as_text(reports.values())

                logging.info("Updating gist with all reports.")
                update_gist(
                    GithubConfig.GITHUB_TOKEN,
                    GithubConfig.GITHUB_GIST_FILENAME,
                    GithubConfig.GITHUB_GIST_ID,
                    text_report
                )

                hashed_reports_persister.dump(reports)
            case _:
                raise Exception(f"Unknown export type: {export_type}")

    logging.info("Done.")


def get_reports(
        cached_reports: HashedReports,
        reports: HashedReports
) -> tuple[list[Report], list[Report], list[Report]]:
    new_hashes = set(reports.keys()) - set(cached_reports.keys())
    old_hashes = set(cached_reports.keys()) - set(reports.keys())

    new_advisories = [v for k, v in reports.items() if k in new_hashes]
    resolved_advisories = [v for k, v in cached_reports.items() if k in old_hashes]
    not_resolved_advisories = [v for k, v in cached_reports.items() if k not in old_hashes]

    return new_advisories, resolved_advisories, not_resolved_advisories


if __name__ == "__main__":
    main()
