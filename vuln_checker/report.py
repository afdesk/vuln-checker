import logging
from pathlib import Path

from prettytable import PrettyTable

from vuln_checker.model import Report, Group


def _diff_to_text(diff: Report) -> str:
    """
    Create common text for all reporters.
    :param diff: The diff to create the text for.
    :return:
    """
    values = diff["results"]
    key = diff["key"]

    msg = ""
    count_groups = len(values)
    for i, value in enumerate(values):
        advisories = value["advisories"]
        for a in advisories:
            source = a["source"]
            msg += f"[{a['id']}]({a['primary_link']}) has `{key}`: `{a[key]}` in `{source}`\n\n"

        is_last = i == count_groups - 1
        if not is_last:
            msg += "but\n\n"

    return msg


def report_as_text(differences: list[Report]) -> str:
    message = ""
    for diff in differences:
        message += _diff_to_text(diff)
        message += "-" * 20 + "\n"
    return message


def export_report_to_text_file(differences: list[Report], path: Path):
    logging.info("Creating text report")
    path.write_text(report_as_text(differences))
    logging.info(f"Text report: {path.absolute()}")


class bcolors:
    OKCYAN = '\033[96m'
    ENDC = '\033[0m'


def print_report_as_table(reports: list[Report], title: str = "Report"):
    table = PrettyTable()
    table.field_names = ["ID", "Source", "Key", "Diff"]
    table.title = title

    for report in reports:
        groups: list[Group] = report["results"]
        key = report["key"]

        for i, group in enumerate(groups):
            advisories = group["advisories"]

            for j, advisory in enumerate(advisories):
                is_last_group = i == len(groups) - 1
                is_last_adv = j == len(advisories) - 1
                divider = is_last_group and is_last_adv
                d = str(advisory[key])
                d = bcolors.OKCYAN + d + bcolors.ENDC if d else ""
                source = advisory["source"]
                table.add_row([advisory["id"], source, key, d], divider=divider)

            is_last_group = i == len(groups) - 1
            if not is_last_group:
                table.add_row(["", "", "", ""])

    print(table)
