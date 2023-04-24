import logging

from github import Github, InputFileContent

from vuln_checker.gh.graphql import fetch_repository, update_discussion, create_discussion, get_discussion
from vuln_checker.model import Report
from vuln_checker.report import _diff_to_text, report_as_text


def export_report_to_github(
        github_repo: str,
        discussions_category_name: str,
        new_reports: list[Report],
        resolved_reports: list[Report]
):
    repo_id, category_id = _get_repo_and_category_id(github_repo, discussions_category_name)

    for report in new_reports:
        discussion_id = _create_new_discussion_with_report(report, category_id, repo_id, "[new]")
        if discussion_id is not None:
            report["discussion_id"] = discussion_id

    for report in resolved_reports:
        if not report.get("discussion_id"):
            logging.info("Creating new discussion for resolved report")
            _create_new_discussion_with_report(report, category_id, repo_id, "[fixed]")
        else:
            logging.info("Updating discussion for resolved report")
            _change_discussion_state_to_resolved(report)


def _get_repo_and_category_id(github_repo: str, discussions_category_name: str):
    repo_owner, repo_name = github_repo.split("/")
    repository = fetch_repository(repo_name=repo_name, repo_owner=repo_owner)
    categories = repository["discussionCategories"]["nodes"]
    repo_id = repository["id"]

    filter_category_by_name = lambda category: category["name"] == discussions_category_name
    category_id = next(filter(filter_category_by_name, categories), None)["id"]
    if category_id is None:
        raise Exception("Failed to find category id")
    return repo_id, category_id


def _change_discussion_state_to_resolved(report: Report):
    discussion_id = report["discussion_id"]

    discussion = get_discussion(discussion_id=discussion_id)

    if discussion["title"].startswith("[fixed]"):
        logging.info(f"Discussion with id {discussion_id} already resolved")
        return

    title = discussion["title"].replace("[new]", "[fixed]")

    discussion = update_discussion(
        discussion_id=discussion_id,
        title=title,
    )

    discussion_url = discussion["url"]
    logging.info(f"Discussion with id {discussion_id} resolved: {discussion_url}")


def _create_new_discussion_with_report(
        report: Report,
        category_id: str,
        repo_id: str,
        title_prefix: str
) -> str | None:
    if len(report["results"]) < 2:
        logging.info(f"Skipping diff with less than 2 groups: {report}")
        return None

    discussion_body = _diff_to_text(report)

    get_id_of_advisory = lambda num_group: report["results"][num_group]["advisories"][0]["id"]
    ger_source_of_advisory = lambda num_group: report["results"][num_group]["advisories"][0]["source"]

    title = title_prefix
    title += f" {get_id_of_advisory(0)}({ger_source_of_advisory(0)}) has a mismatch with "
    title += f"{get_id_of_advisory(1)}({ger_source_of_advisory(1)})"

    discussion = create_discussion(
        repo_id=repo_id,
        category_id=category_id,
        body=discussion_body,
        title=title,
    )

    discussion_url = discussion["url"]
    logging.info(f"Discussion created: {discussion_url}")

    return discussion["id"]


def create_initial_report_to_github(
        github_token: str,
        discussions_category_name: str,
        github_repo: str,
        gist_id: str,
        gist_filename: str,
        reports: list[Report]
):
    g = Github(github_token)

    txt_report = report_as_text(reports)

    try:
        gist = g.get_gist(gist_id)
        logging.info(f"Updating gist: {gist_id}")
        gist.edit(
            files={gist_filename: InputFileContent(txt_report)}
        )

    except Exception as e:
        logging.error(f"Failed to upload report to gist: {e}")
        return

    gist_url = gist.html_url
    logging.info(f"Text report: {gist_url}")

    repo_id, category_id = _get_repo_and_category_id(github_repo, discussions_category_name)

    discussion_body = f"Initial report: {gist_url}"

    discussion = create_discussion(
        repo_id=repo_id,
        category_id=category_id,
        body=discussion_body,
        title="Initial report"
    )

    discussion_url = discussion["url"]
    logging.info(f"Initial discussion created: {discussion_url}")


def update_gist(github_token: str, gist_filename: str, gist_id: str, txt_report: str):
    g = Github(github_token)
    gist = g.get_gist(gist_id)

    if not gist:
        logging.error("Failed to get gist")
        return

    try:
        gist.edit(files={gist_filename: InputFileContent(txt_report)})
    except Exception as e:
        logging.error(f"Failed to update gist: {e}")
        return
