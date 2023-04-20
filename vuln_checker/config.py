import os
from pathlib import Path

from dotenv import load_dotenv
from github import Github

load_dotenv()


def get_env_or_raise(name: str) -> str:
    value = os.getenv(name)
    if value is None:
        raise ValueError(f"The environment variable {name} is not set")
    return value


class FileConfig:
    DEFAULT_DATABASES_PATH = Path.cwd() / "vuln-list"
    VULNS_PATH = Path.cwd() / "vulnerabilities"
    GROUPED_ADVISORIES_DB_PATH = Path.cwd() / "database"
    HASHED_REPORTS_PATH = VULNS_PATH / "dump.csv"
    TEXT_REPORT_PATH = Path.cwd() / "report.txt"
    COMBINED_VULNS_PATH = VULNS_PATH / "combined.json"


class GithubConfig:
    GITHUB_TOKEN = get_env_or_raise("GITHUB_TOKEN")
    GITHUB_REPO = get_env_or_raise("GITHUB_REPOSITORY")
    GITHUB_AUTH_HEADER = f"Bearer {GITHUB_TOKEN}"
    GITHUB_GRAPHQL_API = "https://api.github.com/graphql"
    GITHUB_DISCUSSIONS_CATEGORY_NAME = get_env_or_raise("GITHUB_DISCUSSIONS_CATEGORY_NAME")
    GITHUB_GIST_ID = get_env_or_raise("GITHUB_GIST_ID")
    GITHUB_GIST_FILENAME = get_env_or_raise("GITHUB_GIST_FILENAME")

    if "/" not in GITHUB_REPO:
        raise ValueError("GITHUB_REPOSITORY must be in the format owner/repo")

    GITHUB_REPO_OWNER, GITHUB_REPO_NAME = GITHUB_REPO.split("/")

    g = Github(GITHUB_TOKEN)
    gist = g.get_gist(GITHUB_GIST_ID)
    if gist is None:
        raise ValueError("Github Gist does not exist, please create one")
