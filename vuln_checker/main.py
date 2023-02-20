import json
import logging
import os
import shutil
from pathlib import Path

import yaml
from git import Repo, RemoteProgress
from tqdm import tqdm

from vuln_checker.load import load_vulnerabilities
from vuln_checker.util import create_dir

DEFAULT_DATABASES_PATH = os.path.join(os.getcwd(), "vuln-list")
VULNS_PATH = os.path.join(os.getcwd(), "vulnerabilities")

VULN_LIST_REPO = "https://github.com/aquasecurity/vuln-list.git"
GLAD_DATABASE_REPO = "https://gitlab.com/gitlab-org/security-products/gemnasium-db.git"


def set_to_list(obj):
    if isinstance(obj, set):
        return list(obj)
    raise TypeError


class Progress(RemoteProgress):
    def __init__(self):
        super().__init__()
        self.pbar = tqdm()

    def update(self, op_code, cur_count, max_count=None, message=''):
        self.pbar.total = max_count
        self.pbar.n = cur_count
        self.pbar.refresh()


def prepare_databases():
    if os.path.exists(DEFAULT_DATABASES_PATH):
        logging.info("The databases are already loaded")
        return

    logging.info("Clone `vuln_list` repo")
    Repo.clone_from(
        VULN_LIST_REPO,
        DEFAULT_DATABASES_PATH,
        progress=Progress(),
        single_branch=True,
        depth=1
    )

    glad_database_path = os.path.join(DEFAULT_DATABASES_PATH, "glad")

    logging.info("Remove `glad` database from `vuln_list`")
    if os.path.exists(glad_database_path):
        shutil.rmtree(glad_database_path)

    logging.info("Clone `GitLab Advisory Database` repo")
    Repo.clone_from(
        GLAD_DATABASE_REPO,
        glad_database_path,
        progress=Progress(),
        single_branch=True,
        depth=1
    )

    logging.info("Convert files .yml in .json in the `glad` database")
    glad_path = Path(glad_database_path)
    packages = ("conan", "gem", "go", "maven", "npm", "nuget", "packagist", "pypi")
    for directory in glad_path.iterdir():
        if directory.name not in packages:
            if directory.is_dir():
                shutil.rmtree(directory.absolute())
            else:
                directory.unlink()
            continue
        for p in tqdm((glad_path / directory).rglob("*.yml"), desc=f"Convert `{directory.name}` package"):
            json_file_name = str(p)[:-3] + "json"
            with open(str(p), "r") as yaml_file, open(json_file_name, "w") as json_file:
                advisory = yaml.safe_load(yaml_file)
                json.dump(advisory, json_file)
            p.unlink()


def main():
    logging.basicConfig(level=logging.INFO)

    prepare_databases()
    create_dir(VULNS_PATH)

    for database_name, model in load_vulnerabilities(DEFAULT_DATABASES_PATH):
        database_path = os.path.join(VULNS_PATH, database_name)
        create_dir(database_path)
        file_name = os.path.join(database_path, model.id + '.json')
        with open(file_name, 'w') as f:
            json.dump(model.__dict__, f, default=set_to_list)


if __name__ == "__main__":
    main()