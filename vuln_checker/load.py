import json
import logging
import os
import shutil
from pathlib import Path

import yaml
from git import Repo, RemoteProgress
from tqdm import tqdm

VULN_LIST_REPO = "https://github.com/aquasecurity/vuln-list.git"
GLAD_DATABASE_REPO = "https://gitlab.com/gitlab-org/security-products/gemnasium-db.git"


class Progress(RemoteProgress):
    def __init__(self):
        super().__init__()
        self.pbar = tqdm()

    def update(self, op_code, cur_count, max_count=None, message=''):
        self.pbar.total = max_count
        self.pbar.n = cur_count
        self.pbar.refresh()


def prepare_databases(path: Path):
    if os.path.exists(path):
        logging.info("The databases are already loaded")
        return

    logging.info("Clone `vuln_list` repo")
    Repo.clone_from(
        VULN_LIST_REPO,
        path,
        progress=Progress(),
        single_branch=True,
        depth=1
    )

    glad_database_path = path / "glad"

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

    convert_yml_to_json(glad_database_path)


def convert_yml_to_json(path: Path):
    logging.info("Convert files .yml in .json in the `glad` database")
    glad_path = Path(path)
    packages = ("conan", "gem", "go", "maven", "npm", "nuget", "packagist", "pypi")
    for directory in glad_path.iterdir():
        if directory.name not in packages:
            if directory.is_dir():
                shutil.rmtree(directory.absolute())
            else:
                directory.unlink()
            continue
        desc = f"Convert `{directory.name}` package"
        for p in tqdm((glad_path / directory).rglob("*.yml"), desc=desc):
            json_advisory = p.with_suffix(".json")
            with p.open("r") as yaml_file, json_advisory.open("w") as json_file:
                advisory = yaml.safe_load(yaml_file)
                json.dump(advisory, json_file)
            p.unlink()
