import json
import logging
import os

from vuln_checker.load import load_vulnerabilities
from vuln_checker.util import create_dir

DEFAULT_DATABASES_PATH = os.path.join(os.getcwd(), "vuln-list")
VULNS_PATH = os.path.join(os.getcwd(), "vulnerabilities")


def check_databases_folder(databases_path: str):
    exist = os.path.exists(databases_path)
    if not exist:
        raise NotADirectoryError


def set_to_list(obj):
    if isinstance(obj, set):
        return list(obj)
    raise TypeError


def main():
    logging.basicConfig(level=logging.INFO)

    check_databases_folder(DEFAULT_DATABASES_PATH)
    create_dir(VULNS_PATH)

    for database_name, model in load_vulnerabilities(DEFAULT_DATABASES_PATH):
        database_path = os.path.join(VULNS_PATH, database_name)
        create_dir(database_path)
        file_name = os.path.join(database_path, model.id + '.json')
        with open(file_name, 'w') as f:
            json.dump(model.__dict__, f, default=set_to_list)


if __name__ == "__main__":
    main()
