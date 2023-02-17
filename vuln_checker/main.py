import logging
import os


from vuln_checker.load import load_vulnerabilities

DEFAULT_DATABASES_PATH = os.path.join(os.getcwd(), "vuln-list")


def check_databases_folder(databases_path: str):
    exist = os.path.exists(databases_path)
    if not exist:
        raise NotADirectoryError()


def main():
    logging.basicConfig(level=logging.INFO)

    check_databases_folder(DEFAULT_DATABASES_PATH)

    models = load_vulnerabilities(DEFAULT_DATABASES_PATH)


if __name__ == "__main__":
    main()
