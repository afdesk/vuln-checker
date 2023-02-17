import argparse
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
    parser = argparse.ArgumentParser(description='Compare')
    parser.add_argument(
        '-d',
        '--databases',
        nargs='*',
        help='Databases to compare',
        type=str,
        default=[]
    )
    parser.add_argument(
        '--databases-path',
        help='Path to databases',
        type=str,
        default=DEFAULT_DATABASES_PATH
    )

    args = parser.parse_args()

    check_databases_folder(args.databases_path)

    models = load_vulnerabilities(args.databases_path, args.databases)


if __name__ == "__main__":
    main()
