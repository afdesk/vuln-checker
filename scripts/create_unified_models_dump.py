import os
import pickle

from vuln_checker.load import load_vulnerabilities

DATABASES_PATH = os.path.join(os.getcwd(), "..", "vuln-list")
DUMP_PATH = "../dumps"


def main():
    if not os.path.exists(DUMP_PATH):
        os.makedirs(DUMP_PATH)

    models = load_vulnerabilities(DATABASES_PATH)
    with open(os.path.join(DUMP_PATH, "models.pkl"), 'wb') as f:
        pickle.dump(models, f, pickle.HIGHEST_PROTOCOL)


if __name__ == "__main__":
    main()
