import itertools
import json
import logging
import os
import shutil
from pathlib import Path
from typing import Iterable, TypedDict

import networkx as nx
import yaml
from git import Repo, RemoteProgress
from tqdm import tqdm

from vuln_checker.load import load_vulnerabilities

DEFAULT_DATABASES_PATH = Path.cwd() / "vuln-list"
VULNS_PATH = Path.cwd() / "vulnerabilities"

VULN_LIST_REPO = "https://github.com/aquasecurity/vuln-list.git"
GLAD_DATABASE_REPO = "https://gitlab.com/gitlab-org/security-products/gemnasium-db.git"

def check_databases_folder(databases_path: Path):
    if not databases_path.exists():
        raise NotADirectoryError


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


priorities = frozenset([
    "CVE",
    "GHSA"
])

VulnInfo = TypedDict('VulnInfo', {'aliases': set[str], 'sources': set[str]})
VulnMap = dict[str, VulnInfo]


def key_by_priority(keys: Iterable[str], default) -> tuple[str, set[str]]:
    def find_identifier_by_prefix(k) -> str | None:
        filtered = list(filter(lambda x: x.startswith(k), keys))
        if len(filtered) > 0:
            return filtered[0]
        return None

    key = list(map(find_identifier_by_prefix, priorities))[0]
    if key is None:
        key = default
    aliases = set(keys) - {key}
    return key, aliases


def create_map_of_vulnerabilities() -> VulnMap:
    vulns: VulnMap = {}

    for database_name, model in load_vulnerabilities(DEFAULT_DATABASES_PATH):
        database_path = VULNS_PATH / database_name
        database_path.mkdir(exist_ok=True)
        vulnerability_file = database_path / (model.id + '.json')
        with vulnerability_file.open('w') as f:
            json.dump(model.__dict__, f, default=set_to_list)

        vulnerability = vulns.get(model.id, {})
        aliases = vulnerability.get("aliases", set()) | model.aliases
        aliases.discard(model.id)
        sources = vulnerability.get("sources", set()) | {str(vulnerability_file)}

        vulns[model.id] = {
            "aliases": aliases,
            "sources": sources
        }

    return vulns


def init_graph_of_vulnerabilities(vulnerabilities: VulnMap):
    graph = nx.Graph()

    for k, v in vulnerabilities.items():
        graph.add_node(k, sources=v["sources"])
        aliases = v['aliases']
        edges = zip(aliases, itertools.repeat(k))
        graph.add_edges_from(edges)

    return graph


def traverse_graph_and_combine_vulnerabilities(graph: nx.Graph) -> VulnMap:
    combined_vulnerabilities: VulnMap = {}
    visited = set()
    for node, data in graph.nodes(data=True):
        if node in visited:
            continue
        all_related_nodes = set(nx.bfs_tree(graph, node))
        sources = data.get("sources", set())
        for n in all_related_nodes - {node}:
            sources |= graph.nodes[n].get("sources", set())

        visited |= all_related_nodes
        key, new_aliases = key_by_priority(all_related_nodes, node)
        combined_vulnerabilities[key] = {
            "aliases": new_aliases,
            "sources": sources
        }

    return combined_vulnerabilities


def combine_vulnerabilities(vulns: VulnMap) -> VulnMap:
    graph = init_graph_of_vulnerabilities(vulns)
    return traverse_graph_and_combine_vulnerabilities(graph)


def main():
    logging.basicConfig(level=logging.INFO)

    prepare_databases()
    VULNS_PATH.mkdir(exist_ok=True)

    vulnerabilities = create_map_of_vulnerabilities()
    combined_vulnerabilities = combine_vulnerabilities(vulnerabilities)


if __name__ == "__main__":
    main()
