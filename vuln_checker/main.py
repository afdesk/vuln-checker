import itertools
import json
import logging
import os
from pathlib import Path
from typing import Iterable, TypedDict

import networkx as nx
from networkx import Graph

from vuln_checker.load import load_vulnerabilities

DEFAULT_DATABASES_PATH = Path.cwd() / "vuln-list"
VULNS_PATH = Path.cwd() / "vulnerabilities"


def check_databases_folder(databases_path: Path):
    if not databases_path.exists():
        raise NotADirectoryError


def set_to_list(obj):
    if isinstance(obj, set):
        return list(obj)
    raise TypeError


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
        file_name = os.path.join(database_path, model.id + '.json')
        with open(file_name, 'w') as f:
            json.dump(model.__dict__, f, default=set_to_list)

        vulnerability = vulns.get(model.id, {})
        aliases = vulnerability.get("aliases", set()) | model.aliases
        aliases.discard(model.id)
        sources = vulnerability.get("sources", set()) | {file_name}

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


def traverse_graph_and_combine_vulnerabilities(graph: Graph) -> VulnMap:
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

    check_databases_folder(DEFAULT_DATABASES_PATH)
    VULNS_PATH.mkdir(exist_ok=True)

    vulnerabilities = create_map_of_vulnerabilities()
    combined_vulnerabilities = combine_vulnerabilities(vulnerabilities)


if __name__ == "__main__":
    main()
