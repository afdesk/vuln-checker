import itertools
import json
import logging
from collections import defaultdict
from operator import itemgetter
from pathlib import Path
from typing import Iterable, TypedDict, Literal

import networkx as nx

from vuln_checker.config import FileConfig
from vuln_checker.converter import convert_vulnerabilities
from vuln_checker.load import prepare_databases


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


def create_map_of_vulnerabilities(databases_path: Path, vulnerabilities_path: Path) -> VulnMap:
    vulns: VulnMap = {}

    for database_name, model in convert_vulnerabilities(databases_path):
        database_path = vulnerabilities_path / database_name
        database_path.mkdir(exist_ok=True)
        vulnerability_file = database_path / (model.id + '.json')
        with vulnerability_file.open('w') as f:
            json.dump(model.__dict__, f, default=set_to_list, indent=2)

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


def dump_vulns(vulnerabilities: VulnMap, vulnerabilities_path: Path):
    with (vulnerabilities_path / "combined.json").open("w") as f:
        json.dump(vulnerabilities, f, default=set_to_list, indent=2)


Advisory = TypedDict(
    'Advisory', {
        'source': str,
        'id': str,
        'severity': str | None,
        'cvss_v3_vector': str | None,
        'cvss_v3_score': float | None
    }
)

GroupedAdvisories = dict[str, list[Advisory]]
DifferentAdvisories = TypedDict(
    'DifferentAdvisories', {'severity': list[GroupedAdvisories]}
)

KeyForCheck = Literal['severity', 'cvss_v3_vector', 'cvss_v3_score']


def compare_advisory_by_field_name(advisories: Iterable[Advisory], field_name: KeyForCheck) -> GroupedAdvisories:
    key = itemgetter(field_name)
    advisories = [advisory for advisory in advisories if advisory[field_name]]

    sorted_advisories = sorted(advisories, key=key)
    grouped = itertools.groupby(sorted_advisories, key)
    return {k: list(g) for (k, g) in grouped}


def advisory_to_short_info(advisory: Advisory) -> str:
    source = advisory["source"].split("/")
    identifier = source[-1][:-5]
    database = source[-2]
    return f"{identifier} in {database}"


keys_for_check: tuple[Literal['severity']] = (
    "severity",
)


def find_different_advisories(vulns: VulnMap) -> DifferentAdvisories:
    different_advisories = defaultdict(list)

    for vuln in vulns.values():
        # there is nothing to compare
        if not vuln["aliases"]:
            continue

        advisories: list[Advisory] = []
        for source in vuln["sources"]:
            with open(source, "r") as f:
                advisories += [json.load(f) | {"source": source}]

        for key in keys_for_check:
            different = compare_advisory_by_field_name(advisories, key)
            if len(different) > 1:
                different_advisories[key].append(different)

    return different_advisories


def report_to_file(advisories: DifferentAdvisories, vulnerabilities_path: Path):
    message = ""
    for k, groups in advisories.items():
        for group in groups:
            for key, advisories in group.items():
                message += f"{k}: {key}\n"
                message += "\t" + "\n\t".join(advisory_to_short_info(adv) for adv in advisories) + "\n"
            message += "-" * 20 + "\n"

    (vulnerabilities_path / "report.txt").write_text(message)


def main():
    logging.basicConfig(level=logging.INFO)

    prepare_databases(FileConfig.DEFAULT_DATABASES_PATH)
    FileConfig.VULNERABILITIES_PATH.mkdir(exist_ok=True)

    vulnerabilities = create_map_of_vulnerabilities(
        FileConfig.DEFAULT_DATABASES_PATH,
        FileConfig.VULNERABILITIES_PATH
    )

    combined_vulnerabilities = combine_vulnerabilities(vulnerabilities)
    dump_vulns(combined_vulnerabilities, FileConfig.VULNERABILITIES_PATH)

    advisories = find_different_advisories(combined_vulnerabilities)

    report_to_file(advisories, FileConfig.VULNERABILITIES_PATH)


if __name__ == "__main__":
    main()
