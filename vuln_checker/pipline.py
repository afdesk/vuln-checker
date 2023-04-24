import itertools
import json
import logging
from collections import OrderedDict
from operator import itemgetter
from pathlib import Path
from typing import TypedDict, Iterable

import networkx as nx

from vuln_checker.converter import convert_vulnerabilities
from vuln_checker.model import Advisory, KeyForCheck, GroupedAdvisories, Report

VulnerabilityInfo = TypedDict('VulnerabilityInfo', {'aliases': set[str], 'files': set[str]})
Vulnerabilities = dict[str, VulnerabilityInfo]


def set_to_list(obj):
    if isinstance(obj, set):
        return list(obj)
    raise TypeError


priorities = OrderedDict([
    (0, "CVE-"),
    (1, "GHSA-"),
    (2, "GO-"),
])


def key_by_priority(keys: Iterable[str], default) -> tuple[str, set[str]]:
    """
    Extracts the key with the highest priority from the list of keys.
    :param keys: list of identifiers (e.g. CVE-2020-1234, GHSA-1234)
    :param default: default value if no key is found
    :return: tuple of the key with the highest priority and the set of aliases

    Example:

    >>> key_by_priority(["CVE-2020-1234", "CVE-2020-5678"], "default")
    ('CVE-2020-1234', {'CVE-2020-5678'})
    >>> key_by_priority(["CVE-2020-1234", "GHSA-1234"], "default")
    ('CVE-2020-1234', {'GHSA-1234'})
    >>> key_by_priority(["GHSA-1234"], "GO-2022-0701")
    ('GHSA-1234', set())
    >>> key_by_priority(["GO-2022-0706", "GO-2022-0701"], "GO-2022-0701")
    ('GO-2022-0701', {'GO-2022-0706'})

    """

    for p in priorities.values():
        for k in sorted(keys):
            if k.startswith(p):
                return k, set(keys) - {k}
    return default, set(keys) - {default}


def create_map_of_vulnerabilities(databases_path: Path, vulnerabilities_path: Path) -> Vulnerabilities:
    """
    Creates a map of vulnerabilities from the databases and saves them to the vulnerabilities' folder.
    :param databases_path: path to the databases
    :param vulnerabilities_path: path to the vulnerabilities' folder
    :return: map of vulnerabilities

    """

    vulns: Vulnerabilities = {}

    for database_name, model in convert_vulnerabilities(databases_path):
        database_path = vulnerabilities_path / database_name
        database_path.mkdir(exist_ok=True)
        vulnerability_file = database_path / (model.id + '.json')
        with vulnerability_file.open('w') as f:
            json.dump(model.__dict__, f, default=set_to_list, indent=2)

        vulnerability = vulns.get(model.id, {})
        aliases = vulnerability.get("aliases", set()) | model.aliases
        aliases.discard(model.id)
        files = vulnerability.get("files", set()) | {str(vulnerability_file)}

        vulns[model.id] = {
            "aliases": aliases,
            "files": files
        }

    return vulns


def init_graph_of_vulnerabilities(vulnerabilities: Vulnerabilities):
    """
    Creates a graph of vulnerabilities from the map of vulnerabilities.

    :param vulnerabilities: map of vulnerabilities
    :return: graph of vulnerabilities

    Example:

    >>> g = init_graph_of_vulnerabilities({
    ...     "CVE-2020-1234": {
    ...         "aliases": {"CVE-2020-5678"},
    ...         'files': {"/vulnerabilities/go/1234.json"},
    ...     },
    ...     "CVE-2020-5678": {
    ...         "aliases": {"CVE-2020-1234"},
    ...         'files': {"/vulnerabilities/go/5678.json"},
    ...     },
    ... })

    >>> list(g.nodes(data=True))
    [('CVE-2020-1234', {'files': {'/vulnerabilities/go/1234.json'}}), ('CVE-2020-5678', {'files': {'/vulnerabilities/go/5678.json'}})]
    >>> list(g.edges)
    [('CVE-2020-1234', 'CVE-2020-5678')]

    """
    graph = nx.Graph()

    for k, v in vulnerabilities.items():
        graph.add_node(k, files=v['files'])
        aliases = v['aliases']
        edges = zip(aliases, itertools.repeat(k))
        graph.add_edges_from(edges)

    return graph


def traverse_graph_and_combine_vulnerabilities(graph: nx.Graph) -> Vulnerabilities:
    """
    Traverses the graph of vulnerabilities and combines vulnerabilities.
    :param graph: graph of vulnerabilities
    :return: map of vulnerabilities

    Example:

    >>> g = init_graph_of_vulnerabilities({
    ...     "CVE-2020-1234": {
    ...         "aliases": {"CVE-2020-5678"},
    ...         'files': {"/vulnerabilities/go/1234.json"},
    ...     },
    ...     "CVE-2020-5678": {
    ...         "aliases": {"CVE-2020-1234"},
    ...         'files': {"/vulnerabilities/go/5678.json"},
    ...     },
    ... })

    >>> traverse_graph_and_combine_vulnerabilities(g)
    {'CVE-2020-1234': {'aliases': {'CVE-2020-5678'}, 'files': {'/vulnerabilities/go/5678.json', '/vulnerabilities/go/1234.json'}}}

    """
    combined_vulnerabilities: Vulnerabilities = {}
    visited = set()
    for node, data in graph.nodes(data=True):
        if node in visited:
            continue
        all_related_nodes = set(nx.bfs_tree(graph, node))
        files = data.get('files', set())
        for n in all_related_nodes - {node}:
            files |= graph.nodes[n].get('files', set())

        visited |= all_related_nodes
        key, new_aliases = key_by_priority(all_related_nodes, node)
        combined_vulnerabilities[key] = {
            "aliases": new_aliases,
            'files': files
        }

    return combined_vulnerabilities


def combine_vulnerabilities(vulns: Vulnerabilities) -> Vulnerabilities:
    """
    Combines vulnerabilities from the map of vulnerabilities.

    :param vulns: map of vulnerabilities
    :return: map of vulnerabilities with combined vulnerabilities

    Example:

    >>> combine_vulnerabilities({
    ...     "CVE-2020-1234": {
    ...         "aliases": {"CVE-2020-5678"},
    ...         'files': {"/vulnerabilities/go/1234.json"},
    ...     },
    ...     "CVE-2020-5678": {
    ...         "aliases": {"CVE-2020-1234"},
    ...         'files': {"/vulnerabilities/go/5678.json"},
    ...     },
    ... })
    {
        "CVE-2020-1234": {
            "aliases": {"CVE-2020-5678"},
            'files': {"/vulnerabilities/go/1234.json", "/vulnerabilities/go/5678.json"},
        },
    }

    """
    graph = init_graph_of_vulnerabilities(vulns)
    return traverse_graph_and_combine_vulnerabilities(graph)


def compare_advisory_by_field_name(
        advisories: Iterable[Advisory],
        field_name: KeyForCheck
) -> GroupedAdvisories:
    key = itemgetter(field_name)
    advisories = [advisory for advisory in advisories if advisory.get(field_name)]

    sorted_advisories = sorted(advisories, key=key)
    grouped = itertools.groupby(sorted_advisories, key)
    return {k: list(g) for (k, g) in grouped}


keys_for_check: tuple = ("severity", "cvss_v3_vector", "cvss_v3_score")


def load_combined_vulnerabilities(file: Path) -> Vulnerabilities:
    logging.info("Loading combined vulnerabilities from a file.")
    if not file.exists():
        raise FileNotFoundError(f"The combined vulnerabilities file {file} does not exist.")
    with file.open("r") as f:
        combined_vulnerabilities = json.load(f)
        if not isinstance(combined_vulnerabilities, dict):
            raise TypeError(f"The combined vulnerabilities file {file} is not a dictionary.")
    return combined_vulnerabilities


def create_and_dump_combined_vulnerabilities(
        vulnerabilities: Vulnerabilities,
        file: Path
) -> Vulnerabilities:
    logging.info("Converting the databases to a map.")
    combined_vulnerabilities = combine_vulnerabilities(vulnerabilities)

    logging.info("Dumping combined vulnerabilities to a file.")
    with file.open("w") as f:
        json.dump(combined_vulnerabilities, f, default=set_to_list, indent=2)

    return combined_vulnerabilities


def find_different_advisories(vulns: Vulnerabilities) -> list[Report]:
    """
    Finds different advisories.
    :param vulns: The vulnerabilities.
    :return: The different advisories.
    """

    different_advisories = []

    for vuln in vulns.values():
        # there is nothing to compare
        if not vuln["aliases"]:
            continue

        advisories: list[Advisory] = []
        for source in vuln['files']:
            with open(source, "r") as f:
                advisories += [json.load(f) | {"filepath": source}]

        for key in keys_for_check:
            different = compare_advisory_by_field_name(advisories, key)
            if len(different) > 1:
                different_advisories.append({
                    "results": [
                        {
                            "advisories": advisories,
                            "value": k,
                        } for k, advisories in different.items()
                    ],
                    "key": key,
                    "discussion_id": ""
                })

    return different_advisories


def analyze(
        databases_path: Path,
        vulnerabilities_path: Path,
        combined_file: Path,
        skip_dump: bool
) -> list[Report]:
    if not skip_dump:
        vulnerabilities = create_map_of_vulnerabilities(databases_path, vulnerabilities_path)
        combined_vulnerabilities = create_and_dump_combined_vulnerabilities(vulnerabilities, combined_file)
    else:
        combined_vulnerabilities = load_combined_vulnerabilities(combined_file)

    return find_different_advisories(combined_vulnerabilities)
