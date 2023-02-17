import logging
import json
import os
from abc import ABC, abstractmethod
from typing import Iterator

from tqdm import tqdm

from vuln_checker.model import VulnerabilityModel
from vuln_checker.util import scan_dir_recursively


class AdvisoryLoader(ABC):
    @abstractmethod
    def database_name(self) -> str:
        raise NotImplementedError

    def scan_database(self, database_path: str) -> Iterator[VulnerabilityModel]:
        for entry in scan_dir_recursively(os.path.join(database_path, self.database_name())):
            with open(entry.path) as f:
                data = json.load(f)
                yield self.to_unified_model(data)

    @abstractmethod
    def to_unified_model(self, model: dict) -> VulnerabilityModel:
        raise NotImplementedError


class GithubAdvisoryLoader(AdvisoryLoader):

    def database_name(self) -> str:
        return "ghsa"

    def to_unified_model(self, model: dict) -> VulnerabilityModel:
        advisory = model["Advisory"]
        aliases = {identifier["Value"] for identifier in advisory["Identifiers"]
                   if identifier is not None}

        return VulnerabilityModel(
            advisory["GhsaId"],
            advisory["Description"],
            advisory["Summary"],
            aliases,
            advisory["Severity"],
            advisory["CVSS"]["Score"],
            advisory["CVSS"]["VectorString"]
        )


class GitlabAdvisoryLoader(AdvisoryLoader):

    def database_name(self) -> str:
        return "glad"

    def to_unified_model(self, model: dict) -> VulnerabilityModel:
        # aliases = model["Identifiers"]
        return VulnerabilityModel(
            model["Identifier"],
            model["Description"],
            model["Title"],
            cvss_v3_vector=model["CvssV3"]
        )


class NvdLoader(AdvisoryLoader):

    def database_name(self) -> str:
        return "nvd"

    def to_unified_model(self, model: dict) -> VulnerabilityModel:
        description = [desc for desc in model["cve"]["description"]["description_data"] if desc["lang"] == "en"][0]
        cvss_v3_vector = None
        metric_v3 = model["impact"].get("baseMetricV3")
        if metric_v3 is not None:
            cvss_v3_vector = metric_v3["cvssV3"]["vectorString"]

        return VulnerabilityModel(
            model["cve"]["CVE_data_meta"]["ID"],
            description,
            cvss_v3_vector=cvss_v3_vector
        )


class OsvFormatBasedLoader(AdvisoryLoader, ABC):

    def to_unified_model(self, model: dict) -> VulnerabilityModel:
        return VulnerabilityModel(
            id=model["id"],
            aliases=model.get("aliases") or set(),
            description=model["details"]
        )


class OsvLoader(OsvFormatBasedLoader):

    def database_name(self) -> str:
        return "osv"


class GoLoader(OsvFormatBasedLoader):

    def database_name(self) -> str:
        return "go"


loaders = [
    GithubAdvisoryLoader(),
    GitlabAdvisoryLoader(),
    NvdLoader(),
    OsvLoader(),
    GoLoader()
]


def init_loaders() -> dict[str, AdvisoryLoader]:
    return {loader.database_name(): loader for loader in loaders}


def load_vulnerabilities(databases_path: str) -> tuple[str, Iterator[VulnerabilityModel]]:
    supported_databases = [loader.database_name() for loader in loaders]
    logging.info(f"Supported databases: {supported_databases}")

    for loader in loaders:
        logging.info(f"Scan {loader.database_name()}")
        for model in tqdm(loader.scan_database(databases_path)):
            yield loader.database_name(), model
