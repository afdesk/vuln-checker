import json
import logging
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Iterator

from tqdm import tqdm

from vuln_checker.model import VulnerabilityModel


def safe_str_to_float(score: any):
    if not isinstance(score, str):
        return score
    try:
        return float(score)
    except ValueError:
        return score


class AdvisoryLoader(ABC):
    @abstractmethod
    def database_name(self) -> str:
        raise NotImplementedError

    def scan_database(self, databases_path: Path) -> Iterator[VulnerabilityModel]:
        database_path = databases_path / self.database_name()
        for p in database_path.rglob("*.json"):
            with open(p.absolute()) as f:
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
            advisory.get("Severity", "").upper(),
            safe_str_to_float(advisory["CVSS"]["Score"]),
            advisory["CVSS"]["VectorString"]
        )


class GitlabAdvisoryLoader(AdvisoryLoader):

    def database_name(self) -> str:
        return "glad"

    def to_unified_model(self, model: dict) -> VulnerabilityModel:
        return VulnerabilityModel(
            model["identifier"],
            model["description"],
            model["title"],
            cvss_v3_vector=model.get("cvss_v3"),
            aliases=set(model.get("identifiers", []))
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
            aliases=set(model.get("aliases", [])),
            description=model["details"]
        )


class OsvLoader(OsvFormatBasedLoader):

    def database_name(self) -> str:
        return "osv"


class GoLoader(OsvFormatBasedLoader):

    def database_name(self) -> str:
        return "go"


class RedhatAdvisoryLoader(AdvisoryLoader):
    def database_name(self) -> str:
        return "redhat"

    def to_unified_model(self, model: dict) -> VulnerabilityModel:
        cvss3 = model.get("cvss3", {})
        return VulnerabilityModel(
            id=model["name"],
            description=",".join(model["details"]),
            severity=model.get("threat_severity", "").upper(),
            cvss_v3_score=safe_str_to_float(cvss3.get("cvss3_base_score")),
            cvss_v3_vector=cvss3.get("cvss3_scoring_vector")
        )


loaders = [
    GithubAdvisoryLoader(),
    GitlabAdvisoryLoader(),
    NvdLoader(),
    OsvLoader(),
    GoLoader(),
    RedhatAdvisoryLoader()
]


def init_loaders() -> dict[str, AdvisoryLoader]:
    return {loader.database_name(): loader for loader in loaders}


def load_vulnerabilities(databases_path: Path) -> tuple[str, Iterator[VulnerabilityModel]]:
    supported_databases = [loader.database_name() for loader in loaders]
    logging.info(f"Supported databases: {supported_databases}")

    for loader in loaders:
        progress_description = f"Scan {loader.database_name()}"
        for model in tqdm(loader.scan_database(databases_path), desc=progress_description):
            yield loader.database_name(), model
