import json
import logging
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Iterator

from tqdm import tqdm

from vuln_checker.model import VulnerabilityModel


def safe_str_to_float(score: any):
    try:
        return float(score)
    except (ValueError, TypeError):
        return 0.0


def normalize_severity(severity: str):
    if not isinstance(severity, str):
        return "UNKNOWN"
    match severity.upper():
        case "MEDIUM": return "MODERATE"
        case "IMPORTANT": return "HIGH"
        case other: return other


class AdvisoryConverter(ABC):
    @abstractmethod
    def database_name(self) -> str:
        raise NotImplementedError

    def scan_database(self, databases_path: Path) -> Iterator[VulnerabilityModel]:
        database_path = databases_path / self.database_name()
        for p in database_path.rglob("*.json"):
            with open(p.absolute()) as f:
                data = json.load(f)
                yield self.convert(data)

    @abstractmethod
    def convert(self, model: dict) -> VulnerabilityModel:
        raise NotImplementedError


class GithubAdvisoryConverter(AdvisoryConverter):

    def database_name(self) -> str:
        return "ghsa"

    def convert(self, model: dict) -> VulnerabilityModel:
        advisory = model["Advisory"]
        aliases = {identifier["Value"] for identifier in advisory["Identifiers"]
                   if identifier is not None}

        return VulnerabilityModel(
            advisory["GhsaId"],
            advisory["Description"],
            advisory["Summary"],
            aliases,
            normalize_severity(advisory.get("Severity")),
            safe_str_to_float(advisory["CVSS"]["Score"]),
            advisory["CVSS"]["VectorString"]
        )


class GitlabAdvisoryConverter(AdvisoryConverter):

    def database_name(self) -> str:
        return "glad"

    def convert(self, model: dict) -> VulnerabilityModel:
        return VulnerabilityModel(
            model["identifier"],
            model["description"],
            model["title"],
            cvss_v3_vector=model.get("cvss_v3"),
            aliases=set(model.get("identifiers", []))
        )


class NvdConverter(AdvisoryConverter):

    def database_name(self) -> str:
        return "nvd"

    def convert(self, model: dict) -> VulnerabilityModel:
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


class OsvFormatBasedConverter(AdvisoryConverter, ABC):

    def convert(self, model: dict) -> VulnerabilityModel:
        return VulnerabilityModel(
            id=model["id"],
            aliases=set(model.get("aliases", [])),
            description=model["details"]
        )


class OsvLoader(OsvFormatBasedConverter):

    def database_name(self) -> str:
        return "osv"


class GoLoader(OsvFormatBasedConverter):

    def database_name(self) -> str:
        return "go"


class RedhatAdvisoryConverter(AdvisoryConverter):
    def database_name(self) -> str:
        return "redhat"

    def convert(self, model: dict) -> VulnerabilityModel:
        cvss3 = model.get("cvss3", {})
        return VulnerabilityModel(
            id=model["name"],
            description=",".join(model["details"]),
            severity=normalize_severity(model.get("threat_severity")),
            cvss_v3_score=safe_str_to_float(cvss3.get("cvss3_base_score")),
            cvss_v3_vector=cvss3.get("cvss3_scoring_vector")
        )


converters = [
    GithubAdvisoryConverter(),
    GitlabAdvisoryConverter(),
    NvdConverter(),
    OsvLoader(),
    GoLoader(),
    RedhatAdvisoryConverter()
]


def convert_vulnerabilities(databases_path: Path) -> tuple[str, Iterator[VulnerabilityModel]]:
    supported_databases = [converter.database_name() for converter in converters]
    logging.info(f"Supported databases: {supported_databases}")

    for converter in converters:
        progress_description = f"Converting {converter.database_name()}"
        for model in tqdm(converter.scan_database(databases_path), desc=progress_description):
            yield converter.database_name(), model
