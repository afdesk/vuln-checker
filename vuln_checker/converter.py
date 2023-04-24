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
        case "MEDIUM":
            return "MODERATE"
        case "IMPORTANT":
            return "HIGH"
        case other:
            return other


def create_link_by_id(id: str) -> str:
    if id.startswith("GHSA"):
        return f"https://github.com/advisories/{id}"
    if id.startswith("GLSA"):
        return f"https://security.gentoo.org/glsa/{id}"
    if id.startswith("CVE"):
        return f"https://cve.mitre.org/cgi-bin/cvename.cgi?name={id}"
    if id.startswith("OSV"):
        return f"https://osv.dev/vulnerability/{id}"
    if id.startswith("GO"):
        return f"https://golang.org/issue/{id}"
    if id.startswith("RHSA"):
        return f"https://access.redhat.com/errata/{id}"
    if id.startswith("DSA"):
        return f"https://security-tracker.debian.org/tracker/{id}"
    if id.startswith("USN"):
        return f"https://ubuntu.com/security/notices/{id}"
    if id.startswith("ALAS"):
        return f"https://alas.aws.amazon.com/{id}"
    if id.startswith("MS"):
        return f"https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/{id}"
    if id.startswith("RUSTSEC"):
        return f"https://rustsec.org/advisories/{id}"
    return ""


class AdvisoryConverter(ABC):
    @abstractmethod
    def database_name(self) -> str:
        raise NotImplementedError

    def scan_database(self, databases_path: Path) -> Iterator[VulnerabilityModel]:
        database_path = databases_path / self.database_name()
        for p in database_path.rglob("*.json"):
            if p.is_dir():
                continue

            with p.open() as f:
                data = json.load(f)
                if not self.skip_advisory(data):
                    yield self.convert(data)

    def skip_advisory(self, model: dict) -> bool:
        return False

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
            id=advisory["GhsaId"],
            description=advisory["Description"],
            title=advisory["Summary"],
            source=self.database_name(),
            aliases=aliases,
            severity=normalize_severity(advisory.get("Severity")),
            cvss_v3_score=safe_str_to_float(advisory["CVSS"]["Score"]),
            cvss_v3_vector=advisory["CVSS"]["VectorString"],
            primary_link=create_link_by_id(advisory["GhsaId"])
        )

    def skip_advisory(self, model: dict) -> bool:
        return model["Advisory"].get("WithdrawnAt")


class GitlabAdvisoryConverter(AdvisoryConverter):

    def database_name(self) -> str:
        return "glad"

    def convert(self, model: dict) -> VulnerabilityModel:
        return VulnerabilityModel(
            id=model["identifier"],
            description=model["description"],
            title=model["title"],
            source=self.database_name(),
            cvss_v3_vector=model.get("cvss_v3"),
            aliases=set(model.get("identifiers", [])),
            primary_link=create_link_by_id(model["identifier"])
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

        identifier = model["cve"]["CVE_data_meta"]["ID"]

        return VulnerabilityModel(
            id=identifier,
            description=description,
            source=self.database_name(),
            cvss_v3_vector=cvss_v3_vector,
            primary_link=create_link_by_id(identifier)
        )


class OsvFormatBasedConverter(AdvisoryConverter, ABC):

    def convert(self, model: dict) -> VulnerabilityModel:
        return VulnerabilityModel(
            id=model["id"],
            aliases=set(model.get("aliases", [])),
            description=model["details"],
            source=self.database_name(),
            primary_link=create_link_by_id(model["id"])
        )


class OsvConverter(OsvFormatBasedConverter):

    def database_name(self) -> str:
        return "osv"


class GoConverter(OsvFormatBasedConverter):

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
            source=self.database_name(),
            severity=normalize_severity(model.get("threat_severity")),
            cvss_v3_score=safe_str_to_float(cvss3.get("cvss3_base_score")),
            cvss_v3_vector=cvss3.get("cvss3_scoring_vector"),
            primary_link=create_link_by_id(model["name"])
        )


converters = [
    GithubAdvisoryConverter(),
    GitlabAdvisoryConverter(),
    NvdConverter(),
    OsvConverter(),
    GoConverter(),
    RedhatAdvisoryConverter()
]


def convert_vulnerabilities(databases_path: Path) -> tuple[str, Iterator[VulnerabilityModel]]:
    supported_databases = [converter.database_name() for converter in converters]
    logging.info(f"Supported databases: {supported_databases}")

    for converter in converters:
        progress_description = f"Converting {converter.database_name()}"
        for model in tqdm(converter.scan_database(databases_path), desc=progress_description):
            yield converter.database_name(), model
