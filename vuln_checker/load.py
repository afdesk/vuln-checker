import logging
import json
import os
from abc import ABC, abstractmethod
from typing import Iterator, Dict, TypeAlias

from tqdm import tqdm

from vuln_checker.model import Package, SeverityItem, UnifiedVulnerabilityModel
from vuln_checker.util import scan_dir_recursively, create_purl

Severity: TypeAlias = list[SeverityItem]


class AdvisoryLoader(ABC):
    @abstractmethod
    def database_name(self) -> str:
        raise NotImplementedError()

    @abstractmethod
    def create_package(self, model: dict) -> Package:
        raise NotImplementedError()

    @abstractmethod
    def extract_identifier(self, model: dict) -> str:
        raise NotImplementedError()

    @abstractmethod
    def extract_severity(self, model: dict) -> Severity:
        raise NotImplementedError()

    def scan_database(self, database_path: str) -> Iterator[UnifiedVulnerabilityModel]:
        for entry in scan_dir_recursively(os.path.join(database_path, self.database_name())):
            with open(entry.path) as f:
                data = json.load(f)
                yield self.to_unified_model(data)

    def to_unified_model(self, model: dict) -> UnifiedVulnerabilityModel:
        return UnifiedVulnerabilityModel(
            database=self.database_name(),
            package=self.create_package(model),
            identifier=self.extract_identifier(model),
            severity=self.extract_severity(model)
        )


class GithubAdvisoryLoader(AdvisoryLoader):

    def database_name(self) -> str:
        return "ghsa"

    def create_package(self, model: dict) -> Package:

        pkg = model["Package"]

        ecosystem = pkg["Ecosystem"].lower()
        if ecosystem == "pip":
            ecosystem = "pypi"

        pkg_name: str = pkg["Name"]
        if ecosystem == "go" and pkg_name.startswith("https"):
            pkg_name = "/".join(pkg_name.split("/")[3:])

        return Package(
            ecosystem=ecosystem,
            name=pkg_name,
            purl=create_purl(ecosystem, name=pkg_name)
        )

    def extract_identifier(self, model: dict) -> str:
        identifiers = model["Advisory"]["Identifiers"]

        # TODO
        filtered_identifiers = list(filter(lambda x: x["Type"] == "CVE", identifiers))
        if len(filtered_identifiers) == 0:
            filtered_identifiers = list(filter(lambda x: x["Type"] == "GHSA", identifiers))
        return filtered_identifiers[0]["Value"]

    def extract_severity(self, model: dict) -> Severity:
        advisory = model["Advisory"]
        return [
            SeverityItem(
                type="CVSS_V3",
                score=advisory["CVSS"]["VectorString"]
            )
        ]


class GitlabAdvisoryLoader(AdvisoryLoader):
    def database_name(self) -> str:
        return "glad"

    def create_package(self, model: dict) -> Package:
        slug: str = model["PackageSlug"]
        first_slash = slug.find("/")
        ecosystem = slug[:first_slash]
        pkg_name = slug[first_slash + 1:]
        return Package(
            ecosystem=ecosystem,
            name=pkg_name,
            purl=create_purl(ecosystem, name=pkg_name)
        )

    def extract_identifier(self, model: dict) -> str:
        return model["Identifier"]

    def extract_severity(self, model: dict) -> Severity:
        severity = []
        if "CvssV2" in model:
            severity.append(
                SeverityItem(
                    type="CVSS_V2",
                    score=model["CvssV2"]
                )
            )
        if "CvssV3" in model:
            severity.append(
                SeverityItem(
                    type="CVSS_V3",
                    score=model["CvssV3"]
                )
            )

        return severity


class NvdLoader(AdvisoryLoader):

    def database_name(self) -> str:
        return "nvd"

    def create_package(self, model: dict) -> Package:
        pass

    def extract_identifier(self, model: dict) -> str:
        return model["cve"]["CVE_data_meta"]["ID"]

    def extract_severity(self, model: dict) -> Severity:
        severity = []
        metricV2 = model["impact"].get("baseMetricV2")
        if metricV2 is not None:
            cvssV2 = SeverityItem(
                type="CVSS_V2",
                score=metricV2["cvssV2"]["vectorString"],
            )
            severity.append(cvssV2)
        metricV3 = model["impact"].get("baseMetricV3")
        if metricV3 is not None:
            cvssV3 = SeverityItem(
                type="CVSS_V3",
                score=metricV3["cvssV3"]["vectorString"],
            )
            severity.append(cvssV3)
        return severity


class OsvFormatBasedLoader(AdvisoryLoader, ABC):

    def extract_severity(self, model: dict) -> Severity:
        if "severity" not in model:
            return list()
        return [
            SeverityItem(type=s["type"], score=s["score"])
            for s in model["severity"]
        ]

    def extract_identifier(self, model: dict) -> str:

        identifier: str = model["id"]

        if identifier.startswith("CVE"):
            return identifier

        if "aliases" in model:
            def get_identifier_by_type(_type: str) -> str | None:
                identifiers = list(filter(lambda alias: alias.startswith(_type), model["aliases"]))
                return identifiers[0] if len(identifiers) > 0 else None

            cve = get_identifier_by_type("CVE")
            if cve is not None:
                return cve

            ghsa = get_identifier_by_type("GHSA")
            if ghsa is not None:
                return ghsa

        return identifier


class OsvLoader(OsvFormatBasedLoader):

    def database_name(self) -> str:
        return "osv"

    def create_package(self, model: dict) -> Package:
        # TODO
        pkg = model["affected"][0]["package"]
        return Package(
            ecosystem=pkg["ecosystem"],
            name=pkg["name"],
            purl=pkg["purl"]
        )


class GoLoader(OsvFormatBasedLoader):

    def database_name(self) -> str:
        return "go"

    def create_package(self, model: dict) -> Package:
        return Package(
            ecosystem="go",
            name=model["module"],
            purl=create_purl(_type="go", name=model["module"])
        )

    def extract_severity(self, model: dict) -> Severity:
        # TODO
        pass


loaders = [
    GithubAdvisoryLoader(),
    GitlabAdvisoryLoader(),
    NvdLoader(),
    OsvLoader()
]


def init_loaders() -> Dict[str, AdvisoryLoader]:
    return {loader.database_name(): loader for loader in loaders}


def load_vulnerabilities(databases_path: str, databases: list[str]) -> list[UnifiedVulnerabilityModel]:
    supported_databases = [loader.database_name() for loader in loaders]
    logging.info(f"Supported databases: {supported_databases}")

    scan_all = len(databases) == 0

    if not scan_all:
        for database in databases:
            if database not in supported_databases:
                raise ValueError(f"'{database}' database is not supported")

    models = []
    for loader in loaders:
        if not scan_all and loader.database_name() not in databases:
            logging.info(f"Skip scan {loader.database_name()}")
            continue
        logging.info(f"Scan {loader.database_name()}")
        for model in tqdm(loader.scan_database(databases_path)):
            models.append(model)

    return models
