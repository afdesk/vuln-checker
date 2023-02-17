from dataclasses import dataclass


@dataclass
class Package:
    ecosystem: str
    name: str
    #see https://github.com/package-url/purl-spec
    purl: str


@dataclass
class SeverityItem:
    type: str
    score: str

    def score_is_not_equals(self, other: "SeverityItem") -> bool:
        return self.score != other.score


@dataclass
class UnifiedVulnerabilityModel:
    """
    https://ossf.github.io/osv-schema/
    """
    database: str
    package: str
    identifier: str
    severity: list[SeverityItem]
    package: Package

    def compare_by_identifier_and_purl(self):
        return f"{self.identifier}-{self.package.purl}"

    def get_cvss_by_type(self, _type: str) -> SeverityItem | None:
        cvss_list = list(filter(lambda x: x.type == _type, self.severity))
        if len(cvss_list) > 0:
            return cvss_list[0]

        return None
