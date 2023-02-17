from dataclasses import dataclass, asdict, field


@dataclass
class VulnerabilityModel:
    id: str
    description: str
    title: str | None = None
    aliases: set[str] = field(default_factory=set)
    severity: str | None = None
    cvss_v3_score: float | None = None
    cvss_v3_vector: str | None = None

    def to_dict(self):
        return asdict(self)
