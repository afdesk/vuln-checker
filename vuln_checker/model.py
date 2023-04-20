import hashlib
from dataclasses import dataclass, asdict, field
from typing import TypedDict, Literal


@dataclass
class VulnerabilityModel:
    id: str
    description: str
    source: str
    title: str | None = None
    aliases: set[str] = field(default_factory=set)
    severity: str | None = None
    cvss_v3_score: float | None = None
    cvss_v3_vector: str | None = None
    primary_link: str | None = None

    def to_dict(self):
        return asdict(self)


KeyForCheck = Literal['severity', 'cvss_v3_vector', 'cvss_v3_score']

Advisory = TypedDict(
    'Advisory', {
        'filepath': str,
        'id': str,
        'source': str,
        'primary_link': str | None,
        'severity': str | None,
        'cvss_v3_vector': str | None,
        'cvss_v3_score': float | None
    }
)

GroupedAdvisories = dict[str, list[Advisory]]

Group = TypedDict(
    "Group", {
        "advisories": list[Advisory],
        "value": str | float,
    }
)

Report = TypedDict(
    "Report", {
        "results": list[Group],
        "key": KeyForCheck,
        "discussion_id": str | None,
    }
)

HashedReports = dict[int, Report]


def hash_report(report: Report) -> int:
    converted = _extract_primary_fields(report)
    return int(hashlib.md5(str(converted).encode()).hexdigest(), 16)


def _extract_primary_fields(report: Report) -> list:
    result = []
    results = report["results"]
    field_key = report['key']
    for group in results:
        for advisory in group['advisories']:
            result.append({
                'id': advisory['id'],
                'key': field_key,
                'value': _filter_field_by_key(advisory, field_key)
            })
    result.sort(key=lambda x: x['id'])
    return result


def _filter_field_by_key(advisory: Advisory, key: KeyForCheck) -> str | float:
    return advisory[key]
