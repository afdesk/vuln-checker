from pathlib import Path
from vuln_checker.pipline import find_different_advisories, VulnerabilityInfo

vulns: dict[str, VulnerabilityInfo] = {
    'GHSA-cvx8-ppmc-78hm':
        {
            'aliases': {
                'CVE-2022-1798',
                'GHSA-qv98-3369-g364',
                'GMS-2022-3668',
                'GMS-2022-4130'
            },
            'files': set()
        }
}

test_data_path = Path.cwd() / "tests" / "unit" / "test_data"

files = [
    'ghsa/GHSA-qv98-3369-g364.json',
    'glad/CVE-2022-1798.json',
    'osv/GHSA-cvx8-ppmc-78hm.json',
    'ghsa/GHSA-cvx8-ppmc-78hm.json',
    'redhat/CVE-2022-1798.json',
    'osv/GHSA-qv98-3369-g364.json',
    'glad/GMS-2022-3668.json',
    'glad/GMS-2022-4130.json',
    'nvd/CVE-2022-1798.json'
]

for source in files:
    source_path = test_data_path / source
    vulns["GHSA-cvx8-ppmc-78hm"]["files"].add(source_path.as_posix())


def test_find_different_advisories():
    advisories = find_different_advisories(vulns)
    different_by_severity = next(filter(lambda r: r["key"] == "severity", advisories), None)

    expected_keys = {"HIGH", "MODERATE"}

    actual_keys = {r["value"] for r in different_by_severity["results"]}
    assert actual_keys ^ expected_keys == set()

    for r in different_by_severity["results"]:
        if r["value"] == "HIGH":
            assert len(r["advisories"]) == 2
        elif r["value"] == "MODERATE":
            assert len(r["advisories"]) == 1
