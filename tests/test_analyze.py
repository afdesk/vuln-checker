from pathlib import Path
from vuln_checker.main import find_different_advisories

vulns = {
    'GHSA-cvx8-ppmc-78hm':
        {
            'aliases': [
                'CVE-2022-1798',
                'GHSA-qv98-3369-g364',
                'GMS-2022-3668',
                'GMS-2022-4130'
            ],
            'sources': []
        }
}

test_data_path = Path.cwd() / "test_data"

sources = [
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

for source in sources:
    source_path = test_data_path / source
    vulns["GHSA-cvx8-ppmc-78hm"]["sources"].append(source_path)


def test_find_different_advisories():
    advisories = find_different_advisories(vulns)
    different_by_severity = advisories["severity"][0]

    expected_keys = {"HIGH", "MODERATE"}

    assert different_by_severity.keys() ^ expected_keys == set()
    assert len(different_by_severity["HIGH"]) == 2
    assert len(different_by_severity["MODERATE"]) == 1
