import pytest

from vuln_checker.load import GitlabAdvisoryLoader
from vuln_checker.model import Package, SeverityItem


@pytest.fixture
def loader() -> GitlabAdvisoryLoader:
    return GitlabAdvisoryLoader()


model = {
    "Identifier": "CVE-2019-11289",
    "PackageSlug": "go/code.cloudfoundry.org/gorouter/common/secure",
    "Title": "Improper Input Validation",
    "Description": "Cloud Foundry Routing, all versions before 0.193.0, does not properly validate nonce input. A remote unauthenticated malicious user could forge an HTTP route service request using an invalid nonce that will cause the Gorouter to crash.",
    "Date": "2021-05-18",
    "Pubdate": "2021-05-18",
    "AffectedRange": "\u003c0.193.0",
    "FixedVersions": [
        "0.193.0"
    ],
    "AffectedVersions": "All versions before 0.193.0",
    "NotImpacted": "All versions starting from 0.193.0",
    "Solution": "Upgrade to version 0.193.0 or above.",
    "Urls": [
        "https://nvd.nist.gov/vuln/detail/CVE-2019-11289",
        "https://www.cloudfoundry.org/blog/cve-2019-11289",
        "https://github.com/advisories/GHSA-5796-p3m6-9qj4"
    ],
    "CvssV2": "AV:N/AC:L/Au:N/C:N/I:N/A:C",
    "CvssV3": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H",
    "UUID": "967bd4ce-0043-44e3-ba26-f995385dd230"
}


def test_create_package(loader):
    expected_package = Package(
        ecosystem="go",
        name="code.cloudfoundry.org/gorouter/common/secure",
        purl="pkg:go/code.cloudfoundry.org/gorouter/common/secure"
    )

    package = loader.create_package(model)

    assert package == expected_package


def test_extract_severity(loader):
    expected_severity = [
        SeverityItem(
            type="CVSS_V2",
            score="AV:N/AC:L/Au:N/C:N/I:N/A:C",
        ),
        SeverityItem(
            type="CVSS_V3",
            score="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H"
        )
    ]

    metric = loader.extract_severity(model)

    assert metric == expected_severity


def test_extract_cve_identifier(loader):
    assert loader.extract_identifier(model) == "CVE-2019-11289"
