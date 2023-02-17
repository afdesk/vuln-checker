import pytest

from vuln_checker.load import GithubAdvisoryLoader
from vuln_checker.model import Package, SeverityItem


@pytest.fixture
def loader() -> GithubAdvisoryLoader:
    return GithubAdvisoryLoader()


model = {
    "Severity": "CRITICAL",
    "UpdatedAt": "2022-12-30T19:15:55Z",
    "Package": {
        "Ecosystem": "GO",
        "Name": "code.cloudfoundry.org/archiver"
    },
    "Advisory": {
        "DatabaseId": 199209,
        "Id": "GSA_kwCzR0hTQS0zMnFoLTh2ZzYtOWc0M84AAwop",
        "GhsaId": "GHSA-32qh-8vg6-9g43",
        "References": [
            {
                "Url": "https://nvd.nist.gov/vuln/detail/CVE-2018-25046"
            },
            {
                "Url": "https://github.com/cloudfoundry/archiver/commit/09b5706aa9367972c09144a450bb4523049ee840"
            },
            {
                "Url": "https://pkg.go.dev/vuln/GO-2020-0025"
            },
            {
                "Url": "https://snyk.io/research/zip-slip-vulnerability"
            },
            {
                "Url": "https://github.com/advisories/GHSA-32qh-8vg6-9g43"
            }
        ],
        "Identifiers": [
            {
                "Type": "GHSA",
                "Value": "GHSA-32qh-8vg6-9g43"
            },
            {
                "Type": "CVE",
                "Value": "CVE-2018-25046"
            }
        ],
        "Description": "Due to improper path santization, archives containing relative file paths can cause files to be written (or overwritten) outside of the target directory.",
        "Origin": "UNSPECIFIED",
        "PublishedAt": "2022-12-28T00:30:23Z",
        "Severity": "CRITICAL",
        "Summary": "Cloud Foundry Archiver vulnerable to path traversal",
        "UpdatedAt": "2023-02-03T05:01:28Z",
        "WithdrawnAt": "",
        "CVSS": {
            "Score": 9.1,
            "VectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H"
        }
    },
    "Versions": [
        {
            "FirstPatchedVersion": {
                "Identifier": "0.0.0-20180523222229-09b5706aa936"
            },
            "VulnerableVersionRange": "\u003c 0.0.0-20180523222229-09b5706aa936"
        }
    ]
}


def test_create_package(loader):

    expected_package = Package(
        ecosystem="go",
        name="code.cloudfoundry.org/archiver",
        purl="pkg:go/code.cloudfoundry.org/archiver"
    )

    package = loader.create_package(model)
    assert package == expected_package


def test_create_package_slug_when_pgk_name_is_link_to_go_dev(loader):

    expected_package = Package(
        ecosystem="go",
        name="github.com/cloudwego/hertz",
        purl="pkg:go/github.com/cloudwego/hertz"
    )

    package = loader.create_package(
        {
            "Package": {
                "Ecosystem": "go",
                "Name": "https://pkg.go.dev/github.com/cloudwego/hertz"
            }
        }
    )

    assert package == expected_package


def test_extract_severity(loader):

    expected_severity = [
        SeverityItem(
            type="CVSS_V3",
            score="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H"
        )
    ]

    metric = loader.extract_severity(model)

    assert metric == expected_severity


def test_extract_identifier(loader):
    assert loader.extract_identifier(model) == "CVE-2018-25046"


def test_extract_identifier_when_cve_doesnt_exist_then_extract_ghsa(loader):
    assert loader.extract_identifier(
        {
            "Advisory": {
                "Identifiers": [
                    {
                        "Type": "GHSA",
                        "Value": "GHSA-32qh-8vg6-9g43"
                    }
                ]
            }
        }
    ) == "GHSA-32qh-8vg6-9g43"
