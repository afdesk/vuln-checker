import pytest

from vuln_checker.load import NvdLoader
from vuln_checker.model import SeverityItem


@pytest.fixture
def loader() -> NvdLoader:
    return NvdLoader()


@pytest.fixture
def model() -> dict:
    return {
        "configurations": {
            "CVE_data_version": "4.0",
            "nodes": [
                {
                    "children": [
                        {
                            "children": [],
                            "cpe_match": [
                                {
                                    "cpe23Uri": "cpe:2.3:o:kingjim:mirupass_pw10_firmware:-:*:*:*:*:*:*:*",
                                    "cpe_name": [],
                                    "vulnerable": True
                                }
                            ],
                            "operator": "OR"
                        },
                        {
                            "children": [],
                            "cpe_match": [
                                {
                                    "cpe23Uri": "cpe:2.3:h:kingjim:mirupass_pw10:-:*:*:*:*:*:*:*",
                                    "cpe_name": [],
                                    "vulnerable": False
                                }
                            ],
                            "operator": "OR"
                        }
                    ],
                    "cpe_match": [],
                    "operator": "AND"
                },
                {
                    "children": [
                        {
                            "children": [],
                            "cpe_match": [
                                {
                                    "cpe23Uri": "cpe:2.3:o:kingjim:mirupass_pw20_firmware:-:*:*:*:*:*:*:*",
                                    "cpe_name": [],
                                    "vulnerable": True
                                }
                            ],
                            "operator": "OR"
                        },
                        {
                            "children": [],
                            "cpe_match": [
                                {
                                    "cpe23Uri": "cpe:2.3:h:kingjim:mirupass_pw20:-:*:*:*:*:*:*:*",
                                    "cpe_name": [],
                                    "vulnerable": False
                                }
                            ],
                            "operator": "OR"
                        }
                    ],
                    "cpe_match": [],
                    "operator": "AND"
                }
            ]
        },
        "cve": {
            "CVE_data_meta": {
                "ASSIGNER": "vultures@jpcert.or.jp",
                "ID": "CVE-2022-0183"
            },
            "data_format": "MITRE",
            "data_type": "CVE",
            "data_version": "4.0",
            "description": {
                "description_data": [
                    {
                        "lang": "en",
                        "value": "Missing encryption of sensitive data vulnerability in 'MIRUPASS' PW10 firmware all versions and 'MIRUPASS' PW20 firmware all versions allows an attacker who can physically access the device to obtain the stored passwords."
                    }
                ]
            },
            "problemtype": {
                "problemtype_data": [
                    {
                        "description": [
                            {
                                "lang": "en",
                                "value": "CWE-311"
                            }
                        ]
                    }
                ]
            },
            "references": {
                "reference_data": [
                    {
                        "name": "https://www.kingjim.co.jp/download/security/#mirupass",
                        "refsource": "MISC",
                        "tags": [
                            "Vendor Advisory"
                        ],
                        "url": "https://www.kingjim.co.jp/download/security/#mirupass"
                    },
                    {
                        "name": "https://jvn.jp/en/jp/JVN19826500/index.html",
                        "refsource": "MISC",
                        "tags": [
                            "Third Party Advisory"
                        ],
                        "url": "https://jvn.jp/en/jp/JVN19826500/index.html"
                    }
                ]
            }
        },
        "impact": {
            "baseMetricV2": {
                "acInsufInfo": False,
                "cvssV2": {
                    "accessComplexity": "LOW",
                    "accessVector": "LOCAL",
                    "authentication": "NONE",
                    "availabilityImpact": "NONE",
                    "baseScore": 2.1,
                    "confidentialityImpact": "PARTIAL",
                    "integrityImpact": "NONE",
                    "vectorString": "AV:L/AC:L/Au:N/C:P/I:N/A:N",
                    "version": "2.0"
                },
                "exploitabilityScore": 3.9,
                "impactScore": 2.9,
                "obtainAllPrivilege": False,
                "obtainOtherPrivilege": False,
                "obtainUserPrivilege": False,
                "severity": "LOW",
                "userInteractionRequired": False
            },
            "baseMetricV3": {
                "cvssV3": {
                    "attackComplexity": "LOW",
                    "attackVector": "PHYSICAL",
                    "availabilityImpact": "NONE",
                    "baseScore": 4.6,
                    "baseSeverity": "MEDIUM",
                    "confidentialityImpact": "HIGH",
                    "integrityImpact": "NONE",
                    "privilegesRequired": "NONE",
                    "scope": "UNCHANGED",
                    "userInteraction": "NONE",
                    "vectorString": "CVSS:3.1/AV:P/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                    "version": "3.1"
                },
                "exploitabilityScore": 0.9,
                "impactScore": 3.6
            }
        },
        "lastModifiedDate": "2022-01-26T15:46Z",
        "publishedDate": "2022-01-17T10:15Z"
    }


def test_extract_severity(loader, model):
    expected_severity = [
        SeverityItem(
            type="CVSS_V2",
            score="AV:L/AC:L/Au:N/C:P/I:N/A:N"
        ),
        SeverityItem(
            type="CVSS_V3",
            score="CVSS:3.1/AV:P/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
        )
    ]

    metric = loader.extract_severity(model)

    assert metric == expected_severity


def test_extract_identifier(loader, model):
    assert loader.extract_identifier(model) == "CVE-2022-0183"
