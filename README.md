# vuln-checker

```shell
mv .env.sample .env
```

### Usage

```shell
poetry run vuln-checker -h

usage: vuln-checker [-h] [--skip-convert] [--skip-update] [--export-type EXPORT_TYPE] [--skip-init]

options:
  -h, --help            show this help message and exit
  --skip-convert        Skip convert and dump advisories
  --skip-update         Skip updating the databases.
  --export-type EXPORT_TYPE
                        Export type, comma separated. Available: table, text, github
  --skip-init           Skip initializing the github report.

Examples:
    
    # Analyze advisories and export report to github
    ❯ poetry run vuln-checker --export-type "github"

    # Example for development, skip updating and converting advisories, report only
    ❯ poetry run vuln-checker --skip-update --skip-convert --skip-init --export-type "github,table"
```