import os


def create_purl(_type: str, name: str, namespace: str | None = None) -> str:
    """
    A purl or package URL is an attempt to standardize existing approaches to
    reliably identify and locate software packages.
    :param _type: the package "type" or package "protocol" such as maven, npm, nuget, gem, pypi, etc.
    :param name:the name of the package.
    :param namespace:some name prefix such as a Maven groupid, a Docker image owner, a GitHub user or organization.
    :return:
    """
    if namespace is not None:
        return f"pkg:{_type}/{namespace}/{name}"
    return f"pkg:{_type}/{name}"


def scan_dir_recursively(path):
    for entry in os.scandir(path):
        if entry.is_dir(follow_symlinks=False):
            yield from scan_dir_recursively(entry.path)
        else:
            yield entry
