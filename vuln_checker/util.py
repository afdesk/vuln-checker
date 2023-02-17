import os


def scan_dir_recursively(path):
    for entry in os.scandir(path):
        if entry.is_dir(follow_symlinks=False):
            yield from scan_dir_recursively(entry.path)
        else:
            yield entry


def create_dir(path):
    exist = os.path.exists(path)
    if not exist:
        os.mkdir(path)
