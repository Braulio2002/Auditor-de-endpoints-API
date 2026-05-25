from pathlib import Path


def get_unique_filename(directory: Path, base_name: str, extension: str) -> Path:
    """
    Generates a unique filename in the given directory to prevent overwriting existing reports.
    If 'base_name.extension' exists, tries 'base_name_1.extension', 'base_name_2.extension', etc.
    """
    # Ensure extension starts with a dot
    if extension and not extension.startswith("."):
        extension = f".{extension}"

    target_dir = Path(directory)
    # Check if target directory exists, if not just return default path (directory manager will handle creation)
    if not target_dir.exists():
        return target_dir / f"{base_name}{extension}"

    # Try standard file name
    candidate = target_dir / f"{base_name}{extension}"
    if not candidate.exists():
        return candidate

    # Iterate until finding a non-existent file name
    counter = 1
    while True:
        candidate = target_dir / f"{base_name}_{counter}{extension}"
        if not candidate.exists():
            return candidate
        counter += 1
