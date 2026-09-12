"""Utility functions for LogShield."""

import json
from pathlib import Path


def validate_file(path):
    """Check that the input file exists."""
    file_path = Path(path)

    if not file_path.is_file():
        raise FileNotFoundError(
            f"Log file not found: {path}"
        )

    return file_path


def save_json(data, path):
    """Save data as a formatted JSON file."""
    output_path = Path(path)

    output_path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    with open(
        output_path,
        "w",
        encoding="utf-8",
    ) as file:
        json.dump(
            data,
            file,
            indent=4,
        )