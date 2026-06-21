"""
Semantic versioning utilities.
"""
import re

SEMVER_REGEX = re.compile(r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-((?:0|[1-9]\d*|\d*[a-zA-Z-][0-zA-Z0-9-]*)(?:\.(?:0|[1-9]\d*|\d*[a-zA-Z-][0-zA-Z0-9-]*))*))?(?:\+([0-9a-zA-Z-]+(?:\.[0-9a-zA-Z-]+)*))?$")

def parse_semver(version: str) -> tuple[int, int, int]:
    """Parse semver string into tuple."""
    match = SEMVER_REGEX.match(version)
    if not match:
        raise ValueError(f"Invalid semantic version: {version}")
    return int(match.group(1)), int(match.group(2)), int(match.group(3))

def compare_versions(v1: str, v2: str) -> int:
    """Return 1 if v1 > v2, -1 if v1 < v2, 0 if equal."""
    p1 = parse_semver(v1)
    p2 = parse_semver(v2)
    if p1 > p2:
        return 1
    elif p1 < p2:
        return -1
    return 0

def is_compatible_version(required: str, actual: str) -> bool:
    """Basic major version compatibility check."""
    req_major = parse_semver(required)[0]
    act_major = parse_semver(actual)[0]
    return req_major == act_major
