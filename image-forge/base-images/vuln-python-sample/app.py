"""Trivial payload for the vuln-python-sample test image.

The application is intentionally meaningless — this image exists only to carry
deliberately-vulnerable pip dependencies so the hardening pipeline's
dependency-bump (rebuild) leg can be proven end-to-end. We import the declared
packages so they are unambiguously present/used, then exit.
"""

import jinja2
import requests
import urllib3
import yaml


def main() -> None:
    # Reference each dependency so it is clearly a real, used import.
    versions = {
        "requests": requests.__version__,
        "urllib3": urllib3.__version__,
        "jinja2": jinja2.__version__,
        "pyyaml": yaml.__version__,
    }
    print(f"vuln-python-sample up; dependency versions: {versions}")


if __name__ == "__main__":
    main()
