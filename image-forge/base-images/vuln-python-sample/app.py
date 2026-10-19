"""Trivial payload for the vuln-python-sample test image.

The application is intentionally meaningless — this image exists only to carry a
deliberately-vulnerable pip dependency (urllib3) so the hardening pipeline's
dependency-bump (rebuild) leg can be proven end-to-end. We import the declared
package so it is unambiguously present/used, then exit.
"""

import urllib3


def main() -> None:
    print(f"vuln-python-sample up; urllib3 version: {urllib3.__version__}")


if __name__ == "__main__":
    main()
