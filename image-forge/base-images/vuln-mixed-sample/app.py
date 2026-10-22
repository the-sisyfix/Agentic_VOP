"""Trivial payload for the vuln-mixed-sample test image.

Meaningless by design — this image exists only to carry BOTH a vulnerable OS
package surface (patched by copa) AND a vulnerable pip dependency (fixed by the
dependency-bump rebuild leg), so the combined hardening path can be proven
end-to-end. We import the declared pip dep so it is unambiguously present.
"""

import urllib3


def main() -> None:
    print(f"vuln-mixed-sample up; urllib3 version: {urllib3.__version__}")


if __name__ == "__main__":
    main()
