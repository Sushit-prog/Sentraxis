"""Build a compact ATT&CK Enterprise technique index from mitre/cti STIX.

Downloads the official enterprise-attack bundle once, extracts technique
id -> name pairs (skipping revoked/deprecated entries), and writes a compact
JSON resource used by correlation validation at runtime:

    src/app/correlation/data/attack_index.json

The derived index is committed so runtime never needs network access.
"""

import argparse
import json
import sys
import urllib.request
from pathlib import Path

BUNDLE_URL = (
    "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
)
DEFAULT_OUT = Path("src/app/correlation/data/attack_index.json")


def build_index(bundle_path: Path) -> dict[str, str]:
    data = json.loads(bundle_path.read_text(encoding="utf-8"))
    index: dict[str, str] = {}
    revoked = 0
    for obj in data.get("objects", []):
        if obj.get("type") != "attack-pattern":
            continue
        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            revoked += 1
            continue
        ext_id = None
        for ref in obj.get("external_references", []):
            if ref.get("source_name") == "mitre-attack" and str(
                ref.get("external_id", "")
            ).startswith("T"):
                ext_id = ref["external_id"]
                break
        name = obj.get("name")
        if ext_id and name:
            index[ext_id] = name.strip()
    if len(index) < 400:
        raise SystemExit(f"suspiciously small index ({len(index)} techniques); refusing to write")
    print(f"extracted {len(index)} techniques (skipped {revoked} revoked/deprecated)")
    return index


def main() -> None:
    parser = argparse.ArgumentParser(description="Fetch and compile ATT&CK technique index")
    parser.add_argument("--url", default=BUNDLE_URL)
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    args = parser.parse_args()

    raw_path = Path("/tmp/enterprise-attack.json")
    if not raw_path.exists():
        print(f"downloading {args.url} ...", file=sys.stderr)
        urllib.request.urlretrieve(args.url, raw_path)
    print(f"bundle size: {raw_path.stat().st_size / 1e6:.1f} MB")

    index = build_index(raw_path)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(index, indent=0, sort_keys=True), encoding="utf-8")
    print(f"wrote {args.out} ({args.out.stat().st_size / 1024:.0f} KB)")


if __name__ == "__main__":
    main()
