"""Verify the hash-chained audit ledger end-to-end.

Usage: uv run python scripts/verify_audit_chain.py [--expect-min N]
Exit 0 = chain intact; exit 1 = tampering/gap detected or fewer than
--expect-min entries present.
"""

import argparse

from sqlalchemy.orm import sessionmaker

from app.config import get_settings
from app.orchestration.audit import verify_chain
from app.persistence.db import create_db_engine


def main() -> None:
    parser = argparse.ArgumentParser(description="Verify audit ledger hash chain")
    parser.add_argument("--expect-min", type=int, default=1)
    args = parser.parse_args()

    engine = create_db_engine(get_settings())
    factory = sessionmaker(bind=engine)
    with factory() as session:
        checked, first_bad = verify_chain(session)

    if first_bad is not None:
        print(f"TAMPERING DETECTED: first broken entry at seq={first_bad}")
        raise SystemExit(1)
    if checked < args.expect_min:
        print(f"too few entries: {checked} < {args.expect_min}")
        raise SystemExit(1)
    print(f"audit chain intact: {checked} entries verified")


if __name__ == "__main__":
    main()
