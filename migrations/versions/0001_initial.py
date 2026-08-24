"""initial empty baseline

Revision ID: 0001_initial
Revises:
Create Date: 2026-08-24

"""

from collections.abc import Sequence

revision: str = "0001_initial"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # M0 baseline: no tables yet. Schema arrives in M1.
    pass


def downgrade() -> None:
    pass
