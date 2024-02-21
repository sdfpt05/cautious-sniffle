"""added user creds

Revision ID: 8813f1a688ac
Revises: 146a9012b14e
Create Date: 2024-02-21 14:41:48.999521

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '8813f1a688ac'
down_revision: Union[str, None] = '146a9012b14e'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    pass


def downgrade() -> None:
    pass
