"""ensure_admin_user

Revision ID: 2d84824168da
Revises: 7422421aeec0
Create Date: 2023-06-02 19:23:19.463768

"""
from alembic import op
import sqlalchemy as sa
import sqlmodel

from dundie.models.user import User
from sqlmodel import Session


# revision identifiers, used by Alembic.
revision = '2d84824168da'
down_revision = '7422421aeec0'
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    session = Session(bind=bind)

    admin = User(
        name="Admin",
        username="admin",
        email="admin@dm.com",
        dept="management",
        password="admin", # envvar/secrets
        currency="USD",
    )

    try:
        session.add(admin)
        session.commit()
    except sa.exc.IntegrityError as e:
        print(e)
        session.rollback()



def downgrade() -> None:
    pass
