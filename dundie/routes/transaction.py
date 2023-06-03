from fastapi import APIRouter, Body, HTTPException
from dundie.auth import AuthenticateUser
from dundie.db import ActiveSession
from dundie.models import User
from dundie.tasks.transaction import TransactionError, add_tranaction, Transaction
from sqlmodel import select, Session

router = APIRouter()


@router.post("/{username}/", status_code=201)
async def create_transaction(
    *,
    username: str,
    value: int = Body(embed=True),
    current_user: User = AuthenticateUser,
    session: Session = ActiveSession,
):
    """Adds a new trannsaction to the specfied user."""
    user = session.exec(select(User).where(User.username == username)).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    try:
        add_tranaction(user=user, from_user=current_user, value=value, session=session)
    except TransactionError as e:
        raise HTTPException(status_code=400, detail=str(e))

    # At this point there was no error, so we can return
    return {"message": "Transaction added"}
