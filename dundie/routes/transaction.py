from typing import Optional
from fastapi import APIRouter, Body, Depends, HTTPException
from dundie.auth import AuthenticateUser
from dundie.db import ActiveSession
from dundie.models import User, Transaction
from dundie.models.serializers import TransactionResponse
from dundie.tasks.transaction import TransactionError, add_tranaction, Transaction
from sqlmodel import select, Session, text
from fastapi_pagination import Page, Params
from fastapi_pagination.ext.sqlmodel import paginate
from sqlalchemy.orm import aliased


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


@router.get("/", response_model=Page[TransactionResponse])
async def list_transactions(
    *,
    current_user: User = AuthenticateUser,
    session: Session = ActiveSession,
    params: Params = Depends(),
    user: Optional[str] = None,
    from_user: Optional[str] = None,
    order_by: Optional[str] = None,  #order_by=date, value -date,-value
):
    """List all transactions"""
    query =  select(Transaction)

    # filtros opcionais AND
    if user:
        query = query.join(
            User, Transaction.user_id == User.id
        ).where(User.username == user)

    if from_user:
        FromUser = aliased(User)
        query = query.join(
            FromUser, Transaction.from_id == FromUser.id
        ).where(FromUser.username == from_user)

    # access filters
    if not current_user.superuser:
        query = query.where(
            (Transaction.user_id == current_user.id) | (Transaction.from_id == current_user.id)
        )

    if order_by:
        order_text = text(
            order_by.replace("-", "") + " " + ("desc" if "-" in order_by else "asc")
        )
        query = query.order_by(order_text)

    return paginate(query=query, session=session, params=params)
