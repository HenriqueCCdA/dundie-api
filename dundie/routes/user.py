from fastapi import APIRouter
from sqlmodel import Session, select
from dundie.models.user import User, UserResponse
from dundie.db import ActiveSession


router = APIRouter()


@router.get("/", response_model=list[UserResponse])
async def list_users(*, session: Session = ActiveSession):
    """List all users from database"""
    users = session.exec(select(User)).all()
    return users
