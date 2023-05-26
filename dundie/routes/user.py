from fastapi import APIRouter, HTTPException
from sqlmodel import Session, select
from dundie.models.user import User, UserResponse, UserRequest
from dundie.db import ActiveSession
from dundie.auth import SuperUser
from sqlalchemy.exc import IntegrityError


router = APIRouter()


@router.get("/", response_model=list[UserResponse])
async def list_users(*, session: Session = ActiveSession):
    """List all users from database"""
    users = session.exec(select(User)).all()
    return users


@router.get("/{username}/", response_model=UserResponse)
async def get_user_by_username(*, session: Session = ActiveSession, username: str):
    """Get single usser by username"""
    query = select(User).where(User.username == username)
    user = session.exec(query).first()
    return user


@router.post("/", response_model=UserResponse, status_code=201, dependencies=[SuperUser])
async def create_user(*, session: Session = ActiveSession, user: UserRequest):
    """Creates a new user"""
    if session.exec(select(User).where(User.email == user.email)).first():
        raise HTTPException(
            status_code=409,
            detail="User email already exist",
        )

    db_user = User.from_orm(user)
    session.add(db_user)
    try:
        session.commit()
    except IntegrityError:
        raise HTTPException(
            status_code=500,
            detail="Database IntegrityError",
        )

    session.commit()
    session.refresh(db_user)
    return db_user
