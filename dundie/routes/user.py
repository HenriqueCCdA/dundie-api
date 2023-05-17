from fastapi import APIRouter
from sqlmodel import Session, select
from dundie.models.user import User, UserResponse, UserRequest
from dundie.db import ActiveSession


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



@router.post("/", response_model=UserResponse, status_code=201)
async def create_user(*, session: Session = ActiveSession, user: UserRequest):
    """Creates a new user"""
    db_user = User.from_orm(user)
    print(db_user)
    session.add(db_user)
    session.commit()
    session.refresh(db_user)
    return db_user
