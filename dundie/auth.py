from fastapi import Depends, HTTPException, Request, status
from jose import JWTError, jwt
from datetime import timedelta, datetime
from typing import Callable, Optional, Union

from pydantic import BaseModel
from dundie.config import settings
from functools import partial
from fastapi.security import OAuth2PasswordBearer
from dundie.models.user import User

from dundie.security import verify_password
from dundie.db import engine
from sqlmodel import select, Session


ALGORITHM = settings.security.ALGORITHM
SECRET_KEY = settings.security.SECRET_KEY

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# Models


class Token(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str


class RefreshToken(BaseModel):
    refresh_token: str


class TokenData(BaseModel):
    username: Optional[str] = None


# Functions


def create_access_token(
    data: dict,
    expires_delta: Optional[timedelta] = None,
    scope: str = "access_token",
) -> str:
    """Creates a JWT token user data

    scope: access_token or refresh_token
    """
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expires = datetime.utcnow() + timedelta(minutes=15)

    to_encode.update({"exp": expire, "scope": scope})
    encode_jwt = jwt.encode(
        to_encode,
        SECRET_KEY,
        algorithm=ALGORITHM,
    )

    return encode_jwt


create_refresh_token = partial(create_access_token, scope="refresh_token")


def authenticate_user(get_user: Callable, username: str, password: str) -> Union[User, bool]:
    """Authenticate the user"""
    user = get_user(username)
    if not user:
        return False
    if not verify_password(password, user.password):
        return False
    return user


def get_user(username: str) -> Optional[User]:
    """Get user from database"""
    query = select(User).where(User.username == username)
    with Session(engine) as session:
        return session.exec(query).first()


def get_current_user(
    token: str = Depends(oauth2_scheme),
    request: Request = None,
    fresh=False,
) -> User:
    credential_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )

    if request:
        if authorization := request.headers.get("authorization"):
            try:
                token = authorization.split(" ")[1]
            except IndexError:
                raise credential_exception

    try:
        payload = jwt.decode(
            token,
            SECRET_KEY,
            algorithms=[ALGORITHM]
        )
        username = payload.get("sub")

        if username is None:
            raise credential_exception
        token_data = TokenData(username=username)
    except JWTError:
        raise credential_exception

    user = get_user(username=token_data.username)

    if user is None:
        raise credential_exception

    if fresh and (not payload["fresh"] and not user.superuser):
        raise credential_exception

    return user

# FastAPI dependencies

async def get_current_active_user(
    current_user: User = Depends(get_current_user),
) -> User:
    """Wraps the sync get_active_user for sync call"""
    return current_user

AuthenticateUser = Depends(get_current_active_user)


async def get_current_super_user(
    current_user: User = Depends(get_current_user),
) -> User:
    """Wraps the sync get_active_user for sync calls for superuser"""
    if not current_user.superuser:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not a super user"
        )
    return current_user


SuperUser = Depends(get_current_super_user)


async def validate_token(token: str = Depends(oauth2_scheme)) -> User:
    """Validates useer token"""
    user = get_current_user(token=token)
    return user
