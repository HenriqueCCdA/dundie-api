from jose import jwt
from datetime import timedelta, datetime
from typing import Optional
from dundie.config import settings
from functools import partial

ALGORITHM = settings.security.ALGORITHM
SECRET_KEY = settings.security.SECRET_KEY


def create_access_token(
    data: dict,
    expires_delta: Optional[timedelta] = None,
    scope: str = "access_token" ,
) -> str:
    """Creates a JWT token"""
    to_encode = data.copy()
    expires_delta = expires_delta or timedelta(minutes=15)
    expire = datetime.utcnow() + expires_delta
    to_encode.update({"exp": expire, "scope": scope})

    encode_jwt = jwt.encode(
        to_encode,
        SECRET_KEY,
        ALGORITHM,
    )

    return encode_jwt

create_refresh_token = partial(create_access_token, scope="refresh_token")
