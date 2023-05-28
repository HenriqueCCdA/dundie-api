"""User related data models"""
from typing import Optional
from fastapi import HTTPException
from sqlmodel import Field, SQLModel
from dundie.security import HashedPassword, get_password_hash
from pydantic import BaseModel, root_validator
from fastapi import status


class User(SQLModel, table=True):
    """Represents the User Model"""

    id: Optional[int] = Field(default=None, primary_key=True)
    email: str = Field(unique=True, nullable=False)
    username: str = Field(unique=True, nullable=False)
    avatar: Optional[str] = None
    bio: Optional[str] = None
    password: HashedPassword
    name: str = Field(nullable=False)
    dept: str = Field(nullable=False)
    currency: str = Field(nullable=False)

    @property
    def superuser(self):
        """Users belonging to management dept are admins"""
        return self.dept == "management"


def generate_username(name: str) -> str:
    """Generate a slug from user.name.
    "Bruno Rocha" -> "bruno-rocha"
    "MIchal Scott" -> "mmichal-scott"
    # TODO: library slugify
    """
    return name.lower().replace(" ", "-")


class UserResponse(BaseModel):
    """Serializer for when we send a response to the client"""

    name: str
    username: str
    dept: str
    avatar: Optional[str] = None
    bio: Optional[str] = None
    currency: str


class UserRequest(BaseModel):
    "Deserializer for when we get the user data from the client."
    name: str
    email: str
    dept: str
    password: str
    username: Optional[str] = None
    avatar: Optional[str] = None
    bio: Optional[str] = None
    currency: str = "USD"

    @root_validator(pre=True)
    def generate_username_if_not_set(cls, values):
        """Generates  username"""
        if values.get("username") is None:
            values["username"] = generate_username(values["name"])
        return values


class UserProfilePatchRequest(BaseModel):
    "Deserializer for when client wants to partially update user."

    avatar: Optional[str] = None
    bio: Optional[str] = None

    @root_validator(pre=True)
    def ensure_validate(cls, values):
        if not values:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Bad request, no data informed")

        return values


class UserPasswordPatchRequest(BaseModel):
    password: str
    password_confirm: str

    @root_validator(pre=True)
    def check_password_match(cls, values):
        """Checks if passwords match"""
        if values.get("password") != values.get("password_confirm"):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Psswords do not match",
            )
        return values

    @property
    def hashed_password(self) -> str:
        return get_password_hash(self.password)
