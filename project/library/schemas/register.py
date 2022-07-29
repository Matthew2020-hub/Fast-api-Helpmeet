from pydantic import (
    BaseModel, 
    EmailStr, 
    Field, 
    root_validator
)
from library.dependencies.utils import validate_password

regex = "^(?=.*?[A-Z])(?=.*?[a-z])(?=.*?[0-9])(?=.*?[#?!@$%^&*+=]).{8,}$"


class UserCreate(BaseModel):
    full_name: str = Field(..., max_length=150)
    house_address: str = Field(..., max_length=150)
    estate_name: str = Field(..., max_length=150)
    email: EmailStr
    password: str = Field(..., max_length=40, min_length=8)

    @root_validator()
    def validate_password_value(cls, values):
        return validate_password(values=values)



class UserPublic(BaseModel):
    full_name: str = Field(..., max_length=50)
    house_address: str = Field(..., max_length=150)
    estate_name: str = Field(..., max_length=150)
    is_admin: bool
    email: EmailStr



class EstateCreate(BaseModel):
    email: EmailStr
    password: str = Field(..., max_length=40, min_length=8)
    estate_name: str = Field(..., max_length=50)
    estate_addres: str = Field(..., max_length=50)
    country: str = Field(..., max_length=15)
    estate_name: str = Field(..., max_length=150)



class EstatePublic(BaseModel):
    estate_name: str = Field(..., max_length=50)
    estate_addres: str = Field(..., max_length=50)
    country: str = Field(..., max_length=15)
    estate_name: str = Field(..., max_length=150)
    member: UserPublic



class EmailVerify(BaseModel):
    email_verified: bool
