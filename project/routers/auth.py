from jose import JWTError, jwt
from passlib.context import CryptContext
from datetime import datetime, timedelta, timezone
from fastapi import (
    APIRouter, 
    status, 
    Path, 
    HTTPException
)
from models.user import User
from library.dependencies.utils import to_lower_case
from library.schemas.register import (
    UserCreate, 
    EmailVerify,
    EstatePublic,
    EstateCreate
)
from library.schemas.auth import (
    LoginSchema,
    AuthResponse,
    JWTSchema,
    PasswordResetSchema,
    ForgotPasswordSchema,
    UserPublic
)
from config import SECRET_KEY, ALGORITHM, conf
from fastapi_mail import FastMail, MessageSchema
from models.user import Estate

router = APIRouter(prefix="/auth")
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


@router.post(
    "/register/",
    response_model=UserPublic,
    name="auth:register",
    status_code=status.HTTP_201_CREATED,
)
async def user_register(data: UserCreate):
    """Creates a new user

    Registers a user in the database
    Returns user details when successfully registered
    Args:
        data - a pydantic schema that defines the user registration params
    Returns:
        HTTP_201_CREATED (with user details as defined in the response model)
        Sends otp via SMTP as a background task
    Raises:
        HTTP_400_BAD_REQUEST if user exists
    """

    # Converts user email to lower-case to avoid being case sensitive
    valid_email = to_lower_case(data.email)
    email_exist = await User.exists(email=valid_email)
    if email_exist:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User with this email already exist",
        )

    hashed_password = pwd_context.hash(data.password)
    created_user = await User.create(
        **data.dict(exclude_unset=True, exclude={"password"}),
        hashed_password=hashed_password,
    )
    expire = datetime.now(timezone.utc) + timedelta(seconds=600)
    to_encode = {"user_id": str(created_user.id), "expire": str(expire)}
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    print(encoded_jwt)

    absurl = f"https://freehouses.herokuapp.com/auth/email-verify?token={encoded_jwt}"
    email_body = (
        "Hi " + " " + data.full_name + ":\n" + 
        "Use link below to verify your email" +
        "\n" + absurl
    )
    message = MessageSchema(
        subject="Email Verification",
        recipients=data.email, 
        body=email_body,
        subtype="html"
        )
    fm = FastMail(conf)
    await fm.send_message(message)
    return created_user



@router.put(
    "/verify-email/{token}",
    response_model=EmailVerify,
    status_code=status.HTTP_200_OK,
    # name="auth:verify-email"
)
async def email_verification(token: str = Path(...)):
    """Verifies email of a new user

    Verifies the token and throw an error if token is invalid
    Updates the email verified field to true and returns field
    Args:
        token - a random str retrieved from the path
    Returns:
        HTTP_200_OK (with user details as defined in the response model)
    Raises:
        HTTP_401_UNAUTHORIZED if otp is invalid, expired or verification fails
    """
    credentials_exception = HTTPException(
        status_code=401,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        # Decodes token
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id: str = payload.get("user_id")
        expire = payload.get("expire")
        if user_id is None or expire is None:
            raise credentials_exception
    except JWTError as e:
        raise credentials_exception from e

    # Check token expiration
    if str(datetime.now(timezone.utc)) > expire:
        raise HTTPException(
            status_code=401,
            detail="Token expired or invalid!",
        )

    # Fetches associated user from db
    user = await User.get_or_none(id=user_id)
    if user is None:
        raise HTTPException(
            detail="User not found or does not exist",
            status_code=status.HTTP_401_UNAUTHORIZED,
        )
    return await User.get(id=user_id).update(is_verify=True)



@router.post(
    "/login/",
    response_model=AuthResponse,
    name="auth:login",
    status_code=status.HTTP_200_OK,
)
async def login(data: LoginSchema):
    """Handles user login.

    Args:
        data - a pydantic schema that defines the user login details
    Return:
        HTTP_200_OK (with user details as defined in the response model)
        a jwt encoded token to be attached to request headers
    Raises:
        HTTP_401_UNAUTHORIZED if login credentials are incorrect
    """
    user = await User.get_or_none(email=data.email)

    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Your email or password is incorrect.",
        )

    # Check password.
    hashed_password = user.hashed_password
    is_valid_password: bool = pwd_context.verify(
        data.password, hashed_password
    )
    if not is_valid_password:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Your email or password is incorrect.",
        )

    # Generate an auth token.
    jwt_data = JWTSchema(user_id=str(user.id))
    to_encode = jwt_data.dict()
    expire = datetime.now(timezone.utc) + timedelta(days=30)
    to_encode.update({"expire": str(expire)})

    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return AuthResponse(user=user, token=encoded_jwt)



@router.post(
    "/forgot-password/",
    name="auth:forgot-password",
    status_code=status.HTTP_200_OK,
)
async def forgot_password(data: ForgotPasswordSchema):
    """Handles forgot password request

    Args:
        data - a pydantic schema that defines forgot password detail
    Return:
        HTTP_200_OK response with password reset link sent in a mail service
    Raises:
        HTTP_401_UNAUTHORIZED if data doesn't match any entry in the DB
    """
    user = await User.get_or_none(email=data.email)
    if user is None:
        raise HTTPException(
            detail="User does not exist",
            status_code=status.HTTP_401_UNAUTHORIZED,
        )
    expire = datetime.now(timezone.utc) + timedelta(seconds=600)
    to_encode = {"user_id": str(user.id), "expire": str(expire)}
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    print(encoded_jwt)
    
    absurl = f"https://freehouses.herokuapp.com/auth/email-verify?token={encoded_jwt}"
    email_body = (
        "Hi " + " " + data.full_name + ":\n"
        "To reset your passowrd, use the link below"
        "\n" + absurl
    )
    message = MessageSchema(
        subject="Email Verification",
        recipients=data.email, 
        body=email_body,
        subtype="html"
        )
    fm = FastMail(conf)
    await fm.send_message(message)
    return {"message": f"Password reset link sent to {data.email}"}


@router.put(
    "/reset-password/{token}",
    name="auth:reset-password",
    status_code=status.HTTP_200_OK,
)
async def password_reset(data: PasswordResetSchema, token: str = Path(...)):
    """Handles password reset request

    Args:
        data - a pydantic schema that defines the required reset details
        token - jwt encoded token sent as path param
    Return:
        HTTP_200_OK response with a success message
    Raises:
        HTTP_401_UNAUTHORIZED if decoded token doesn't match any User entry
        HTTP_401_UNAUTHORIZED if decoded token is expired
        HTTP_424_FAILED_DEPENDENCY if password reset was unsuccessful
    """
    credentials_exception = HTTPException(
        status_code=401,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        # Decodes token
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id: str = payload.get("user_id")
        expire = payload.get("expire")
        if user_id is None or expire is None:
            raise credentials_exception
    except JWTError as e:
        raise credentials_exception from e

    # Check token expiration
    if str(datetime.now(timezone.utc)) > expire:
        raise HTTPException(
            status_code=401,
            detail="Token expired or invalid!",
        )

    # Fetches associated user from db
    user = await User.get_or_none(id=user_id)

    if not user:
        raise HTTPException(
            detail="User not found or does not exist",
            status_code=status.HTTP_401_UNAUTHORIZED,
        )
    new_hashed_password = pwd_context.hash(data.password)
    pwd_reset = await User.get(id=user.id).update(
        hashed_password=new_hashed_password
    )

    if not pwd_reset:
        raise HTTPException(
            detail="Password reset unsuccessful",
            status_code=status.HTTP_424_FAILED_DEPENDENCY,
        )
    return {"message": "Password reset successful"}



@router.post(
    "/estate/register/",
    response_model= EstatePublic,
    name="auth:estate-registration",
    status_code=status.HTTP_201_CREATED,
)
async def estate_registration(data: EstateCreate):
    """Creates a new estate

    Registers an estate admin object during estate registration
    Returns user details when successfully registered
    Args:
        data- a pydantic schema that defines the estate registration params
    Returns:
        HTTP_201_CREATED- (estate details as defined in the response model)
    Raises:
        HTTP_424_FAILED_DEPENDENCY- if failure to create an estate instance
        HTTP_400_BAD_REQUEST- if email or estate name exists
    """

    estate_email = data.email
    # verify that estate-admin email is unique
    verify_email_exist = await User.filter(email=estate_email).exists()
    if verify_email_exist:
        raise HTTPException(
            detail = "User with this email already exist",
            status_code = status.HTTP_400_BAD_REQUEST,
        )
    # verify that estate name is unique
    verify_estate_name_exist = await Estate.filter(
        estate_name=data.estate_name
        ).exists()
    if verify_estate_name_exist:
        raise HTTPException(
            detail = "User with this email already exist",
            status_code = status.HTTP_400_BAD_REQUEST,
        )
    estate_password = data.password
    hashed_password = pwd_context.hash(estate_password)
    # create estate agent as a user object to permit authentication
    estate_admin_create = await User.create(
        email=estate_email, 
        hashed_password=hashed_password, 
        is_admin=True
    )
    estate_create = await Estate.create(**data.dict(
        exclude_unset=True, exclude={"estate_email","estate_password"}
        ), member=estate_admin_create)
    if not estate_admin_create and not estate_create:
        raise HTTPException(
            detail="Estate registration is unsuccessful",
            status_code=status.HTTP_424_FAILED_DEPENDENCY,
            )
    return estate_create
