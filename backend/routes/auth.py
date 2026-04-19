from fastapi import APIRouter, Depends
from fastapi.security import OAuth2PasswordRequestForm
from pydantic import BaseModel, EmailStr

from services.auth_service import register_user, login_user, get_all_users
from auth.dependencies import get_current_user, require_role

router = APIRouter()


class RegisterRequest(BaseModel):
    username: str
    email: str
    password: str
    role: str = "analyst"


class LoginRequest(BaseModel):
    email: str
    password: str


@router.post("/register")
async def register(req: RegisterRequest):
    return await register_user(req.username, req.email, req.password, req.role)


@router.post("/login")
async def login(req: LoginRequest):
    return await login_user(req.email, req.password)


# OAuth2 form-compatible login (used by FastAPI Swagger UI)
@router.post("/token")
async def login_form(form: OAuth2PasswordRequestForm = Depends()):
    # form.username holds email in our system
    return await login_user(form.username, form.password)


@router.get("/me")
async def get_me(current_user: dict = Depends(get_current_user)):
    current_user.pop("hashed_password", None)
    return current_user


@router.get("/users", dependencies=[Depends(require_role("admin"))])
async def list_users():
    return await get_all_users()
