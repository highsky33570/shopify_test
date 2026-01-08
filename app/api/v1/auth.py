from typing import Optional
from fastapi import APIRouter, HTTPException, status, Depends, Form
from pydantic import BaseModel, EmailStr
from supabase import create_client, Client
from app.config import settings
from app.dependencies import get_current_user

router = APIRouter()

# Initialize Supabase client
def get_supabase_client() -> Client:
    """Get Supabase client instance"""
    is_valid, error_msg = settings.validate_supabase_config()
    if not is_valid:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Configuration error: {error_msg}. Please set SUPABASE_URL and SUPABASE_KEY environment variables."
        )
    return create_client(settings.SUPABASE_URL, settings.SUPABASE_KEY)


# Request/Response Models
class UserRegister(BaseModel):
    email: EmailStr
    password: str
    full_name: Optional[str] = None


class UserLogin(BaseModel):
    email: EmailStr
    password: str


class UserResponse(BaseModel):
    id: str
    email: str
    created_at: str


class AuthResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: dict


@router.post("/register", response_model=AuthResponse, status_code=status.HTTP_201_CREATED)
async def register_user(
    email: EmailStr = Form(...),
    password: str = Form(...),
    full_name: Optional[str] = Form(None)
):
    """
    Register a new user with email and password
    Accepts form data (application/x-www-form-urlencoded)
    """
    try:
        # Create user in Supabase Auth
        supabase = get_supabase_client()
        response = supabase.auth.sign_up({
            "email": email,
            "password": password,
            "options": {
                "data": {
                    "full_name": full_name or ""
                }
            }
        })
        
        if response.user is None:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Failed to create user"
            )
        
        # Build complete response with all available data
        session_data = {}
        if response.session:
            session_data = {
                "access_token": response.session.access_token,
                "refresh_token": response.session.refresh_token if hasattr(response.session, 'refresh_token') else None,
                "expires_in": response.session.expires_in if hasattr(response.session, 'expires_in') else None,
                "expires_at": response.session.expires_at if hasattr(response.session, 'expires_at') else None,
                "token_type": response.session.token_type if hasattr(response.session, 'token_type') else "bearer",
            }
        else:
            session_data = {
                "access_token": "",
                "refresh_token": None,
                "expires_in": None,
                "expires_at": None,
                "token_type": "bearer",
            }
        
        user_data = {
            "id": response.user.id,
            "email": response.user.email,
            "phone": getattr(response.user, 'phone', None),
            "confirmed_at": str(response.user.confirmed_at) if hasattr(response.user, 'confirmed_at') and response.user.confirmed_at else None,
            "email_confirmed_at": str(response.user.email_confirmed_at) if hasattr(response.user, 'email_confirmed_at') and response.user.email_confirmed_at else None,
            "phone_confirmed_at": str(response.user.phone_confirmed_at) if hasattr(response.user, 'phone_confirmed_at') and response.user.phone_confirmed_at else None,
            "last_sign_in_at": str(response.user.last_sign_in_at) if hasattr(response.user, 'last_sign_in_at') and response.user.last_sign_in_at else None,
            "app_metadata": response.user.app_metadata if hasattr(response.user, 'app_metadata') else {},
            "user_metadata": response.user.user_metadata if hasattr(response.user, 'user_metadata') else {},
            "identities": [{
                "id": identity.id,
                "user_id": identity.user_id,
                "identity_data": identity.identity_data if hasattr(identity, 'identity_data') else {},
                "provider": identity.provider,
                "created_at": str(identity.created_at) if hasattr(identity, 'created_at') else None,
                "updated_at": str(identity.updated_at) if hasattr(identity, 'updated_at') else None,
            } for identity in (response.user.identities if hasattr(response.user, 'identities') and response.user.identities else [])],
            "created_at": str(response.user.created_at) if response.user.created_at else None,
            "updated_at": str(response.user.updated_at) if hasattr(response.user, 'updated_at') and response.user.updated_at else None,
            "aud": response.user.aud if hasattr(response.user, 'aud') else None,
            "role": response.user.role if hasattr(response.user, 'role') else None,
        }
        
        return {
            **session_data,
            "user": user_data
        }
    
    except Exception as e:
        error_message = str(e)
        if "already registered" in error_message.lower() or "already exists" in error_message.lower():
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="User with this email already exists"
            )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Registration failed: {error_message}"
        )


@router.post("/login", response_model=AuthResponse)
async def login_user(
    email: EmailStr = Form(...),
    password: str = Form(...)
):
    """
    Login user with email and password
    Accepts form data (application/x-www-form-urlencoded)
    """
    try:
        # Authenticate user with Supabase
        supabase = get_supabase_client()
        response = supabase.auth.sign_in_with_password({
            "email": email,
            "password": password
        })
        
        if response.user is None or response.session is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid email or password"
            )
        
        # Build complete response with all available data
        session_data = {
            "access_token": response.session.access_token,
            "refresh_token": response.session.refresh_token if hasattr(response.session, 'refresh_token') else None,
            "expires_in": response.session.expires_in if hasattr(response.session, 'expires_in') else None,
            "expires_at": response.session.expires_at if hasattr(response.session, 'expires_at') else None,
            "token_type": response.session.token_type if hasattr(response.session, 'token_type') else "bearer",
        }
        
        user_data = {
            "id": response.user.id,
            "email": response.user.email,
            "phone": getattr(response.user, 'phone', None),
            "confirmed_at": str(response.user.confirmed_at) if hasattr(response.user, 'confirmed_at') and response.user.confirmed_at else None,
            "email_confirmed_at": str(response.user.email_confirmed_at) if hasattr(response.user, 'email_confirmed_at') and response.user.email_confirmed_at else None,
            "phone_confirmed_at": str(response.user.phone_confirmed_at) if hasattr(response.user, 'phone_confirmed_at') and response.user.phone_confirmed_at else None,
            "last_sign_in_at": str(response.user.last_sign_in_at) if hasattr(response.user, 'last_sign_in_at') and response.user.last_sign_in_at else None,
            "app_metadata": response.user.app_metadata if hasattr(response.user, 'app_metadata') else {},
            "user_metadata": response.user.user_metadata if hasattr(response.user, 'user_metadata') else {},
            "identities": [{
                "id": identity.id,
                "user_id": identity.user_id,
                "identity_data": identity.identity_data if hasattr(identity, 'identity_data') else {},
                "provider": identity.provider,
                "created_at": str(identity.created_at) if hasattr(identity, 'created_at') else None,
                "updated_at": str(identity.updated_at) if hasattr(identity, 'updated_at') else None,
            } for identity in (response.user.identities if hasattr(response.user, 'identities') and response.user.identities else [])],
            "created_at": str(response.user.created_at) if response.user.created_at else None,
            "updated_at": str(response.user.updated_at) if hasattr(response.user, 'updated_at') and response.user.updated_at else None,
            "aud": response.user.aud if hasattr(response.user, 'aud') else None,
            "role": response.user.role if hasattr(response.user, 'role') else None,
        }
        
        return {
            **session_data,
            "user": user_data
        }
    
    except Exception as e:
        error_message = str(e)
        if "invalid" in error_message.lower() or "wrong" in error_message.lower():
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid email or password"
            )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Login failed: {error_message}"
        )


@router.post("/logout")
async def logout_user():
    """
    Logout the current user
    """
    try:
        supabase = get_supabase_client()
        supabase.auth.sign_out()
        return {"message": "Successfully logged out"}
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Logout failed: {str(e)}"
        )


@router.get("/me")
async def get_current_user_info(current_user: dict = Depends(get_current_user)):
    """
    Get the current authenticated user
    Requires Bearer token in Authorization header
    """
    return current_user
