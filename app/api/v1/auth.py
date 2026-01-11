import base64
import hashlib
import hmac
import json
import logging
import secrets
from typing import Optional, Dict
from datetime import datetime
from fastapi import APIRouter, HTTPException, Query, Request, status, Depends, Form, RedirectResponse
from pydantic import BaseModel, EmailStr
from supabase import create_client, Client
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
from app.config import settings
from app.dependencies import get_current_user

# Set up logging
logger = logging.getLogger(__name__)

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
    
    except HTTPException as http_ex:
        # Re-raise HTTP exceptions (like configuration errors)
        raise http_ex
    except Exception as e:
        error_message = str(e)
        # Check if it's a configuration error
        if "configuration error" in error_message.lower() or "supabase_url" in error_message.lower() or "supabase_key" in error_message.lower():
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Server configuration error: {error_message}. Please check Vercel environment variables."
            )
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
    
    except HTTPException as http_ex:
        # Re-raise HTTP exceptions (like configuration errors)
        raise http_ex
    except Exception as e:
        error_message = str(e)
        # Check if it's a configuration error
        if "configuration error" in error_message.lower() or "supabase_url" in error_message.lower() or "supabase_key" in error_message.lower():
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Server configuration error: {error_message}. Please check Vercel environment variables."
            )
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


def validate_shopify_sso_token(token: str) -> Optional[Dict]:
    """Validate and decrypt SSO token from Shopify"""
    if not settings.SHOPIFY_SSO_SECRET:
        raise ValueError("SHOPIFY_SSO_SECRET environment variable is required")

    try:
        # Decode base64
        token_data = base64.urlsafe_b64decode(token)

        # Derive keys
        key_material = hashlib.sha256(settings.SHOPIFY_SSO_SECRET.encode()).digest()
        encryption_key = key_material[:16]
        signature_key = key_material[16:32]

        # Extract signature (last 32 bytes) and encrypted data
        signature = token_data[-32:]
        encrypted_data = token_data[:-32]

        # Verify signature
        expected_signature = hmac.new(
            signature_key, encrypted_data, hashlib.sha256
        ).digest()

        if not hmac.compare_digest(signature, expected_signature):
            return None

        # Extract IV (first 16 bytes) and ciphertext
        iv = encrypted_data[:16]
        ciphertext = encrypted_data[16:]

        # Decrypt
        cipher = Cipher(
            algorithms.AES(encryption_key), modes.CBC(iv), backend=default_backend()
        )
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(ciphertext) + decryptor.final()

        # Remove PKCS7 padding
        unpadder = padding.PKCS7(128).unpadder()
        plaintext = unpadder.update(plaintext) + unpadder.final()

        customer_data = json.loads(plaintext.decode("utf-8"))

        # Check expiry
        created_at = datetime.fromisoformat(customer_data["created_at"].replace('Z', '+00:00'))
        now = datetime.utcnow().replace(tzinfo=created_at.tzinfo)
        diff_minutes = (now - created_at).total_seconds() / 60

        if diff_minutes > settings.TOKEN_EXPIRY_MINUTES:
            return None

        return customer_data

    except Exception as e:
        logger.error(f"Token validation error: {e}")
        return None


@router.get("/shopify-callback")
async def shopify_callback_v1(
    request: Request,
    email: EmailStr = Query(..., description="Customer email from Shopify"),
    shop: str = Query(..., description="Shop domain from Shopify"),
    customer_id: str = Query(..., description="Customer ID from Shopify"),
    first_name: str = Query("", description="Customer first name"),
    last_name: str = Query("", description="Customer last name"),
    return_to: str = Query("/dashboard", description="Return URL after authentication"),
):
    """
    Shopify SSO callback endpoint
    Accepts customer parameters directly and creates/updates user in Supabase
    """
    try:
        # Process customer information from query parameters
        shop_domain = shop
        full_name = f"{first_name} {last_name}".strip() or None
        
        if not email:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Email is required"
            )
        
        logger.info(f"Shopify SSO callback for: {email} (Shop: {shop_domain}, Customer ID: {customer_id})")
        
        # Get Supabase client
        supabase = get_supabase_client()
        
        # Prepare user metadata
        user_metadata = {
            "full_name": full_name,
            "shopify_customer_id": str(customer_id) if customer_id else None,
            "shopify_shop_domain": shop_domain,
            "shopify_first_name": first_name,
            "shopify_last_name": last_name,
            "source": "shopify_sso"
        }
        
        # Use a consistent password for SSO users
        # This allows us to sign in existing users and create new ones
        temp_password = "Qwer1234!@#$" #secrets.token_urlsafe(32)
        
        user_id = None
        access_token = None
        response = None
        
        # Try to sign in existing user first
        try:
            logger.info(f"Attempting to sign in existing user: {email}")
            response = supabase.auth.sign_in_with_password({
                "email": email,
                "password": temp_password
            })
            
            if response.user and response.session:
                user_id = response.user.id
                access_token = response.session.access_token
                logger.info(f"Successfully signed in existing user via SSO: {user_id}")
                
                # Update user metadata with latest Shopify info
                try:
                    # Note: Updating metadata might require admin API
                    # For now, we'll just log that the user signed in
                    logger.info(f"User {email} signed in - metadata update may be needed")
                except Exception as update_error:
                    logger.warning(f"Could not update metadata: {str(update_error)}")
                    
        except Exception as signin_error:
            error_msg = str(signin_error).lower()
            logger.info(f"Sign in failed (user may not exist): {str(signin_error)}")
            
            # If sign in fails, try to create new user
            try:
                logger.info(f"Attempting to create new user: {email}")
                response = supabase.auth.sign_up({
                    "email": email,
                    "password": temp_password,
                    "options": {
                        "data": user_metadata,
                        "email_redirect_to": None
                    }
                })
                
                if response.user and response.session:
                    user_id = response.user.id
                    access_token = response.session.access_token
                    logger.info(f"Successfully created new user via SSO: {user_id}")
                else:
                    raise HTTPException(
                        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                        detail="Failed to create user session"
                    )
                    
            except Exception as signup_error:
                signup_error_msg = str(signup_error).lower()
                if "already registered" in signup_error_msg or "already exists" in signup_error_msg:
                    # User exists but password doesn't match
                    # This shouldn't happen if we use the same password, but handle it anyway
                    logger.error(f"User {email} exists but password mismatch")
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail=f"User {email} already exists but authentication failed. Please contact support."
                    )
                else:
                    raise HTTPException(
                        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                        detail=f"Failed to create user session: {str(signup_error)}"
                    )
        
        # Redirect with token or session
        # Option 1: Redirect to return_to URL with token in query or cookie
        # Option 2: Return JSON with token for frontend to handle
        
        # For security, you might want to set a secure cookie instead
        redirect_url = f"{return_to}?token={access_token}" if access_token else return_to
        
        # return RedirectResponse(url=redirect_url, status_code=302)
        
        # Alternative: Return JSON response if frontend handles it
        # Build complete user information
        user_info = {}
        if response and response.user:
            user_info = {
                "id": response.user.id,
                "email": response.user.email,
                "phone": getattr(response.user, 'phone', None),
                "confirmed_at": str(response.user.confirmed_at) if hasattr(response.user, 'confirmed_at') and response.user.confirmed_at else None,
                "email_confirmed_at": str(response.user.email_confirmed_at) if hasattr(response.user, 'email_confirmed_at') and response.user.email_confirmed_at else None,
                "phone_confirmed_at": str(response.user.phone_confirmed_at) if hasattr(response.user, 'phone_confirmed_at') and response.user.phone_confirmed_at else None,
                "last_sign_in_at": str(response.user.last_sign_in_at) if hasattr(response.user, 'last_sign_in_at') and response.user.last_sign_in_at else None,
                "app_metadata": response.user.app_metadata if hasattr(response.user, 'app_metadata') else {},
                "user_metadata": response.user.user_metadata if hasattr(response.user, 'user_metadata') else {},
                "created_at": str(response.user.created_at) if response.user.created_at else None,
                "updated_at": str(response.user.updated_at) if hasattr(response.user, 'updated_at') and response.user.updated_at else None,
                "aud": response.user.aud if hasattr(response.user, 'aud') else None,
                "role": response.user.role if hasattr(response.user, 'role') else None,
            }
        else:
            # Fallback if user data not available
            user_info = {
                "id": user_id,
                "email": email,
                "user_metadata": user_metadata
            }
        
        # Build session information
        session_info = {}
        if response and response.session:
            session_info = {
                "access_token": response.session.access_token,
                "refresh_token": response.session.refresh_token if hasattr(response.session, 'refresh_token') else None,
                "expires_in": response.session.expires_in if hasattr(response.session, 'expires_in') else None,
                "expires_at": response.session.expires_at if hasattr(response.session, 'expires_at') else None,
                "token_type": response.session.token_type if hasattr(response.session, 'token_type') else "bearer",
            }
        else:
            session_info = {
                "access_token": access_token,
                "token_type": "bearer"
            }
        
        return {
            "status": "success",
            "message": "Authentication successful",
            "session": session_info,
            "user": user_info,
            "redirect_to": return_to
        }
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Shopify SSO callback error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"SSO authentication failed: {str(e)}"
        )

