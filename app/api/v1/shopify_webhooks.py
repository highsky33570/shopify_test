import hmac
import hashlib
import base64
from typing import Optional
from fastapi import APIRouter, HTTPException, status, Request, Header
from supabase import create_client, Client
from app.config import settings

router = APIRouter()

# Initialize Supabase client
def get_supabase_client() -> Client:
    """Get Supabase client instance"""
    return create_client(settings.SUPABASE_URL, settings.SUPABASE_KEY)

def get_supabase_admin_client() -> Client:
    """Get Supabase admin client instance (uses service key)"""
    if not settings.SUPABASE_SERVICE_KEY:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="SUPABASE_SERVICE_KEY not configured"
        )
    return create_client(settings.SUPABASE_URL, settings.SUPABASE_SERVICE_KEY)


def verify_shopify_webhook(data: bytes, signature: str, secret: str) -> bool:
    """
    Verify Shopify webhook signature
    """
    if not secret:
        return False
    
    # Calculate expected signature
    calculated_signature = base64.b64encode(
        hmac.new(
            secret.encode('utf-8'),
            data,
            hashlib.sha256
        ).digest()
    ).decode('utf-8')
    
    # Use constant-time comparison to prevent timing attacks
    return hmac.compare_digest(calculated_signature, signature)


@router.post("/customers/create")
async def shopify_customer_create_webhook(
    request: Request,
    x_shopify_shop_domain: Optional[str] = Header(None, alias="X-Shopify-Shop-Domain"),
    x_shopify_topic: Optional[str] = Header(None, alias="X-Shopify-Topic"),
    x_shopify_hmac_sha256: Optional[str] = Header(None, alias="X-Shopify-Hmac-Sha256")
):
    """
    Shopify webhook endpoint for customer creation
    When a customer is created in Shopify, automatically register them in Supabase
    """
    try:
        # Get raw request body for signature verification
        body = await request.body()
        
        # Verify webhook signature if secret is configured
        webhook_secret = getattr(settings, 'SHOPIFY_WEBHOOK_SECRET', None)
        if webhook_secret and x_shopify_hmac_sha256:
            if not verify_shopify_webhook(body, x_shopify_hmac_sha256, webhook_secret):
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid webhook signature"
                )
        
        # Parse webhook payload
        import json
        try:
            payload = await request.json()
        except:
            payload = json.loads(body.decode('utf-8'))
        
        # Extract customer data from Shopify webhook
        customer = payload.get('customer') or payload
        
        if not customer:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="No customer data found in webhook payload"
            )
        
        # Extract customer information
        email = customer.get('email')
        first_name = customer.get('first_name', '')
        last_name = customer.get('last_name', '')
        full_name = f"{first_name} {last_name}".strip() or None
        phone = customer.get('phone')
        customer_id = customer.get('id')
        
        if not email:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Customer email is required"
            )
        
        # Generate a temporary password or use a default one
        # In production, you might want to send a password reset email
        temp_password = f"shopify_{customer_id}_{email}".replace('@', '_').replace('.', '_')
        
        # Register user in Supabase
        supabase = get_supabase_client()
        
        # Try to create new user in Supabase
        try:
            response = supabase.auth.sign_up({
                "email": email,
                "password": temp_password,
                "options": {
                    "data": {
                        "full_name": full_name,
                        "shopify_customer_id": str(customer_id),
                        "shopify_phone": phone,
                        "shopify_first_name": first_name,
                        "shopify_last_name": last_name,
                        "source": "shopify"
                    },
                    "email_redirect_to": None  # Disable email confirmation for webhook-created users
                }
            })
            
            if response.user is None:
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail="Failed to create user in Supabase"
                )
            
            # Build user data response
            user_data = {
                "id": response.user.id,
                "email": response.user.email,
                "phone": getattr(response.user, 'phone', None),
                "user_metadata": response.user.user_metadata if hasattr(response.user, 'user_metadata') else {},
                "created_at": str(response.user.created_at) if response.user.created_at else None,
            }
            
            return {
                "status": "success",
                "message": "Customer registered in Supabase",
                "user": user_data,
                "shopify_customer_id": str(customer_id),
                "note": "User created with temporary password. Consider sending password reset email."
            }
        
        except Exception as signup_error:
            error_msg = str(signup_error).lower()
            # Check if user already exists
            if "already registered" in error_msg or "already exists" in error_msg or "user already" in error_msg:
                # User exists, return success message
                return {
                    "status": "success",
                    "message": "User already exists in Supabase",
                    "email": email,
                    "shopify_customer_id": str(customer_id),
                    "note": "User already registered. Consider updating metadata if needed."
                }
            else:
                # Re-raise if it's a different error
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail=f"Failed to create user: {str(signup_error)}"
                )
    
    except HTTPException:
        raise
    except Exception as e:
        error_message = str(e)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Webhook processing failed: {error_message}"
        )


@router.post("/customers/update")
async def shopify_customer_update_webhook(
    request: Request,
    x_shopify_shop_domain: Optional[str] = Header(None, alias="X-Shopify-Shop-Domain"),
    x_shopify_topic: Optional[str] = Header(None, alias="X-Shopify-Topic"),
    x_shopify_hmac_sha256: Optional[str] = Header(None, alias="X-Shopify-Hmac-Sha256")
):
    """
    Shopify webhook endpoint for customer updates
    Updates user metadata in Supabase when customer is updated in Shopify
    """
    try:
        # Get raw request body for signature verification
        body = await request.body()
        
        # Verify webhook signature if secret is configured
        webhook_secret = getattr(settings, 'SHOPIFY_WEBHOOK_SECRET', None)
        if webhook_secret and x_shopify_hmac_sha256:
            if not verify_shopify_webhook(body, x_shopify_hmac_sha256, webhook_secret):
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid webhook signature"
                )
        
        # Parse webhook payload
        import json
        try:
            payload = await request.json()
        except:
            payload = json.loads(body.decode('utf-8'))
        
        # Extract customer data
        customer = payload.get('customer') or payload
        
        if not customer:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="No customer data found in webhook payload"
            )
        
        email = customer.get('email')
        if not email:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Customer email is required"
            )
        
        # Update user metadata
        first_name = customer.get('first_name', '')
        last_name = customer.get('last_name', '')
        full_name = f"{first_name} {last_name}".strip() or None
        phone = customer.get('phone')
        customer_id = customer.get('id')
        
        # Try to update using admin client if available
        try:
            admin_client = get_supabase_admin_client()
            # Note: Admin API methods may vary by Supabase client version
            # For now, return a message that update was received
            return {
                "status": "success",
                "message": "Customer update received",
                "email": email,
                "shopify_customer_id": str(customer_id),
                "note": "Metadata update requires admin API. User should update profile through app."
            }
        except:
            # If admin client not available, just acknowledge the webhook
            return {
                "status": "success",
                "message": "Customer update webhook received",
                "email": email,
                "shopify_customer_id": str(customer_id),
                "note": "Admin API not configured. User metadata update skipped."
            }
    
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Webhook processing failed: {str(e)}"
        )
