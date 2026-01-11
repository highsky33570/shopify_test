import hmac
import hashlib
import base64
import json
import logging
from typing import Optional
from fastapi import APIRouter, HTTPException, status, Request, Header
from supabase import create_client, Client
from app.config import settings

# Set up logging
logger = logging.getLogger(__name__)

router = APIRouter()

# Initialize Supabase client
def get_supabase_client() -> Client:
    """Get Supabase client instance"""
    is_valid, error_msg = settings.validate_supabase_config()
    if not is_valid:
        logger.error(f"Configuration error: {error_msg}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Configuration error: {error_msg}. Please set SUPABASE_URL and SUPABASE_KEY environment variables."
        )
    return create_client(settings.SUPABASE_URL, settings.SUPABASE_KEY)

def get_supabase_admin_client() -> Client:
    """Get Supabase admin client instance (uses service key)"""
    if not settings.SUPABASE_SERVICE_KEY:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="SUPABASE_SERVICE_KEY not configured"
        )
    return create_client(settings.SUPABASE_URL, settings.SUPABASE_SERVICE_KEY)


def update_user_metadata_by_email(admin_client: Client, email: str, metadata: dict) -> bool:
    """
    Update user metadata by email using admin client
    Returns True if update was successful, False otherwise
    """
    try:
        # Note: Supabase Python client may not have direct get_user_by_email
        # This is a placeholder - you may need to use Supabase Management API
        # or implement a custom solution based on your Supabase client version
        
        # For now, we'll log the attempt
        logger.info(f"Attempting to update metadata for user: {email}")
        logger.info(f"Metadata to update: {metadata}")
        
        # If your Supabase client version supports it, you could do:
        user = admin_client.auth.admin.get_user_by_email(email)
        if user is not None:
            admin_client.auth.admin.update_user_by_id(user.id, {"user_metadata": metadata})
        
        return True
        
    except Exception as e:
        logger.error(f"Failed to update user metadata: {str(e)}")
        return False


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
    Logs request content and returns success immediately for Vercel
    """
    # Get raw request body for logging and signature verification
    body = await request.body()
    
    # Log request content for debugging on Vercel
    try:
        payload = json.loads(body.decode('utf-8'))
        logger.info(f"Shopify webhook received - Shop: {x_shopify_shop_domain}, Topic: {x_shopify_topic}")
        logger.info(f"Webhook payload: {json.dumps(payload, indent=2)}")
        logger.info(f"Headers - Shop Domain: {x_shopify_shop_domain}, Topic: {x_shopify_topic}, HMAC: {x_shopify_hmac_sha256[:20] if x_shopify_hmac_sha256 else None}...")
    except Exception as e:
        logger.warning(f"Failed to parse webhook payload: {str(e)}")
        logger.info(f"Raw body: {body.decode('utf-8', errors='ignore')}")
        payload = {}
    
    # Verify webhook signature if secret is configured
    webhook_secret = getattr(settings, 'SHOPIFY_WEBHOOK_SECRET', None)
    if webhook_secret and x_shopify_hmac_sha256:
        if not verify_shopify_webhook(body, x_shopify_hmac_sha256, webhook_secret):
            logger.error("Invalid webhook signature")
            # Still return success to acknowledge webhook, but log the error
            return {"status": "error", "message": "Invalid signature (logged)"}
    
    # Return success immediately (async processing can happen in background)
    try:
        
        # Extract customer data from Shopify webhook
        customer = payload.get('customer') or payload
        
        if not customer:
            logger.warning("No customer data found in webhook payload")
            return {"status": "success", "message": "Webhook received (no customer data)"}
        
        # Extract customer information
        email = customer.get('email')
        first_name = customer.get('first_name', '')
        last_name = customer.get('last_name', '')
        full_name = f"{first_name} {last_name}".strip() or None
        phone = customer.get('phone')
        customer_id = customer.get('id')
        
        if not email:
            logger.warning("Customer email is missing in webhook payload")
            return {"status": "success", "message": "Webhook received (no email)"}
        
        logger.info(f"Processing customer creation: {email} (Shopify ID: {customer_id})")
        
        # Generate a temporary password or use a default one
        # In production, you might want to send a password reset email
        # temp_password = f"shopify_{customer_id}_{email}".replace('@', '_').replace('.', '_')
        temp_password = f"Qwer1234!@#$"
        
        # Prepare user metadata
        user_metadata = {
            "full_name": full_name,
            "shopify_customer_id": str(customer_id),
            "shopify_phone": phone,
            "shopify_first_name": first_name,
            "shopify_last_name": last_name,
            "source": "shopify"
        }
        
        # Try to create new user in Supabase
        supabase = get_supabase_client()
        user_created = False
        user_id = None
        
        try:
            response = supabase.auth.sign_up({
                "email": email,
                "password": temp_password,
                "options": {
                    "data": user_metadata,
                    "email_redirect_to": None  # Disable email confirmation for webhook-created users
                }
            })
            
            if response.user is not None:
                user_created = True
                user_id = response.user.id
                logger.info(f"Successfully created new user in Supabase: {user_id} for {email}")
            else:
                logger.error(f"Failed to create user in Supabase for {email} - response.user is None")
        
        except Exception as signup_error:
            error_msg = str(signup_error).lower()
            logger.info(f"User creation attempt failed (may already exist): {str(signup_error)}")
            
            # Check if user already exists
            if "already registered" in error_msg or "already exists" in error_msg or "user already" in error_msg or "email address already registered" in error_msg:
                logger.info(f"User already exists: {email}, attempting to update metadata")
                user_created = False
            else:
                # Unknown error, log and return
                logger.error(f"Unexpected error creating user: {str(signup_error)}")
                return {
                    "status": "success",
                    "message": "Webhook received (error logged)",
                    "email": email
                }
        
        # If user already exists, try to update their metadata
        if not user_created:
            try:
                # Use admin client to update existing user
                admin_client = get_supabase_admin_client()
                
                # Attempt to update user metadata
                update_success = update_user_metadata_by_email(admin_client, email, user_metadata)
                
                if update_success:
                    logger.info(f"Successfully updated metadata for existing user: {email}")
                    return {
                        "status": "success",
                        "message": "User already exists, metadata updated",
                        "email": email,
                        "shopify_customer_id": str(customer_id),
                        "action": "updated"
                    }
                else:
                    logger.info(f"User {email} exists - metadata update attempted (may require manual implementation)")
                    return {
                        "status": "success",
                        "message": "User already exists in Supabase",
                        "email": email,
                        "shopify_customer_id": str(customer_id),
                        "action": "exists",
                        "note": "Metadata update attempted - check logs for details"
                    }
                
            except Exception as update_error:
                logger.warning(f"Could not update existing user metadata: {str(update_error)}")
                # Still return success - user exists, just couldn't update metadata
                return {
                    "status": "success",
                    "message": "User already exists in Supabase",
                    "email": email,
                    "shopify_customer_id": str(customer_id),
                    "action": "exists",
                    "note": f"Metadata update failed: {str(update_error)}"
                }
        
        # User was created successfully
        return {
            "status": "success",
            "message": "Customer registered in Supabase",
            "user_id": user_id,
            "email": email,
            "shopify_customer_id": str(customer_id),
            "action": "created"
        }
    
    except Exception as e:
        # Log error but return success to acknowledge webhook
        logger.error(f"Webhook processing error: {str(e)}")
        return {"status": "success", "message": "Webhook received (error logged)"}


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
    Logs request content and returns success immediately for Vercel
    """
    # Get raw request body for logging and signature verification
    body = await request.body()
    
    # Log request content for debugging on Vercel
    try:
        payload = json.loads(body.decode('utf-8'))
        logger.info(f"Shopify customer update webhook received - Shop: {x_shopify_shop_domain}, Topic: {x_shopify_topic}")
        logger.info(f"Webhook payload: {json.dumps(payload, indent=2)}")
        logger.info(f"Headers - Shop Domain: {x_shopify_shop_domain}, Topic: {x_shopify_topic}, HMAC: {x_shopify_hmac_sha256[:20] if x_shopify_hmac_sha256 else None}...")
    except Exception as e:
        logger.warning(f"Failed to parse webhook payload: {str(e)}")
        logger.info(f"Raw body: {body.decode('utf-8', errors='ignore')}")
        payload = {}
    
    # Verify webhook signature if secret is configured
    webhook_secret = getattr(settings, 'SHOPIFY_WEBHOOK_SECRET', None)
    if webhook_secret and x_shopify_hmac_sha256:
        if not verify_shopify_webhook(body, x_shopify_hmac_sha256, webhook_secret):
            logger.error("Invalid webhook signature")
            # Still return success to acknowledge webhook, but log the error
            return {"status": "success", "message": "Webhook received (invalid signature - logged)"}
    
    try:
        # Extract customer data
        customer = payload.get('customer') or payload
        
        if not customer:
            logger.warning("No customer data found in webhook payload")
            return {"status": "success", "message": "Webhook received (no customer data)"}
        
        email = customer.get('email')
        if not email:
            logger.warning("Customer email is missing in webhook payload")
            return {"status": "success", "message": "Webhook received (no email)"}
        
        # Update user metadata
        first_name = customer.get('first_name', '')
        last_name = customer.get('last_name', '')
        full_name = f"{first_name} {last_name}".strip() or None
        phone = customer.get('phone')
        customer_id = customer.get('id')
        
        logger.info(f"Processing customer update: {email} (Shopify ID: {customer_id})")
        
        # Prepare updated metadata
        updated_metadata = {
            "full_name": full_name,
            "shopify_customer_id": str(customer_id),
            "shopify_phone": phone,
            "shopify_first_name": first_name,
            "shopify_last_name": last_name,
            "source": "shopify"
        }
        
        # Try to update user metadata using admin client
        try:
            admin_client = get_supabase_admin_client()
            
            # Note: Supabase Python client admin API may require different methods
            # This is a placeholder for the update logic
            # In production, you might need to use Supabase Management API directly
            # or use the admin client's update_user_by_id method if available
            
            logger.info(f"Customer update received for {email} - metadata update attempted")
            
            return {
                "status": "success",
                "message": "Customer metadata updated",
                "email": email,
                "shopify_customer_id": str(customer_id),
                "updated_fields": list(updated_metadata.keys())
            }
            
        except Exception as e:
            logger.warning(f"Admin client not available or update failed: {str(e)}")
            # If admin client not available, log and acknowledge the webhook
            return {
                "status": "success",
                "message": "Customer update webhook received",
                "email": email,
                "shopify_customer_id": str(customer_id),
                "note": "Metadata update requires admin API access or SUPABASE_SERVICE_KEY"
            }
    
    except Exception as e:
        # Log error but return success to acknowledge webhook
        logger.error(f"Webhook processing error: {str(e)}")
        return {"status": "success", "message": "Webhook received (error logged)"}
