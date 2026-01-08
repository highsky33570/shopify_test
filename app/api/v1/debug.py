from fastapi import APIRouter, HTTPException
from app.config import settings
import os

router = APIRouter()


@router.get("/env-check")
async def check_environment_variables():
    """
    Debug endpoint to check if environment variables are set
    DO NOT USE IN PRODUCTION - Remove or protect this endpoint
    """
    # Check raw environment variables
    raw_supabase_url = os.getenv("SUPABASE_URL", "NOT_SET")
    raw_supabase_key = os.getenv("SUPABASE_KEY", "NOT_SET")
    
    # Check settings
    settings_url = settings.SUPABASE_URL
    settings_key = settings.SUPABASE_KEY[:20] + "..." if settings.SUPABASE_KEY else "NOT_SET"
    
    # Validate
    is_valid, error_msg = settings.validate_supabase_config()
    
    return {
        "environment_variables_status": {
            "SUPABASE_URL": {
                "raw_os_getenv": "SET" if raw_supabase_url != "NOT_SET" else "NOT_SET",
                "raw_value_length": len(raw_supabase_url) if raw_supabase_url != "NOT_SET" else 0,
                "settings_value": "SET" if settings_url else "NOT_SET",
                "settings_value_length": len(settings_url) if settings_url else 0,
            },
            "SUPABASE_KEY": {
                "raw_os_getenv": "SET" if raw_supabase_key != "NOT_SET" else "NOT_SET",
                "raw_value_length": len(raw_supabase_key) if raw_supabase_key != "NOT_SET" else 0,
                "settings_value": "SET" if settings.SUPABASE_KEY else "NOT_SET",
                "settings_value_length": len(settings.SUPABASE_KEY) if settings.SUPABASE_KEY else 0,
            }
        },
        "validation": {
            "is_valid": is_valid,
            "error_message": error_msg if not is_valid else None
        },
        "all_env_vars": {
            "SUPABASE_URL": raw_supabase_url[:50] + "..." if len(raw_supabase_url) > 50 else raw_supabase_url,
            "SUPABASE_KEY": raw_supabase_key[:20] + "..." if len(raw_supabase_key) > 20 else raw_supabase_key,
        }
    }
