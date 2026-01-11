import os
from typing import Optional
from dotenv import load_dotenv

# Load .env file for local development only
# On Vercel/production, environment variables are injected directly by the platform
# load_dotenv() will silently do nothing if .env doesn't exist (which is fine)
load_dotenv()


class Settings:
    """Application settings loaded from environment variables"""
    
    # Supabase Configuration
    SUPABASE_URL: str = os.getenv("SUPABASE_URL", "").strip()
    SUPABASE_KEY: str = os.getenv("SUPABASE_KEY", "").strip()
    SUPABASE_SERVICE_KEY: Optional[str] = os.getenv("SUPABASE_SERVICE_KEY", "").strip() or None
    
    # JWT Settings (if needed for custom token handling)
    SECRET_KEY: str = os.getenv("SECRET_KEY", "your-secret-key-change-in-production")
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    
    # Shopify Webhook Configuration
    SHOPIFY_WEBHOOK_SECRET: Optional[str] = os.getenv("SHOPIFY_WEBHOOK_SECRET", "").strip() or None
    
    # Shopify SSO Configuration
    SHOPIFY_SSO_SECRET: str = os.getenv("SHOPIFY_SSO_SECRET", "").strip()
    TOKEN_EXPIRY_MINUTES: int = int(os.getenv("TOKEN_EXPIRY_MINUTES", "15"))
    
    def validate_supabase_config(self) -> tuple[bool, str]:
        """Validate that required Supabase configuration is present"""
        if not self.SUPABASE_URL:
            return False, "SUPABASE_URL environment variable is not set"
        if not self.SUPABASE_KEY:
            return False, "SUPABASE_KEY environment variable is not set"
        return True, ""


settings = Settings()
