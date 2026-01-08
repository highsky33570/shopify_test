from fastapi import APIRouter
from app.api.v1.endpoint import router as endpoint_router
from app.api.v1.auth import router as auth_router
from app.api.v1.shopify_webhooks import router as shopify_webhooks_router
from app.api.v1.debug import router as debug_router

router = APIRouter(prefix="/v1", tags=["v1"])

# Include all v1 endpoint routers
router.include_router(endpoint_router)
router.include_router(auth_router, prefix="/auth", tags=["authentication"])
router.include_router(shopify_webhooks_router, prefix="/webhooks/shopify", tags=["shopify-webhooks"])
router.include_router(debug_router, prefix="/debug", tags=["debug"])