from fastapi import APIRouter
from fastapi.responses import HTMLResponse

router = APIRouter()

@router.get("/")
async def root():
    return {"message": "XWAN AI API", "version": "1.0.0"}


@router.get("/health")
async def health():
    return {"status": "healthy"}