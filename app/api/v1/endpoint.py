from fastapi import APIRouter

router = APIRouter()


@router.get("/endpoint")
def get_endpoint():
    """API v1 endpoint example"""
    return {
        "message": "This is the API v1 endpoint",
        "version": "1.0.0",
        "status": "active"
    }
