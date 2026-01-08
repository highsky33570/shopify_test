from fastapi import FastAPI

app = FastAPI(
    title="Vercel + FastAPI",
    description="Vercel + FastAPI",
    version="1.0.0",
)

# Import and include routers
from app.api import api_router
from app.routes import router as routes_router

app.include_router(api_router)
app.include_router(routes_router)
