from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.routers import upload
from app.routers import alerts
from app.routers import ai


app = FastAPI(
    title="AI SOC Analyst",
    description="AI-powered Security Operations Center Copilot",
    version="1.0.0",
)


app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


app.include_router(upload.router)
app.include_router(alerts.router)
app.include_router(ai.router)


@app.get("/")
def root():
    return {
        "message": "Welcome to AI SOC Analyst 🚀"
    }


@app.get("/health")
def health():
    return {
        "status": "Server is running successfully"
    }