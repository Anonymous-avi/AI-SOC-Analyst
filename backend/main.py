from fastapi import FastAPI
from app.routers import upload

app = FastAPI(
    title="AI SOC Analyst",
    description="AI-powered Security Operations Center Copilot",
    version="1.0.0"
)

app.include_router(upload.router)


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