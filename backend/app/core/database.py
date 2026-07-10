import os

from pymongo import MongoClient
from pymongo.database import Database


MONGODB_URL = os.getenv(
    "MONGODB_URL",
    "mongodb://localhost:27017",
)

DATABASE_NAME = os.getenv(
    "DATABASE_NAME",
    "ai_soc_analyst",
)


client = MongoClient(
    MONGODB_URL,
    serverSelectionTimeoutMS=5000,
)


def get_database() -> Database:
    return client[DATABASE_NAME]


def check_database_connection() -> bool:
    try:
        client.admin.command("ping")
        return True
    except Exception:
        return False