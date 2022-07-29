from asyncio.log import logger
import logging
from typing import Callable
from fastapi import FastAPI
from tortoise import Tortoise
from tortoise.contrib.fastapi import register_tortoise

from Authentication.config import (
    DATABASE_PASSWORD,
    DATABASE_DB,
    DATABASE_HOST,
    DATABASE_PORT,
    DATABASE_USER
)

logger = logging.getLogger(__name__)

MODELS = ["models", "aerich.models"]

TORTOISE_ORM = {
    "connections": {
        "default": {
            "engine": "tortoise.backends.asyncpg",
            "credentials": {
                "host": f"{DATABASE_HOST}",
                "port": f"{DATABASE_PORT}",
                "user": f"{DATABASE_USER}",
                "password": f"{DATABASE_PASSWORD}",
                "database": f"{DATABASE_DB}",
            },
        },
    },
    "apps": {
        "models": {
            "models": MODELS,
            "default_connection": "default",
        }
    },
}

async def init_db(app: FastAPI) -> None:
    try:
        register_tortoise(
            app,
            db_url=f"postgres://{DATABASE_USER}:{DATABASE_PASSWORD}@{DATABASE_HOST}:{DATABASE_PORT}/{DATABASE_DB}",
            modules={"models": MODELS},
            generate_schemas=True,
            add_exception_handlers=True
        )
        logger.warning("---DB CONNECTION WAS SUCCESSFUL ---")
    except Exception as e:
        logger.warning("--- DB CONNECTION ERROR ---")
        logger.warning(e)
        logger.warning("--- DB CONNECTION ERROR ---")


def create_start_app_handler(app: FastAPI) -> Callable:
    async def start_app() -> None:
        await init_db(app)
    return start_app