from starlette.config import Config
from starlette.datastructures import Secret

config = Config(".env")

cloud_name=config("DATABASE_USER",  cast=Secret)
api_key=config("api_key",  cast=Secret)
api_secret=config("api_secret",  cast=Secret)

TESTING = config("TESTING",  cast=bool, default=False)
DEBUG = config("DEBUG",  cast=bool, default=False)
LIVE = config("LIVEE",  cast=bool, default=False)


DATABASE_USER = config("DATABASE_USER",  cast=Secret)
DATABASE_PASSWORD= config("DATABASE_PASSWORD",  cast=Secret)
DATABASE_HOST = config("DATABASE_HOST",  cast=Secret)
DATABASE_PORT = config("DATABASE_PORT",  cast=Secret)
DATABASE_DB = config("DATABASE_DB",  cast=Secret)
