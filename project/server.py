from fastapi import FastAPI
from library.database.database import create_start_app_handler
from project.routers.auth import router
from project.routers.chat_app import router as routers

def get_application():
    app = FastAPI()

    # connect to database.
    app.add_event_handler("startup", create_start_app_handler(app))
    app.include_router(router)
    app.include_router(routers)
    return app
app = get_application()



