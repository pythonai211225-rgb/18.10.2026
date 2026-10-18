from pathlib import Path

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

import messages
import users
from database import init_db

STATIC_DIR = Path(__file__).parent / "static"

app = FastAPI(title="Messages API", version="1.5")


@app.on_event("startup")
def startup():
    init_db()


@app.middleware("http")
async def no_cache_frontend(request, call_next):
    response = await call_next(request)
    if request.url.path == "/" or request.url.path.endswith(".html"):
        response.headers["Cache-Control"] = "no-cache"
    return response


app.include_router(users.router)
app.include_router(messages.router)

# Frontend (mounted last so API routes take priority)
app.mount("/", StaticFiles(directory=STATIC_DIR, html=True), name="static")
