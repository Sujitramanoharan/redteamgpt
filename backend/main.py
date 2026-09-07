"""RedTeamGPT FastAPI backend."""
import sys
from pathlib import Path
sys.path.append(str(Path(__file__).parent.parent / "src"))

from fastapi import FastAPI
from fastapi.responses import FileResponse
from pydantic import BaseModel

from firewall import detect

app = FastAPI(title="RedTeamGPT")
FRONTEND = Path(__file__).parent.parent / "frontend"


class PromptRequest(BaseModel):
    prompt: str


@app.post("/api/check")
def check(req: PromptRequest):
    return detect(req.prompt)


@app.get("/")
def home():
    return FileResponse(FRONTEND / "index.html")

@app.get("/index.html")
def index_page():
    return FileResponse(FRONTEND / "index.html")

@app.get("/about.html")
def about_page():
    return FileResponse(FRONTEND / "about.html")

@app.get("/style.css")
def css():
    return FileResponse(FRONTEND / "style.css")

@app.get("/script.js")
def js():
    return FileResponse(FRONTEND / "script.js")
