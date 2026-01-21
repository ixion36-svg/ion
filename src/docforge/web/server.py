"""FastAPI web server for DocForge."""

import uvicorn
from pathlib import Path
from fastapi import FastAPI, Request
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.responses import HTMLResponse

from docforge.web.api import router as api_router
from docforge.core.config import get_config
from docforge.storage.database import init_db

# Get the directory containing this file
BASE_DIR = Path(__file__).parent

app = FastAPI(
    title="DocForge",
    description="Documentation Template Management System",
    version="0.1.0",
)

# Mount static files
app.mount("/static", StaticFiles(directory=BASE_DIR / "static"), name="static")

# Setup templates
templates = Jinja2Templates(directory=BASE_DIR / "templates")

# Include API routes
app.include_router(api_router, prefix="/api")


@app.on_event("startup")
async def startup_event():
    """Initialize database on startup."""
    config = get_config()
    if not config.db_path.exists():
        config.db_path.parent.mkdir(parents=True, exist_ok=True)
        init_db(config.db_path)


@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    """Render the main dashboard."""
    return templates.TemplateResponse("index.html", {"request": request})


@app.get("/templates", response_class=HTMLResponse)
async def templates_page(request: Request):
    """Render the templates page."""
    return templates.TemplateResponse("templates.html", {"request": request})


@app.get("/templates/new", response_class=HTMLResponse)
async def new_template_page(request: Request):
    """Render the new template page."""
    return templates.TemplateResponse("template_form.html", {"request": request, "template": None})


@app.get("/templates/{template_id}", response_class=HTMLResponse)
async def view_template_page(request: Request, template_id: int):
    """Render the template view page."""
    return templates.TemplateResponse("template_view.html", {"request": request, "template_id": template_id})


@app.get("/templates/{template_id}/edit", response_class=HTMLResponse)
async def edit_template_page(request: Request, template_id: int):
    """Render the template edit page."""
    return templates.TemplateResponse("template_form.html", {"request": request, "template_id": template_id})


@app.get("/templates/{template_id}/render", response_class=HTMLResponse)
async def render_template_page(request: Request, template_id: int):
    """Render the template rendering page."""
    return templates.TemplateResponse("template_render.html", {"request": request, "template_id": template_id})


@app.get("/templates/{template_id}/versions", response_class=HTMLResponse)
async def versions_page(request: Request, template_id: int):
    """Render the versions page."""
    return templates.TemplateResponse("versions.html", {"request": request, "template_id": template_id})


@app.get("/documents", response_class=HTMLResponse)
async def documents_page(request: Request):
    """Render the documents page."""
    return templates.TemplateResponse("documents.html", {"request": request})


@app.get("/extract", response_class=HTMLResponse)
async def extract_page(request: Request):
    """Render the extraction page."""
    return templates.TemplateResponse("extract.html", {"request": request})


# Auth page routes
@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    """Render the login page."""
    return templates.TemplateResponse("login.html", {"request": request})


@app.get("/profile", response_class=HTMLResponse)
async def profile_page(request: Request):
    """Render the user profile page."""
    return templates.TemplateResponse("profile.html", {"request": request})


@app.get("/users", response_class=HTMLResponse)
async def users_page(request: Request):
    """Render the user management page (admin only)."""
    return templates.TemplateResponse("users.html", {"request": request})


@app.get("/audit-logs", response_class=HTMLResponse)
async def audit_logs_page(request: Request):
    """Render the audit logs page (admin only)."""
    return templates.TemplateResponse("audit_logs.html", {"request": request})


def main():
    """Run the web server."""
    import argparse
    parser = argparse.ArgumentParser(description="DocForge Web Server")
    parser.add_argument("--host", default="127.0.0.1", help="Host to bind to")
    parser.add_argument("--port", type=int, default=8000, help="Port to bind to")
    parser.add_argument("--reload", action="store_true", help="Enable auto-reload")
    args = parser.parse_args()

    print(f"Starting DocForge Web UI at http://{args.host}:{args.port}")
    uvicorn.run(
        "docforge.web.server:app",
        host=args.host,
        port=args.port,
        reload=args.reload,
    )


if __name__ == "__main__":
    main()
