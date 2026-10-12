
from contextlib import asynccontextmanager
from pathlib import Path
import json
import sqlite3
from datetime import datetime, timezone
from uuid import uuid4

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "brandshield.db"


def connect_db():
    db = sqlite3.connect(DB_PATH)
    db.row_factory = sqlite3.Row
    return db


def initialize_db():
    with connect_db() as db:
        db.executescript("""
            CREATE TABLE IF NOT EXISTS brands (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                domain TEXT DEFAULT '',
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS threats (
                id TEXT PRIMARY KEY,
                brand_id TEXT,
                brand_name TEXT NOT NULL,
                type TEXT NOT NULL,
                severity TEXT NOT NULL,
                status TEXT NOT NULL,
                description TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
        """)


@asynccontextmanager
async def lifespan(app: FastAPI):
    initialize_db()
    yield


app = FastAPI(
    title="BrandShield AI API",
    version="1.0.0",
    lifespan=lifespan,
)

# Local development only. Restrict origins in production.
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://127.0.0.1:5500",
        "http://localhost:5500",
        "http://127.0.0.1:5501",
        "http://localhost:5501",
    ],
    allow_credentials=False,
    allow_methods=["GET", "POST", "PATCH", "DELETE"],
    allow_headers=["Content-Type"],
)


class BrandInput(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    domain: str = Field(default="", max_length=255)


class AnalyzeInput(BaseModel):
    brand_name: str = Field(min_length=1, max_length=100)


class StatusInput(BaseModel):
    status: str


def now():
    return datetime.now(timezone.utc).isoformat()


def row_dict(row):
    return dict(row) if row else None


@app.get("/")
def home():
    return {
        "name": "BrandShield AI",
        "status": "running",
        "mode": "mock"
    }


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/analyze")
def analyze(data: AnalyzeInput):
    name = data.brand_name.strip()
    if not name:
        raise HTTPException(400, "Brand name cannot be empty.")

    # These findings are demonstrations, not actual detections.
    return {
        "success": True,
        "brand_name": name,
        "analysis_type": "mock",
        "risk_level": "Medium",
        "risk_score": 42,
        "findings": [
            {
                "type": "Impersonation monitoring",
                "severity": "Medium",
                "status": "Needs review",
                "description": "Simulated finding; no profile was scanned."
            },
            {
                "type": "Suspicious profile activity",
                "severity": "Low",
                "status": "Unverified",
                "description": "No real social platform data was checked."
            },
            {
                "type": "Mobile app risk",
                "severity": "Low",
                "status": "Not scanned",
                "description": "No application was analyzed."
            }
        ],
        "recommendation": (
            "Connect authorized data sources before making "
            "real security decisions."
        ),
        "disclaimer": "Mock data only. No real threats were verified."
    }


@app.get("/brands")
def list_brands():
    with connect_db() as db:
        rows = db.execute(
            "SELECT * FROM brands ORDER BY created_at DESC"
        ).fetchall()
    return {"items": [row_dict(r) for r in rows]}


@app.post("/brands", status_code=201)
def add_brand(data: BrandInput):
    name = data.name.strip()
    domain = data.domain.strip()

    if not name:
        raise HTTPException(400, "Brand name cannot be empty.")

    brand_id = str(uuid4())
    created = now()

    with connect_db() as db:
        db.execute(
            """INSERT INTO brands (id, name, domain, created_at)
               VALUES (?, ?, ?, ?)""",
            (brand_id, name, domain, created),
        )

    return {
        "id": brand_id,
        "name": name,
        "domain": domain,
        "created_at": created,
    }


@app.delete("/brands/{brand_id}")
def delete_brand(brand_id: str):
    with connect_db() as db:
        cursor = db.execute(
            "DELETE FROM brands WHERE id = ?", (brand_id,)
        )
    if cursor.rowcount == 0:
        raise HTTPException(404, "Brand not found.")
    return {"success": True, "deleted_id": brand_id}


@app.get("/threats")
def list_threats():
    with connect_db() as db:
        rows = db.execute(
            "SELECT * FROM threats ORDER BY created_at DESC"
        ).fetchall()
    return {"items": [row_dict(r) for r in rows]}


@app.post("/threats/demo", status_code=201)
def create_demo_threat():
    """Create one explicitly simulated finding for dashboard testing."""
    threat_id = str(uuid4())
    created = now()

    with connect_db() as db:
        db.execute(
            """INSERT INTO threats
               (id, brand_id, brand_name, type, severity, status,
                description, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                threat_id, None, "Example Brand",
                "Demo impersonation alert", "Medium", "Open",
                "Simulated record; no real threat was detected.",
                created,
            ),
        )
        row = db.execute(
            "SELECT * FROM threats WHERE id = ?", (threat_id,)
        ).fetchone()

    return row_dict(row)


@app.patch("/threats/{threat_id}")
def update_threat(threat_id: str, data: StatusInput):
    allowed = {"Open", "Investigating", "Resolved"}
    if data.status not in allowed:
        raise HTTPException(
            400, f"Status must be one of: {', '.join(sorted(allowed))}"
        )

    with connect_db() as db:
        cursor = db.execute(
            "UPDATE threats SET status = ? WHERE id = ?",
            (data.status, threat_id),
        )
        row = db.execute(
            "SELECT * FROM threats WHERE id = ?", (threat_id,)
        ).fetchone()

    if cursor.rowcount == 0:
        raise HTTPException(404, "Threat not found.")

    return row_dict(row)


@app.get("/reports")
def reports():
    with connect_db() as db:
        brands = db.execute(
            "SELECT COUNT(*) AS total FROM brands"
        ).fetchone()["total"]

        threats = db.execute(
            "SELECT COUNT(*) AS total FROM threats"
        ).fetchone()["total"]

        open_threats = db.execute(
            "SELECT COUNT(*) AS total FROM threats WHERE status != 'Resolved'"
        ).fetchone()["total"]

        by_severity = db.execute(
            """SELECT severity, COUNT(*) AS total
               FROM threats GROUP BY severity"""
        ).fetchall()

    return {
        "generated_at": now(),
        "analysis_mode": "mock",
        "total_brands": brands,
        "total_findings": threats,
        "unresolved_findings": open_threats,
        "findings_by_severity": [
            row_dict(r) for r in by_severity
        ],
        "disclaimer": "Statistics describe stored demo records only."
    }