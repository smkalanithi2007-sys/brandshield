import asyncio
import ipaddress
import json
import logging
import os
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from typing import Annotated
from urllib.parse import urlsplit

from fastapi import Depends, FastAPI, HTTPException, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, EmailStr, Field
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.orm import Session

from database import SessionLocal, engine, get_db, initialize_database
from models import Brand, Finding, ScanRun, User
from providers import configured_sources, scan_brand
from security import (
    create_access_token,
    decode_access_token,
    hash_password,
    secret_key,
    verify_password,
)

logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"))
logger = logging.getLogger("brandshield")
FRONTEND_DIR = os.path.join(os.path.dirname(__file__), "..", "frontend")
APP_ENV = os.getenv("APP_ENV", "development").lower()
SESSION_COOKIE = "brandshield_session"
SESSION_MAX_AGE = 12 * 60 * 60
DEFAULT_ORIGINS = [
    "http://localhost:5500",
    "http://127.0.0.1:5500",
    "http://localhost:5501",
    "http://127.0.0.1:5501",
]
configured_origins = os.getenv("ALLOWED_ORIGINS")
ALLOWED_ORIGINS = [
    origin.strip()
    for origin in (
        configured_origins.split(",")
        if configured_origins is not None
        else (DEFAULT_ORIGINS if APP_ENV != "production" else [])
    )
    if origin.strip()
]
POLL_SECONDS = int(os.getenv("SCHEDULE_POLL_SECONDS", "60"))
SCHEDULE_BATCH_SIZE = int(os.getenv("SCHEDULE_BATCH_SIZE", "3"))
MAX_BRANDS_PER_USER = 20
ALLOWED_FINDING_STATUSES = {"Needs review", "Investigating", "Resolved"}
limiter = Limiter(key_func=get_remote_address)


class Credentials(BaseModel):
    email: EmailStr
    password: str = Field(min_length=12, max_length=128)


class BrandInput(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    domain: str = Field(default="", max_length=255)
    external_lookup_consent: bool = False
    monitoring_interval_hours: int | None = Field(
        default=None, ge=24, le=168
    )


class ScanInput(BaseModel):
    brand_name: str = Field(min_length=1, max_length=100)
    domain: str = Field(default="", max_length=255)
    external_lookup_consent: bool = False


class ScheduleInput(BaseModel):
    interval_hours: int | None = Field(default=None, ge=24, le=168)
    external_lookup_consent: bool = False


class FindingStatusInput(BaseModel):
    status: str


def normalize_domain(value: str) -> str:
    candidate = value.strip()
    if not candidate:
        return ""

    try:
        parsed = urlsplit(
            candidate if "://" in candidate else f"https://{candidate}"
        )
    except ValueError:
        raise HTTPException(400, "Enter a valid public domain or HTTP(S) URL.")
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise HTTPException(400, "Enter a valid public domain or HTTP(S) URL.")
    if parsed.username or parsed.password:
        raise HTTPException(400, "Domain URLs must not contain credentials.")

    try:
        host = parsed.hostname.encode("idna").decode("ascii").lower().rstrip(".")
        address = ipaddress.ip_address(host)
    except (UnicodeError, ValueError):
        if not parsed.hostname:
            raise HTTPException(400, "Enter a valid public domain name.")
        try:
            host = parsed.hostname.encode("idna").decode("ascii").lower().rstrip(".")
        except UnicodeError:
            raise HTTPException(400, "Enter a valid public domain name.")
        address = None
    if address and not address.is_global:
        raise HTTPException(400, "Private and reserved IP addresses are not allowed.")
    if not address:
        labels = host.split(".")
        if len(host) > 253 or len(labels) < 2 or any(
            not label
            or len(label) > 63
            or label.startswith("-")
            or label.endswith("-")
            or not all(character.isalnum() or character == "-" for character in label)
            for label in labels
        ):
            raise HTTPException(400, "Enter a valid public domain name.")
    return host


def set_session_cookie(response: Response, user_id: int) -> None:
    response.set_cookie(
        SESSION_COOKIE,
        create_access_token(user_id),
        max_age=SESSION_MAX_AGE,
        httponly=True,
        secure=APP_ENV == "production",
        samesite="strict",
        path="/",
    )


def current_user(
    request: Request,
    db: Annotated[Session, Depends(get_db)],
) -> User:
    token = request.cookies.get(SESSION_COOKIE)
    user_id = decode_access_token(token) if token else None
    if user_id is None:
        raise HTTPException(401, "Sign in to continue.")
    user = db.get(User, user_id)
    if user is None:
        raise HTTPException(401, "Sign in to continue.")
    return user


def user_record(user: User) -> dict:
    return {"id": user.id, "email": user.email, "created_at": user.created_at}


def brand_record(brand: Brand) -> dict:
    return {
        "id": brand.id,
        "name": brand.name,
        "domain": brand.domain,
        "external_lookup_consent": brand.external_lookup_consent_at is not None,
        "monitoring_interval_hours": brand.monitoring_interval_hours,
        "next_scan_at": brand.next_scan_at,
        "created_at": brand.created_at,
    }


def finding_record(finding: Finding) -> dict:
    return {
        "id": finding.id,
        "scan_id": finding.scan_id,
        "brand_id": finding.brand_id,
        "source": finding.source,
        "category": finding.category,
        "severity": finding.severity,
        "status": finding.status,
        "title": finding.title,
        "url": finding.url,
        "details": finding.details,
        "created_at": finding.created_at,
    }


def execute_scan(
    db: Session,
    user_id: int,
    brand_name: str,
    domain: str,
    brand_id: int | None = None,
) -> dict:
    findings, provider_results = scan_brand(brand_name, domain)
    scan_status = get_scan_status(provider_results)
    run = ScanRun(
        user_id=user_id,
        brand_id=brand_id,
        brand_name=brand_name,
        domain=domain,
        scan_status=scan_status,
        provider_results=json.dumps(provider_results),
    )
    db.add(run)
    db.flush()

    stored_findings = []
    for item in findings:
        finding = Finding(
            user_id=user_id,
            scan_id=run.id,
            brand_id=brand_id,
            source=item["source"],
            category=item["category"],
            severity=item["severity"],
            title=item["title"],
            url=item["url"],
            details=item["details"],
        )
        db.add(finding)
        stored_findings.append(finding)

    db.commit()
    return {
        "id": run.id,
        "brand_name": run.brand_name,
        "domain": run.domain,
        "scan_status": run.scan_status,
        "provider_results": provider_results,
        "findings": [finding_record(item) for item in stored_findings],
        "created_at": run.created_at,
    }


def get_scan_status(provider_results: list[dict]) -> str:
    provider_statuses = [item["status"] for item in provider_results]
    active_statuses = [
        status for status in provider_statuses
        if status not in {"not_configured", "skipped"}
    ]
    if not active_statuses or all(status == "unavailable" for status in active_statuses):
        return "unavailable"
    if any(status == "unavailable" for status in active_statuses) or any(
        status == "not_configured" for status in provider_statuses
    ):
        return "partial"
    return "completed"


def due_brand_snapshots() -> list[dict]:
    now = datetime.now(timezone.utc)
    with SessionLocal() as db:
        with db.begin():
            brands = db.scalars(
                select(Brand)
                .where(
                    Brand.monitoring_interval_hours.is_not(None),
                    Brand.next_scan_at <= now,
                )
                .order_by(Brand.next_scan_at)
                .limit(SCHEDULE_BATCH_SIZE)
                .with_for_update(skip_locked=True)
            ).all()
            snapshots = []
            for brand in brands:
                interval_hours = brand.monitoring_interval_hours
                if interval_hours is None:
                    continue
                brand.next_scan_at = now + timedelta(
                    hours=interval_hours
                )
                snapshots.append({
                    "id": brand.id,
                    "user_id": brand.user_id,
                    "name": brand.name,
                    "domain": brand.domain,
                })
        return snapshots


def run_scheduled_scans() -> None:
    for brand in due_brand_snapshots():
        with SessionLocal() as db:
            try:
                execute_scan(
                    db,
                    brand["user_id"],
                    brand["name"],
                    brand["domain"],
                    brand["id"],
                )
            except SQLAlchemyError:
                db.rollback()
                logger.exception(
                    "Could not save a scheduled scan for brand id %s",
                    brand["id"],
                )


async def schedule_worker() -> None:
    while True:
        try:
            await asyncio.to_thread(run_scheduled_scans)
        except SQLAlchemyError:
            logger.exception("Could not check scheduled scans")
        await asyncio.sleep(POLL_SECONDS)


@asynccontextmanager
async def lifespan(_app: FastAPI):
    if POLL_SECONDS < 10 or SCHEDULE_BATCH_SIZE < 1:
        raise RuntimeError(
            "SCHEDULE_POLL_SECONDS must be at least 10 and "
            "SCHEDULE_BATCH_SIZE must be positive."
        )
    if APP_ENV == "production" and not os.getenv("DATABASE_URL", "").startswith(
        ("postgres://", "postgresql://", "postgresql+psycopg://")
    ):
        raise RuntimeError(
            "Production requires Railway PostgreSQL; configure DATABASE_URL."
        )
    secret_key()
    initialize_database()
    worker = asyncio.create_task(schedule_worker())
    try:
        yield
    finally:
        worker.cancel()
        try:
            await worker
        except asyncio.CancelledError:
            pass
        engine.dispose()


app = FastAPI(
    title="BrandShield AI",
    version="2.0.0",
    description=(
        "Live threat-intelligence lookups and search-result leads. "
        "Search results are unverified leads, not proof of fraud."
    ),
    lifespan=lifespan,
)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PATCH", "DELETE"],
    allow_headers=["Content-Type"],
)


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    return response


@app.get("/health")
def health():
    return {"status": "ok", "mode": "live-provider-lookups"}


@app.get("/api/sources")
def list_sources(
    _user: Annotated[User, Depends(current_user)],
):
    return {"items": configured_sources()}


@app.post("/api/auth/register")
@limiter.limit("5/hour")
def register(
    request: Request,
    data: Credentials,
    response: Response,
    db: Annotated[Session, Depends(get_db)],
):
    email = str(data.email).strip().lower()
    if db.scalar(select(User).where(User.email == email)):
        raise HTTPException(409, "An account with that email already exists.")

    user = User(email=email, password_hash=hash_password(data.password))
    db.add(user)
    try:
        db.commit()
        db.refresh(user)
    except IntegrityError:
        db.rollback()
        raise HTTPException(409, "An account with that email already exists.")
    set_session_cookie(response, user.id)
    return {"user": user_record(user)}


@app.post("/api/auth/login")
@limiter.limit("5/minute")
def login(
    request: Request,
    data: Credentials,
    response: Response,
    db: Annotated[Session, Depends(get_db)],
):
    email = str(data.email).strip().lower()
    user = db.scalar(select(User).where(User.email == email))
    if user is None or not verify_password(data.password, user.password_hash):
        raise HTTPException(401, "Email or password is incorrect.")
    set_session_cookie(response, user.id)
    return {"user": user_record(user)}


@app.post("/api/auth/logout")
def logout(response: Response):
    response.delete_cookie(
        SESSION_COOKIE,
        httponly=True,
        secure=APP_ENV == "production",
        samesite="strict",
        path="/",
    )
    return {"success": True}


@app.get("/api/auth/me")
def me(user: Annotated[User, Depends(current_user)]):
    return {"user": user_record(user)}


@app.get("/api/brands")
def list_brands(
    user: Annotated[User, Depends(current_user)],
    db: Annotated[Session, Depends(get_db)],
):
    brands = db.scalars(
        select(Brand)
        .where(Brand.user_id == user.id)
        .order_by(Brand.created_at.desc())
    ).all()
    return {"items": [brand_record(item) for item in brands]}


@app.post("/api/brands", status_code=201)
def add_brand(
    data: BrandInput,
    user: Annotated[User, Depends(current_user)],
    db: Annotated[Session, Depends(get_db)],
):
    name = data.name.strip()
    if not name:
        raise HTTPException(400, "Brand name cannot be empty.")
    count = db.scalar(
        select(func.count()).select_from(Brand).where(Brand.user_id == user.id)
    )
    if count >= MAX_BRANDS_PER_USER:
        raise HTTPException(
            429, f"Each account can monitor up to {MAX_BRANDS_PER_USER} brands."
        )

    brand = Brand(
        user_id=user.id,
        name=name,
        domain=normalize_domain(data.domain),
        monitoring_interval_hours=data.monitoring_interval_hours,
    )
    if brand.monitoring_interval_hours:
        brand.next_scan_at = datetime.now(timezone.utc) + timedelta(
            hours=brand.monitoring_interval_hours
        )
    if not data.external_lookup_consent:
        raise HTTPException(
            400,
            "Consent to send the brand name and domain to external providers "
            "before saving it.",
        )
    brand.external_lookup_consent_at = datetime.now(timezone.utc)
    db.add(brand)
    try:
        db.commit()
        db.refresh(brand)
    except IntegrityError:
        db.rollback()
        raise HTTPException(409, "This brand and domain are already monitored.")
    return brand_record(brand)


@app.delete("/api/brands/{brand_id}")
def delete_brand(
    brand_id: int,
    user: Annotated[User, Depends(current_user)],
    db: Annotated[Session, Depends(get_db)],
):
    brand = db.scalar(
        select(Brand).where(Brand.id == brand_id, Brand.user_id == user.id)
    )
    if brand is None:
        raise HTTPException(404, "Brand not found.")
    db.delete(brand)
    db.commit()
    return {"success": True, "deleted_id": brand_id}


@app.patch("/api/brands/{brand_id}/schedule")
def update_schedule(
    brand_id: int,
    data: ScheduleInput,
    user: Annotated[User, Depends(current_user)],
    db: Annotated[Session, Depends(get_db)],
):
    brand = db.scalar(
        select(Brand).where(Brand.id == brand_id, Brand.user_id == user.id)
    )
    if brand is None:
        raise HTTPException(404, "Brand not found.")
    if data.interval_hours is not None and (
        brand.external_lookup_consent_at is None
        and not data.external_lookup_consent
    ):
        raise HTTPException(
            400,
            "Consent to scheduled external provider lookups before enabling "
            "automatic monitoring.",
        )
    if data.external_lookup_consent:
        brand.external_lookup_consent_at = datetime.now(timezone.utc)
    brand.monitoring_interval_hours = data.interval_hours
    brand.next_scan_at = (
        datetime.now(timezone.utc) + timedelta(hours=data.interval_hours)
        if data.interval_hours is not None
        else None
    )
    db.commit()
    db.refresh(brand)
    return brand_record(brand)


@app.post("/api/brands/{brand_id}/scan")
@limiter.limit("5/hour")
def scan_saved_brand(
    request: Request,
    brand_id: int,
    user: Annotated[User, Depends(current_user)],
    db: Annotated[Session, Depends(get_db)],
):
    brand = db.scalar(
        select(Brand).where(Brand.id == brand_id, Brand.user_id == user.id)
    )
    if brand is None:
        raise HTTPException(404, "Brand not found.")
    if brand.external_lookup_consent_at is None:
        raise HTTPException(403, "Provider lookup consent is required.")
    return execute_scan(db, user.id, brand.name, brand.domain, brand.id)


@app.post("/api/scans")
@limiter.limit("5/hour")
def scan_brand_on_demand(
    request: Request,
    data: ScanInput,
    user: Annotated[User, Depends(current_user)],
    db: Annotated[Session, Depends(get_db)],
):
    name = data.brand_name.strip()
    if not name:
        raise HTTPException(400, "Brand name cannot be empty.")
    if not data.external_lookup_consent:
        raise HTTPException(
            400,
            "Consent to send the brand name and domain to external providers "
            "before scanning.",
        )
    domain = normalize_domain(data.domain)
    return execute_scan(db, user.id, name, domain)


@app.post("/api/public/scans")
@limiter.limit("5/hour")
def scan_brand_without_saving(
    request: Request,
    data: ScanInput,
):
    name = data.brand_name.strip()
    if not name:
        raise HTTPException(400, "Brand name cannot be empty.")
    if not data.external_lookup_consent:
        raise HTTPException(
            400,
            "Consent to send the brand name and domain to external providers "
            "before scanning.",
        )
    domain = normalize_domain(data.domain)
    findings, provider_results = scan_brand(name, domain)
    return {
        "id": None,
        "brand_name": name,
        "domain": domain,
        "scan_status": get_scan_status(provider_results),
        "provider_results": provider_results,
        "findings": findings,
        "created_at": datetime.now(timezone.utc),
    }


@app.get("/api/scans")
def list_scans(
    user: Annotated[User, Depends(current_user)],
    db: Annotated[Session, Depends(get_db)],
):
    runs = db.scalars(
        select(ScanRun)
        .where(ScanRun.user_id == user.id)
        .order_by(ScanRun.created_at.desc())
        .limit(50)
    ).all()
    return {
        "items": [{
            "id": run.id,
            "brand_id": run.brand_id,
            "brand_name": run.brand_name,
            "domain": run.domain,
            "scan_status": run.scan_status,
            "provider_results": json.loads(run.provider_results),
            "created_at": run.created_at,
        } for run in runs]
    }


@app.get("/api/findings")
def list_findings(
    user: Annotated[User, Depends(current_user)],
    db: Annotated[Session, Depends(get_db)],
):
    findings = db.scalars(
        select(Finding)
        .where(Finding.user_id == user.id)
        .order_by(Finding.created_at.desc())
        .limit(200)
    ).all()
    return {"items": [finding_record(item) for item in findings]}


@app.patch("/api/findings/{finding_id}")
def update_finding(
    finding_id: int,
    data: FindingStatusInput,
    user: Annotated[User, Depends(current_user)],
    db: Annotated[Session, Depends(get_db)],
):
    if data.status not in ALLOWED_FINDING_STATUSES:
        raise HTTPException(
            400, f"Status must be one of: {', '.join(sorted(ALLOWED_FINDING_STATUSES))}"
        )
    finding = db.scalar(
        select(Finding).where(
            Finding.id == finding_id, Finding.user_id == user.id
        )
    )
    if finding is None:
        raise HTTPException(404, "Finding not found.")
    finding.status = data.status
    db.commit()
    db.refresh(finding)
    return finding_record(finding)


@app.get("/api/reports")
def reports(
    user: Annotated[User, Depends(current_user)],
    db: Annotated[Session, Depends(get_db)],
):
    brands = db.scalar(
        select(func.count()).select_from(Brand).where(Brand.user_id == user.id)
    )
    scans = db.scalar(
        select(func.count()).select_from(ScanRun).where(ScanRun.user_id == user.id)
    )
    findings = db.scalar(
        select(func.count()).select_from(Finding).where(Finding.user_id == user.id)
    )
    unresolved = db.scalar(
        select(func.count()).select_from(Finding).where(
            Finding.user_id == user.id,
            Finding.status != "Resolved",
        )
    )
    return {
        "generated_at": datetime.now(timezone.utc),
        "total_brands": brands,
        "total_scans": scans,
        "total_findings": findings,
        "unresolved_findings": unresolved,
        "sources": configured_sources(),
        "disclaimer": (
            "Threat-feed matches are provider data; web and app-store entries "
            "are unverified leads, not proof of impersonation or fraud."
        ),
    }


if not os.path.isdir(FRONTEND_DIR):
    raise RuntimeError(f"Frontend directory does not exist: {FRONTEND_DIR}")
app.mount("/", StaticFiles(directory=FRONTEND_DIR, html=True), name="frontend")
