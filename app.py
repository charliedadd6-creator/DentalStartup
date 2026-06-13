import asyncio
import base64
import hashlib
import html
import hmac
import json
import logging
import os
import re
import time
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Annotated

import asyncpg
import resend
from fastapi import BackgroundTasks, FastAPI, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from models_auth import UserCreate, UserLogin, generate_uuid
from pydantic import BaseModel, EmailStr, Field, ValidationError, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict
from security import hash_password, verify_password
from starlette.middleware.sessions import SessionMiddleware

logger = logging.getLogger("swiftslot")
logging.basicConfig(level=logging.INFO)
log = logger

BASE_DIR = Path(__file__).resolve().parent
SMTP_SEMAPHORE = asyncio.Semaphore(5)
resend.api_key = os.getenv("RESEND_API_KEY")
TOKEN_SECRET = os.getenv("TOKEN_SECRET", "")
if not TOKEN_SECRET:
    TOKEN_SECRET = "dev-token-secret-change-this"
SECRET_KEY = TOKEN_SECRET.encode("utf-8")


def require_auth(request: Request):
    user_id = request.session.get("user_id")
    if not user_id:
        return RedirectResponse(url="/login-page")
    return None


def get_session_clinic_id(request: Request) -> str:
    clinic_id = request.session.get("clinic_id")
    if not clinic_id:
        raise HTTPException(status_code=401, detail="Clinic session missing")
    return clinic_id


def iso_or_none(value):
    if value is None:
        return None
    if hasattr(value, "isoformat"):
        return value.isoformat()
    return value


DEFAULT_GDPR_NOTICE = (
    "Only contact patients who have given explicit consent to receive short-notice appointment offers."
)
APPOINTMENT_TYPES = [
    "Check-up",
    "Hygienist",
    "Emergency",
    "Filling",
    "Crown",
    "Extraction",
    "Consultation",
    "Other",
]
PATIENT_LIFECYCLE_STATUSES = {"waitlist", "booked", "completed", "archived"}
APPOINTMENT_STATUSES = {"booked", "completed", "cancelled", "no_show"}
APPOINTMENT_SOURCES = {"manual", "recovered", "import", "integration"}


def safe_int(value, default=0):
    try:
        return int(value)
    except Exception:
        return default


def clamp_expiry_minutes(value: int) -> int:
    return max(5, min(value, 1440))


def clamp_patient_priority(value: int) -> int:
    return max(1, min(safe_int(value, 3), 5))


def clean_optional_string(value):
    if value is None:
        return None
    trimmed = str(value).strip()
    return trimmed or None


def clean_optional_text(value):
    return clean_optional_string(value)


def normalize_email(value) -> str | None:
    cleaned = clean_optional_string(value)
    if cleaned is None:
        return None
    return cleaned.lower()


def parse_money_to_pence(value) -> int:
    if value is None or value == "":
        return 0
    if isinstance(value, int):
        return max(0, value)
    text = str(value).strip().replace("£", "").replace(",", "")
    try:
        amount = float(text)
    except ValueError as exc:
        raise ValueError("money value must be a valid number") from exc
    if amount < 0:
        raise ValueError("money value cannot be negative")
    return round(amount * 100)


def normalize_appointment_type(value):
    cleaned = clean_optional_string(value)
    if cleaned is None:
        return None
    for appointment_type in APPOINTMENT_TYPES:
        if appointment_type.lower() == cleaned.lower():
            return appointment_type
    raise ValueError(f"appointment_type must be one of: {', '.join(APPOINTMENT_TYPES)}")


def validate_appointment_type(value):
    return normalize_appointment_type(value)


def normalize_lifecycle_status(value) -> str:
    cleaned = clean_optional_string(value) or "waitlist"
    cleaned = cleaned.lower()
    if cleaned not in PATIENT_LIFECYCLE_STATUSES:
        raise ValueError("lifecycle_status must be waitlist, booked, completed, or archived")
    return cleaned


def get_resend_from_email() -> str:
    return os.getenv("RESEND_FROM_EMAIL", "SwiftSlot <onboarding@resend.dev>")


def normalize_appointment_status(value) -> str:
    cleaned = clean_optional_string(value) or "booked"
    cleaned = cleaned.lower()
    if cleaned not in APPOINTMENT_STATUSES:
        raise ValueError("status must be booked, completed, cancelled, or no_show")
    return cleaned


def normalize_appointment_source(value) -> str:
    cleaned = clean_optional_string(value) or "manual"
    cleaned = cleaned.lower()
    if cleaned not in APPOINTMENT_SOURCES:
        raise ValueError("source must be manual, recovered, import, or integration")
    return cleaned


def generate_secure_token(offer_id: str) -> str:
    timestamp = int(time.time())
    payload = f"{offer_id}:{timestamp}".encode("utf-8")
    signature = hmac.new(SECRET_KEY, payload, hashlib.sha256).hexdigest()
    token_str = f"{offer_id}:{timestamp}:{signature}"
    return base64.urlsafe_b64encode(token_str.encode("utf-8")).decode("utf-8")


def verify_secure_token(token: str, max_age_seconds: int = 14400) -> str | None:
    try:
        decoded = base64.urlsafe_b64decode(token.encode("utf-8")).decode("utf-8")
        offer_id, timestamp_str, signature = decoded.split(":")
        if time.time() - int(timestamp_str) > max_age_seconds:
            return None
        payload = f"{offer_id}:{timestamp_str}".encode("utf-8")
        expected_signature = hmac.new(SECRET_KEY, payload, hashlib.sha256).hexdigest()
        if hmac.compare_digest(signature, expected_signature):
            return offer_id
    except Exception:
        return None
    return None


class Settings(BaseSettings):
    database_url: str = Field(default="", alias="DATABASE_URL")
    render_external_url: str = Field(default="", alias="RENDER_EXTERNAL_URL")
    db_min_size: int = Field(default=1, alias="DB_POOL_MIN_SIZE")
    db_max_size: int = Field(default=10, alias="DB_POOL_MAX_SIZE")
    log_level: str = Field(default="INFO", alias="LOG_LEVEL")

    model_config = SettingsConfigDict(
        env_file=str(Path(__file__).resolve().parent / ".env"),
        extra="ignore"
    )

    def assert_startup_ready(self) -> None:
        if not self.database_url:
            raise RuntimeError("DATABASE_URL must be set to a Neon PostgreSQL connection string.")

        external_url = self.render_external_url.strip().rstrip("/")
        if not external_url:
            raise RuntimeError(
                "RENDER_EXTERNAL_URL must be set. "
                "For local development use: RENDER_EXTERNAL_URL=http://localhost:8000"
            )
        self.render_external_url = external_url


settings = Settings()
logging.getLogger("swiftslot").setLevel(settings.log_level.upper())


class DashboardOfferRequest(BaseModel):
    slot_time: datetime
    clinician: str | None = Field(default=None, max_length=160)
    appointment_type: str | None = Field(default=None, max_length=120)
    slot_value_pence: int = 0
    patient_emails: Annotated[list[EmailStr], Field(min_length=1, max_length=100)]

    @field_validator("slot_time")
    @classmethod
    def normalize_slot_time(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)

    @field_validator("slot_value_pence")
    @classmethod
    def validate_slot_value_pence(cls, value: int) -> int:
        if value < 0:
            raise ValueError("slot_value_pence cannot be negative")
        return value

    @field_validator("patient_emails")
    @classmethod
    def dedupe_patient_emails(cls, value: list[EmailStr]) -> list[EmailStr]:
        seen: set[str] = set()
        deduped: list[EmailStr] = []
        for email in value:
            normalized = str(email).lower()
            if normalized not in seen:
                seen.add(normalized)
                deduped.append(email)
        return deduped


class ClinicSettingsUpdate(BaseModel):
    display_name: str | None = None
    contact_email: EmailStr | None = None
    phone: str | None = None
    sender_name: str | None = None
    reply_to_email: EmailStr | None = None
    default_slot_value_pence: int | None = None
    default_expiry_minutes: int | None = None
    gdpr_notice: str | None = None

    @field_validator("contact_email", "reply_to_email", mode="before")
    @classmethod
    def normalize_optional_email(cls, value):
        if value is None:
            return None
        trimmed = str(value).strip()
        return trimmed or None

    @field_validator("display_name")
    @classmethod
    def validate_display_name(cls, value: str | None) -> str | None:
        if value is None:
            return None
        trimmed = value.strip()
        if not trimmed:
            raise ValueError("display_name cannot be empty")
        return trimmed

    @field_validator("phone", "sender_name", "gdpr_notice", mode="before")
    @classmethod
    def normalize_optional_string(cls, value):
        if value is None:
            return None
        trimmed = str(value).strip()
        return trimmed or None

    @field_validator("default_slot_value_pence")
    @classmethod
    def validate_default_slot_value(cls, value: int | None) -> int | None:
        if value is not None and value < 0:
            raise ValueError("default_slot_value_pence cannot be negative")
        return value

    @field_validator("default_expiry_minutes")
    @classmethod
    def validate_default_expiry(cls, value: int | None) -> int | None:
        if value is None:
            return None
        return clamp_expiry_minutes(value)


class PatientCreate(BaseModel):
    first_name: str
    last_name: str | None = None
    email: EmailStr
    phone: str | None = None
    consent_status: str = "consented"
    notes: str | None = None
    priority: int = 3
    preferred_appointment_type: str | None = None
    preferred_clinician: str | None = None
    lifecycle_status: str = "waitlist"

    @field_validator("priority")
    @classmethod
    def validate_priority(cls, value: int) -> int:
        return clamp_patient_priority(value)


class PatientUpdate(BaseModel):
    first_name: str | None = None
    last_name: str | None = None
    email: EmailStr | None = None
    phone: str | None = None
    consent_status: str | None = None
    notes: str | None = None
    priority: int | None = None
    preferred_appointment_type: str | None = None
    preferred_clinician: str | None = None
    lifecycle_status: str | None = None

    @field_validator("email", mode="before")
    @classmethod
    def normalize_optional_email(cls, value):
        if value is None:
            return None
        trimmed = str(value).strip()
        return trimmed or None

    @field_validator(
        "first_name",
        "last_name",
        "phone",
        "consent_status",
        "notes",
        "preferred_appointment_type",
        "preferred_clinician",
        "lifecycle_status",
        mode="before",
    )
    @classmethod
    def normalize_optional_patient_string(cls, value):
        return clean_optional_string(value)

    @field_validator("priority")
    @classmethod
    def validate_priority(cls, value: int | None) -> int | None:
        if value is None:
            return None
        return clamp_patient_priority(value)


class BroadcastResponse(BaseModel):
    slot_id: str
    slot_time: datetime
    clinician: str | None
    status: str
    offers_sent: int
    accepted_by: str | None


class SlotStatusResponse(BaseModel):
    slot_id: str
    slot_time: datetime
    clinician: str | None
    status: str
    offers_sent: int
    accepted_by: str | None
    locked_at: datetime | None
    offers: list[dict] = Field(default_factory=list)


class AppointmentCreate(BaseModel):
    patient_email: EmailStr
    patient_name: str | None = None
    patient_id: str | None = None
    appointment_type: str | None = None
    clinician: str | None = None
    appointment_time: datetime
    slot_value_pence: int = 0
    notes: str | None = None
    source: str = "manual"

    @field_validator("appointment_time")
    @classmethod
    def normalize_appointment_time(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)

    @field_validator("slot_value_pence")
    @classmethod
    def validate_slot_value(cls, value: int) -> int:
        if value < 0:
            raise ValueError("slot_value_pence cannot be negative")
        return value


class AppointmentUpdate(BaseModel):
    appointment_type: str | None = None
    clinician: str | None = None
    appointment_time: datetime | None = None
    slot_value_pence: int | None = None
    notes: str | None = None
    status: str | None = None

    @field_validator("appointment_time")
    @classmethod
    def normalize_appointment_time(cls, value: datetime | None) -> datetime | None:
        if value is None:
            return None
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)

    @field_validator("slot_value_pence")
    @classmethod
    def validate_slot_value(cls, value: int | None) -> int | None:
        if value is not None and value < 0:
            raise ValueError("slot_value_pence cannot be negative")
        return value


class AppointmentImportRows(BaseModel):
    rows: list[dict] = Field(default_factory=list, max_length=500)


class PatientImportRows(BaseModel):
    rows: list[dict] = Field(default_factory=list, max_length=500)


async def log_clinical_event(
    pool: asyncpg.Pool,
    event_type: str,
    clinic_id: str | None = None,
    slot_id: str | None = None,
    offer_id: str | None = None,
    patient_email: str | None = None,
    client_ip: str | None = None,
    success: bool = True,
    details: dict | None = None,
) -> None:
    email_hash = None
    if patient_email:
        email_hash = hashlib.sha256(patient_email.strip().lower().encode("utf-8")).hexdigest()

    try:
        clinic_uuid = uuid.UUID(str(clinic_id)) if clinic_id else None
        slot_uuid = uuid.UUID(str(slot_id)) if slot_id else None
        offer_uuid = uuid.UUID(str(offer_id)) if offer_id else None
        details_json = json.dumps(details or {}, default=str)
        async with pool.acquire() as conn:
            await conn.execute(
                """
                INSERT INTO audit_log (clinic_id, event_type, slot_id, offer_id, patient_email_hash, client_ip, success, details)
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8);
                """,
                clinic_uuid,
                event_type,
                slot_uuid,
                offer_uuid,
                email_hash,
                client_ip,
                success,
                details_json,
            )
    except Exception as e:
        print(f"FAILED TO WRITE TO AUDIT LOG: {e}")


async def get_clinic_settings(pool: asyncpg.Pool, clinic_id: str) -> dict:
    clinic_uuid = uuid.UUID(str(clinic_id))
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            """
            SELECT
                id::text,
                name,
                display_name,
                contact_email,
                phone,
                sender_name,
                reply_to_email,
                default_slot_value_pence,
                default_expiry_minutes,
                gdpr_notice
            FROM clinics
            WHERE id = $1
            """,
            clinic_uuid,
        )

    if not row:
        raise HTTPException(status_code=404, detail="Clinic not found")

    clinic_name = row["display_name"] or row["name"] or "Your clinic"
    contact_email = row["contact_email"]
    default_expiry = clamp_expiry_minutes(safe_int(row["default_expiry_minutes"], 240))
    email_sender = get_resend_from_email()

    return {
        "clinic_id": row["id"],
        "clinic_name": clinic_name,
        "contact_email": contact_email,
        "phone": row["phone"],
        "sender_name": row["sender_name"] or clinic_name or "SwiftSlot",
        "reply_to_email": row["reply_to_email"] or contact_email,
        "default_slot_value_pence": max(0, safe_int(row["default_slot_value_pence"], 0)),
        "default_expiry_minutes": default_expiry,
        "gdpr_notice": row["gdpr_notice"] or DEFAULT_GDPR_NOTICE,
        "email_sender": email_sender,
        "email_sender_is_testing": "resend.dev" in email_sender.lower(),
    }


def serialize_patient(row) -> dict:
    return {
        "id": row["id"],
        "first_name": row["first_name"],
        "last_name": row["last_name"],
        "email": row["email"],
        "phone": row["phone"],
        "consent_status": row["consent_status"],
        "consent_source": row["consent_source"],
        "consented_at": iso_or_none(row["consented_at"]),
        "notes": row["notes"],
        "priority": row["priority"],
        "preferred_appointment_type": row["preferred_appointment_type"],
        "preferred_clinician": row["preferred_clinician"],
        "last_contacted_at": iso_or_none(row["last_contacted_at"]),
        "last_response_at": iso_or_none(row["last_response_at"]),
        "accepted_count": row["accepted_count"],
        "declined_count": row["declined_count"],
        "offer_count": row["offer_count"],
        "lifecycle_status": row["lifecycle_status"],
        "booked_at": iso_or_none(row["booked_at"]),
        "completed_at": iso_or_none(row["completed_at"]),
        "archived_at": iso_or_none(row["archived_at"]),
        "created_at": iso_or_none(row["created_at"]),
        "updated_at": iso_or_none(row["updated_at"]),
    }


def serialize_appointment(row) -> dict:
    return {
        "id": row["id"],
        "patient_id": row["patient_id"],
        "patient_email": row["patient_email"],
        "patient_name": row["patient_name"],
        "source": row["source"],
        "appointment_type": row["appointment_type"],
        "clinician": row["clinician"],
        "appointment_time": iso_or_none(row["appointment_time"]),
        "slot_value_pence": row["slot_value_pence"],
        "status": row["status"],
        "notes": row["notes"],
        "completed_at": iso_or_none(row["completed_at"]),
        "cancelled_at": iso_or_none(row["cancelled_at"]),
        "no_show_at": iso_or_none(row["no_show_at"]),
        "created_at": iso_or_none(row["created_at"]),
        "updated_at": iso_or_none(row["updated_at"]),
    }


def split_patient_name(patient_name: str | None, email: str) -> tuple[str, str | None]:
    cleaned = clean_optional_string(patient_name)
    if not cleaned:
        return email.split("@", 1)[0], None
    parts = cleaned.split()
    return parts[0], " ".join(parts[1:]) or None


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings.assert_startup_ready()
    pool = await asyncpg.create_pool(
        dsn=settings.database_url,
        min_size=settings.db_min_size,
        max_size=settings.db_max_size,
    )
    app.state.pool = pool
    async with pool.acquire() as conn:
        await conn.fetchval("SELECT 1")
    await ensure_schema(pool)
    await backfill_recovered_appointments(pool)
    try:
        yield
    finally:
        await pool.close()


app = FastAPI(title="SwiftSlot Sidecar Pilot", version="0.2.0", lifespan=lifespan)
SESSION_COOKIE_SECURE = os.getenv("SESSION_COOKIE_SECURE", "true").lower() == "true"

app.add_middleware(
    SessionMiddleware,
    secret_key=os.getenv("SESSION_SECRET", "dev-secret-change-this"),
    same_site="lax",
    https_only=SESSION_COOKIE_SECURE
)
templates = Jinja2Templates(directory="templates")


@app.get("/", response_class=HTMLResponse)
async def root(request: Request):
    if request.session.get("user_id"):
        return RedirectResponse(url="/app/dashboard")
    html = (BASE_DIR / "templates" / "landing.html").read_text()
    return HTMLResponse(html)


@app.get("/login-page", response_class=HTMLResponse)
async def login_page():
    html = (BASE_DIR / "templates" / "login.html").read_text()
    return HTMLResponse(html)


@app.get("/signup-page", response_class=HTMLResponse)
async def signup_page():
    html = (BASE_DIR / "templates" / "signup.html").read_text()
    return HTMLResponse(html)


@app.get("/health")
async def health_check(request: Request):
    db_status = "disconnected"
    try:
        # Access our connection pool from app state
        pool = request.app.state.pool
        if pool:
            # Ping the database with a fast, lightweight query
            async with pool.acquire() as conn:
                await conn.fetchval("SELECT 1")
            db_status = "connected"
    except Exception as e:
        log.error(f"Database health check failed: {e}")
        db_status = "disconnected"

    return {
        "status": "healthy" if db_status == "connected" else "degraded",
        "database": db_status
    }


@app.get("/robots.txt", response_class=PlainTextResponse)
async def robots_txt():
    return PlainTextResponse(
        "User-agent: *\n"
        "Disallow: /app/\n"
        "Disallow: /api/\n"
        "Disallow: /offer/\n"
        "Disallow: /accept/\n"
        "Disallow: /decline/\n"
    )


@app.get("/app/dashboard", response_class=HTMLResponse)
async def dashboard(request: Request):
    auth_redirect = require_auth(request)
    if auth_redirect:
        return auth_redirect
    html = (BASE_DIR / "templates" / "dashboard.html").read_text()
    return HTMLResponse(html)


@app.get("/app/waitlist", response_class=HTMLResponse)
async def waitlist(request: Request):
    auth_redirect = require_auth(request)
    if auth_redirect:
        return auth_redirect
    html = (BASE_DIR / "templates" / "waitlist.html").read_text()
    return HTMLResponse(html)


@app.get("/app/broadcasts", response_class=HTMLResponse)
async def broadcasts(request: Request):
    auth_redirect = require_auth(request)
    if auth_redirect:
        return auth_redirect
    html = (BASE_DIR / "templates" / "broadcasts.html").read_text()
    return HTMLResponse(html)


@app.get("/app/appointments", response_class=HTMLResponse)
async def appointments(request: Request):
    auth_redirect = require_auth(request)
    if auth_redirect:
        return auth_redirect
    html = (BASE_DIR / "templates" / "appointments.html").read_text()
    return HTMLResponse(html)


@app.get("/app/analytics", response_class=HTMLResponse)
async def analytics(request: Request):
    auth_redirect = require_auth(request)
    if auth_redirect:
        return auth_redirect
    html = (BASE_DIR / "templates" / "analytics.html").read_text()
    return HTMLResponse(html)


@app.get("/app/settings", response_class=HTMLResponse)
async def settings_page(request: Request):
    auth_redirect = require_auth(request)
    if auth_redirect:
        return auth_redirect
    html = (BASE_DIR / "templates" / "settings.html").read_text()
    return HTMLResponse(html)


@app.get("/api/clinic/settings")
async def api_get_clinic_settings(request: Request):
    auth_redirect = require_auth(request)
    if auth_redirect:
        raise HTTPException(status_code=401, detail="Authentication required")

    clinic_id = get_session_clinic_id(request)
    return await get_clinic_settings(request.app.state.pool, clinic_id)


@app.get("/api/appointment-types")
async def api_appointment_types(request: Request):
    auth_redirect = require_auth(request)
    if auth_redirect:
        raise HTTPException(status_code=401, detail="Authentication required")
    return {"appointment_types": APPOINTMENT_TYPES}


def env_is_placeholder(value: str | None, dev_fallbacks: set[str] | None = None) -> bool:
    cleaned = (value or "").strip()
    if not cleaned:
        return True
    lowered = cleaned.lower()
    if dev_fallbacks and cleaned in dev_fallbacks:
        return True
    return any(token in lowered for token in ["your_key_here", "placeholder", "change-this", "changeme", "example"])


def readiness_check(key: str, label: str, ok: bool, message: str, warning: bool = False) -> dict:
    return {
        "key": key,
        "label": label,
        "status": "pass" if ok and not warning else "warning" if ok and warning else "fail",
        "message": message,
    }


@app.get("/api/system/readiness")
async def api_system_readiness(request: Request):
    auth_redirect = require_auth(request)
    if auth_redirect:
        raise HTTPException(status_code=401, detail="Authentication required")

    clinic_uuid = uuid.UUID(str(get_session_clinic_id(request)))
    async with request.app.state.pool.acquire() as conn:
        clinic = await conn.fetchrow(
            """
            SELECT display_name, reply_to_email, contact_email, default_expiry_minutes
            FROM clinics
            WHERE id = $1
            """,
            clinic_uuid,
        )
        counts = await conn.fetchrow(
            """
            SELECT
                (SELECT COUNT(*)::int FROM patients WHERE clinic_id = $1 AND consent_status = 'consented' AND archived_at IS NULL) AS consented_patients,
                (SELECT COUNT(*)::int FROM appointments WHERE clinic_id = $1 AND source IN ('recovered', 'manual', 'import')) AS appointments
            """,
            clinic_uuid,
        )

    default_expiry = safe_int(clinic["default_expiry_minutes"], 0) if clinic else 0
    resend_key = os.getenv("RESEND_API_KEY", "")
    resend_from_env = os.getenv("RESEND_FROM_EMAIL", "")
    resend_from = get_resend_from_email()
    token_secret = os.getenv("TOKEN_SECRET", "")
    session_secret = os.getenv("SESSION_SECRET", "")
    render_url = os.getenv("RENDER_EXTERNAL_URL", "")
    is_production = (
        os.getenv("RENDER", "").lower() == "true"
        or os.getenv("ENVIRONMENT", "").lower() == "production"
        or os.getenv("APP_ENV", "").lower() == "production"
    )
    render_https_ok = not is_production or render_url.strip().startswith("https://")

    checks = [
        readiness_check(
            "clinic_settings",
            "Clinic settings completed",
            bool(clinic and clean_optional_string(clinic["display_name"])),
            "Clinic display name is set." if clinic and clean_optional_string(clinic["display_name"]) else "Complete clinic display name in Settings.",
        ),
        readiness_check(
            "reply_to_email",
            "Reply-to email configured",
            bool(clinic and clean_optional_string(clinic["reply_to_email"])),
            "Reply-to email is available." if clinic and clean_optional_string(clinic["reply_to_email"]) else "Add a reply-to email in Settings.",
        ),
        readiness_check(
            "default_expiry_minutes",
            "Default offer expiry set",
            5 <= default_expiry <= 1440,
            "Default expiry is within the allowed live range." if 5 <= default_expiry <= 1440 else "Set default expiry between 5 and 1440 minutes.",
        ),
        readiness_check(
            "resend_api_key",
            "Resend API key configured",
            not env_is_placeholder(resend_key, {"re_your_key_here"}),
            "Resend API key is configured." if not env_is_placeholder(resend_key, {"re_your_key_here"}) else "Set RESEND_API_KEY to a live Resend key.",
        ),
        readiness_check(
            "resend_from_email",
            "Sender email configured",
            bool(clean_optional_string(resend_from_env)),
            "Sender email is configured." if clean_optional_string(resend_from_env) else "Set RESEND_FROM_EMAIL.",
        ),
        readiness_check(
            "resend_domain",
            "Sending domain verified",
            True,
            "Sender is using a clinic/domain sender." if "resend.dev" not in (resend_from or "").lower() else "Verify sending domain and stop using the resend.dev test sender.",
            warning="resend.dev" in (resend_from or "").lower(),
        ),
        readiness_check(
            "token_secret",
            "Token secret configured",
            not env_is_placeholder(token_secret, {"dev-token-secret-change-this"}),
            "TOKEN_SECRET is configured." if not env_is_placeholder(token_secret, {"dev-token-secret-change-this"}) else "Set TOKEN_SECRET to a strong production value.",
        ),
        readiness_check(
            "session_secret",
            "Session secret configured",
            not env_is_placeholder(session_secret, {"dev-secret-change-this"}),
            "SESSION_SECRET is configured." if not env_is_placeholder(session_secret, {"dev-secret-change-this"}) else "Set SESSION_SECRET to a strong production value.",
        ),
        readiness_check(
            "render_external_url",
            "Production URL uses HTTPS",
            render_https_ok,
            "Production external URL is HTTPS." if render_https_ok else "Set RENDER_EXTERNAL_URL to an https:// URL in production.",
        ),
        readiness_check(
            "consented_patients",
            "Consented waitlist patients added",
            safe_int(counts["consented_patients"], 0) > 0 if counts else False,
            "At least one consented waitlist patient exists." if counts and safe_int(counts["consented_patients"], 0) > 0 else "Add or import consented patients.",
        ),
        readiness_check(
            "appointment_types",
            "Appointment types available",
            len(APPOINTMENT_TYPES) > 0,
            "Appointment types are available." if APPOINTMENT_TYPES else "Add at least one appointment type.",
        ),
        readiness_check(
            "appointments",
            "Appointment workflow has data",
            safe_int(counts["appointments"], 0) > 0 if counts else False,
            "At least one appointment has been created or recovered." if counts and safe_int(counts["appointments"], 0) > 0 else "Create, import, or recover an appointment.",
        ),
    ]
    return {"ready": all(check["status"] == "pass" for check in checks), "checks": checks}


@app.get("/api/system/request-debug")
async def api_system_request_debug(request: Request):
    if os.getenv("ALLOW_DEBUG_ENDPOINTS", "").lower() != "true":
        raise HTTPException(status_code=404, detail="Not found")

    return {
        "request_url": str(request.url),
        "request_base_url": str(request.base_url),
        "host": request.headers.get("host"),
        "client_host": request.client.host if request.client else None,
        "render_external_url": settings.render_external_url,
        "session_cookie_secure": SESSION_COOKIE_SECURE,
    }


@app.patch("/api/clinic/settings")
async def api_update_clinic_settings(update: ClinicSettingsUpdate, request: Request):
    auth_redirect = require_auth(request)
    if auth_redirect:
        raise HTTPException(status_code=401, detail="Authentication required")

    clinic_id = get_session_clinic_id(request)
    clinic_uuid = uuid.UUID(str(clinic_id))
    allowed_fields = {
        "display_name",
        "contact_email",
        "phone",
        "sender_name",
        "reply_to_email",
        "default_slot_value_pence",
        "default_expiry_minutes",
        "gdpr_notice",
    }
    payload = update.model_dump(exclude_unset=True)
    fields = [field for field in update.model_fields_set if field in allowed_fields]

    if fields:
        assignments = []
        values = []
        for index, field in enumerate(fields, start=1):
            value = payload.get(field)
            if field in {"contact_email", "reply_to_email"} and value is not None:
                value = str(value)
            assignments.append(f"{field} = ${index}")
            values.append(value)
        assignments.append("updated_at = now()")
        values.append(clinic_uuid)
        async with request.app.state.pool.acquire() as conn:
            await conn.execute(
                f"""
                UPDATE clinics
                SET {", ".join(assignments)}
                WHERE id = ${len(values)}
                """,
                *values,
            )

    settings_data = await get_clinic_settings(request.app.state.pool, clinic_id)
    await log_clinical_event(
        request.app.state.pool,
        "clinic_settings_updated",
        clinic_id=clinic_id,
        client_ip=request.client.host if request.client else None,
        details={"fields": sorted(fields)},
    )
    return settings_data


@app.get("/api/me")
async def api_me(request: Request):
    auth_redirect = require_auth(request)
    if auth_redirect:
        raise HTTPException(status_code=401, detail="Authentication required")

    clinic_id = get_session_clinic_id(request)
    return {
        "user_id": request.session.get("user_id"),
        "clinic_id": clinic_id,
        "clinic": await get_clinic_settings(request.app.state.pool, clinic_id),
    }


async def backfill_recovered_appointments(pool: asyncpg.Pool) -> None:
    backfilled = 0
    skipped_legacy = 0
    try:
        async with pool.acquire() as conn:
            skipped_legacy = await conn.fetchval(
                """
                SELECT COUNT(*)::int
                FROM waitlist_slots
                WHERE clinic_id IS NULL
                  AND accepted_by IS NOT NULL
                """
            ) or 0
            if skipped_legacy:
                logger.warning(
                    "Skipping %s recovered appointment backfill row(s) for legacy slots without clinic_id",
                    skipped_legacy,
                )

            rows = await conn.fetch(
                """
                SELECT
                    s.id AS id,
                    s.clinic_id, p.id AS patient_id, s.accepted_by,
                    TRIM(CONCAT(COALESCE(p.first_name, ''), ' ', COALESCE(p.last_name, ''))) AS patient_name,
                    s.id AS slot_id, s.appointment_type, s.clinician,
                    s.slot_time, s.slot_value_pence
                FROM waitlist_slots s
                LEFT JOIN patients p
                  ON p.clinic_id = s.clinic_id
                 AND lower(p.email) = lower(s.accepted_by)
                WHERE s.clinic_id IS NOT NULL
                  AND s.accepted_by IS NOT NULL
                  AND (s.status = 'locked' OR s.accepted_by IS NOT NULL)
                  AND NOT EXISTS (
                    SELECT 1 FROM appointments a WHERE a.slot_id = s.id
                  );
                """
            )

            for row in rows:
                if not row["clinic_id"]:
                    skipped_legacy += 1
                    logger.warning(
                        "Skipping recovered appointment backfill for legacy slot without clinic_id: %s",
                        row["id"],
                    )
                    continue

                try:
                    result = await conn.execute(
                        """
                        INSERT INTO appointments (
                            id, clinic_id, patient_id, patient_email, patient_name, slot_id,
                            source, appointment_type, clinician, appointment_time,
                            slot_value_pence, status
                        )
                        VALUES ($1, $2, $3, $4, $5, $6, 'recovered', $7, $8, $9, $10, 'booked')
                        ON CONFLICT DO NOTHING
                        """,
                        uuid.uuid4(),
                        row["clinic_id"],
                        row["patient_id"],
                        row["accepted_by"],
                        clean_optional_string(row["patient_name"]),
                        row["slot_id"],
                        row["appointment_type"],
                        row["clinician"],
                        row["slot_time"],
                        row["slot_value_pence"],
                    )
                    if result.endswith(" 1"):
                        backfilled += 1
                except Exception:
                    logger.exception(
                        "Failed to backfill recovered appointment for slot %s",
                        row["id"],
                    )
                    continue
            logger.info(
                "Recovered appointment backfill complete: %s backfilled, %s legacy rows skipped",
                backfilled,
                skipped_legacy,
            )
    except Exception:
        logger.exception("Failed to scan recovered appointments for backfill")


async def fetch_appointment(conn, appointment_id: uuid.UUID, clinic_id: uuid.UUID):
    return await conn.fetchrow(
        """
        SELECT
            a.id::text, a.patient_id::text, a.patient_email, a.patient_name,
            a.source, a.appointment_type, a.clinician, a.appointment_time,
            a.slot_value_pence, a.status, a.notes, a.completed_at,
            a.cancelled_at, a.no_show_at, a.created_at, a.updated_at
        FROM appointments a
        WHERE a.id = $1 AND a.clinic_id = $2
        """,
        appointment_id,
        clinic_id,
    )


async def sync_patient_lifecycle_for_appointment(
    conn,
    clinic_id: uuid.UUID,
    patient_id: uuid.UUID | None,
    status: str,
    now: datetime,
) -> None:
    if not patient_id:
        return
    if status == "completed":
        await conn.execute(
            """
            UPDATE patients
            SET lifecycle_status = 'completed',
                completed_at = COALESCE(completed_at, $3),
                archived_at = COALESCE(archived_at, $3),
                updated_at = $3
            WHERE id = $1 AND clinic_id = $2
            """,
            patient_id,
            clinic_id,
            now,
        )
    elif status == "booked":
        await conn.execute(
            """
            UPDATE patients
            SET lifecycle_status = 'booked',
                booked_at = COALESCE(booked_at, $3),
                updated_at = $3
            WHERE id = $1 AND clinic_id = $2 AND lifecycle_status <> 'completed'
            """,
            patient_id,
            clinic_id,
            now,
        )
    elif status in {"cancelled", "no_show"}:
        await conn.execute(
            """
            UPDATE patients
            SET lifecycle_status = 'waitlist',
                updated_at = $3
            WHERE id = $1
              AND clinic_id = $2
              AND lifecycle_status = 'booked'
              AND archived_at IS NULL
            """,
            patient_id,
            clinic_id,
            now,
        )


async def find_or_create_booked_patient(conn, clinic_id: uuid.UUID, appointment: AppointmentCreate) -> tuple[uuid.UUID, str, bool, bool]:
    email = str(appointment.patient_email).lower().strip()
    now = datetime.now(timezone.utc)
    patient_id = None
    created = False
    updated = False
    if appointment.patient_id:
        try:
            patient_id = uuid.UUID(appointment.patient_id)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail="Invalid patient_id") from exc
        patient = await conn.fetchrow(
            "SELECT id FROM patients WHERE id = $1 AND clinic_id = $2",
            patient_id,
            clinic_id,
        )
        if not patient:
            raise HTTPException(status_code=404, detail="Patient not found")
    else:
        patient = await conn.fetchrow(
            "SELECT id FROM patients WHERE clinic_id = $1 AND lower(email) = lower($2)",
            clinic_id,
            email,
        )
        if patient:
            patient_id = patient["id"]

    if patient_id is None:
        first_name, last_name = split_patient_name(appointment.patient_name, email)
        patient_id = uuid.uuid4()
        await conn.execute(
            """
            INSERT INTO patients (
                id, clinic_id, first_name, last_name, email, consent_status,
                consent_source, lifecycle_status, booked_at, created_at, updated_at
            )
            VALUES ($1, $2, $3, $4, $5, 'not_consented', 'appointment_import', 'booked', $6, $6, $6)
            """,
            patient_id,
            clinic_id,
            first_name,
            last_name,
            email,
            now,
        )
        created = True
    else:
        await conn.execute(
            """
            UPDATE patients
            SET lifecycle_status = 'booked',
                booked_at = COALESCE(booked_at, $3),
                updated_at = $3
            WHERE id = $1 AND clinic_id = $2 AND lifecycle_status <> 'completed'
            """,
            patient_id,
            clinic_id,
            now,
        )
        updated = True

    return patient_id, email, created, updated


async def create_appointment_record(
    conn,
    clinic_id: uuid.UUID,
    appointment: AppointmentCreate,
    source_override: str | None = None,
) -> tuple[asyncpg.Record, bool, bool]:
    try:
        appointment_type = normalize_appointment_type(appointment.appointment_type)
        source = normalize_appointment_source(source_override or appointment.source)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    patient_id, email, created_patient, updated_patient = await find_or_create_booked_patient(conn, clinic_id, appointment)
    now = datetime.now(timezone.utc)
    row = await conn.fetchrow(
        """
        INSERT INTO appointments (
            id, clinic_id, patient_id, patient_email, patient_name, source,
            appointment_type, clinician, appointment_time, slot_value_pence,
            status, notes, created_at, updated_at
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, 'booked', $11, $12, $12)
        RETURNING id::text, patient_id::text, patient_email, patient_name, source,
                  appointment_type, clinician, appointment_time, slot_value_pence,
                  status, notes, completed_at, cancelled_at, no_show_at,
                  created_at, updated_at
        """,
        uuid.uuid4(),
        clinic_id,
        patient_id,
        email,
        clean_optional_string(appointment.patient_name),
        source,
        appointment_type,
        clean_optional_string(appointment.clinician),
        appointment.appointment_time,
        appointment.slot_value_pence,
        clean_optional_string(appointment.notes),
        now,
    )
    return row, created_patient, updated_patient


async def upsert_recovered_appointment_for_accept(conn, slot, offer, now: datetime) -> None:
    patient = await conn.fetchrow(
        """
        SELECT id, TRIM(CONCAT(COALESCE(first_name, ''), ' ', COALESCE(last_name, ''))) AS patient_name
        FROM patients
        WHERE clinic_id = $1 AND lower(email) = lower($2)
        """,
        slot["clinic_id"],
        offer["patient_email"],
    )
    await conn.execute(
        """
        INSERT INTO appointments (
            id, clinic_id, patient_id, patient_email, patient_name, slot_id,
            source, appointment_type, clinician, appointment_time,
            slot_value_pence, status, created_at, updated_at
        )
        VALUES ($1, $2, $3, $4, $5, $6, 'recovered', $7, $8, $9, $10, 'booked', $11, $11)
        ON CONFLICT (slot_id) WHERE slot_id IS NOT NULL DO UPDATE
        SET patient_id = EXCLUDED.patient_id,
            patient_email = EXCLUDED.patient_email,
            patient_name = EXCLUDED.patient_name,
            source = 'recovered',
            appointment_type = EXCLUDED.appointment_type,
            clinician = EXCLUDED.clinician,
            appointment_time = EXCLUDED.appointment_time,
            slot_value_pence = EXCLUDED.slot_value_pence,
            status = 'booked',
            updated_at = EXCLUDED.updated_at
        """,
        uuid.uuid4(),
        slot["clinic_id"],
        patient["id"] if patient else None,
        offer["patient_email"],
        patient["patient_name"] if patient else None,
        slot["id"],
        slot["appointment_type"],
        slot["clinician"],
        slot["slot_time"],
        slot["slot_value_pence"],
        now,
    )


async def update_appointment_status(conn, clinic_id: uuid.UUID, appointment_id: uuid.UUID, status: str) -> asyncpg.Record:
    try:
        normalized_status = normalize_appointment_status(status)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    now = datetime.now(timezone.utc)
    current_status = await conn.fetchval(
        """
        SELECT status
        FROM appointments
        WHERE id = $1 AND clinic_id = $2
        """,
        appointment_id,
        clinic_id,
    )
    if current_status is None:
        raise HTTPException(status_code=404, detail="Appointment not found")
    if current_status == "completed" and normalized_status in {"cancelled", "no_show"}:
        raise HTTPException(status_code=400, detail="Completed appointments cannot be cancelled or marked no-show")

    timestamp_field = {
        "completed": "completed_at",
        "cancelled": "cancelled_at",
        "no_show": "no_show_at",
    }.get(normalized_status)
    if timestamp_field:
        row = await conn.fetchrow(
            f"""
            UPDATE appointments
            SET status = $3,
                {timestamp_field} = COALESCE({timestamp_field}, $4),
                updated_at = $4
            WHERE id = $1 AND clinic_id = $2
            RETURNING id::text, patient_id::text, patient_email, patient_name, source,
                      appointment_type, clinician, appointment_time, slot_value_pence,
                      status, notes, completed_at, cancelled_at, no_show_at,
                      created_at, updated_at
            """,
            appointment_id,
            clinic_id,
            normalized_status,
            now,
        )
    else:
        row = await conn.fetchrow(
            """
            UPDATE appointments
            SET status = $3, updated_at = $4
            WHERE id = $1 AND clinic_id = $2
            RETURNING id::text, patient_id::text, patient_email, patient_name, source,
                      appointment_type, clinician, appointment_time, slot_value_pence,
                      status, notes, completed_at, cancelled_at, no_show_at,
                      created_at, updated_at
            """,
            appointment_id,
            clinic_id,
            normalized_status,
            now,
        )
    if not row:
        raise HTTPException(status_code=404, detail="Appointment not found")
    await sync_patient_lifecycle_for_appointment(
        conn,
        clinic_id,
        uuid.UUID(row["patient_id"]) if row["patient_id"] else None,
        normalized_status,
        now,
    )
    return row


@app.post("/broadcast", response_model=BroadcastResponse)
async def broadcast(
    request: DashboardOfferRequest,
    background_tasks: BackgroundTasks,
    http_request: Request,
) -> BroadcastResponse:
    auth_redirect = require_auth(http_request)
    if auth_redirect:
        raise HTTPException(status_code=401, detail="Authentication required")

    clinic_id = http_request.session.get("clinic_id")
    if not clinic_id:
        raise HTTPException(status_code=401, detail="Clinic session missing")

    slot = await create_broadcast_slot(http_request.app.state.pool, request, clinic_id)
    offers = await create_waitlist_offers(http_request.app.state.pool, slot["id"], request.patient_emails, clinic_id)
    background_tasks.add_task(send_waitlist_offer_emails, http_request.app.state.pool, slot, offers)
    background_tasks.add_task(
        log_clinical_event,
        http_request.app.state.pool,
        "broadcast_dispatched",
        clinic_id=clinic_id,
        slot_id=str(slot["id"]),
        client_ip=http_request.client.host if http_request.client else None,
        details={"offers_sent": len(offers), "clinician": request.clinician},
    )
    return await build_broadcast_response(http_request.app.state.pool, slot["id"], clinic_id)


@app.get("/api/broadcasts")
async def api_broadcasts(request: Request):
    auth_redirect = require_auth(request)
    if auth_redirect:
        raise HTTPException(status_code=401, detail="Authentication required")

    clinic_uuid = uuid.UUID(str(get_session_clinic_id(request)))
    async with request.app.state.pool.acquire() as conn:
        rows = await conn.fetch(
            """
            SELECT
                s.id::text AS id,
                s.slot_time,
                s.clinician,
                s.appointment_type,
                s.slot_value_pence,
                s.status,
                s.accepted_by,
                s.created_at,
                s.locked_at,
                COUNT(o.id)::int AS offers_sent,
                (COUNT(o.id) FILTER (WHERE o.status = 'accepted'))::int AS accepted_offers,
                (COUNT(o.id) FILTER (WHERE o.status = 'declined'))::int AS declined_offers,
                (COUNT(o.id) FILTER (WHERE o.status = 'expired'))::int AS expired_offers,
                (COUNT(o.id) FILTER (WHERE o.status = 'sent'))::int AS pending_offers,
                (COUNT(o.id) FILTER (WHERE o.email_send_status = 'sent'))::int AS sent_email_count,
                (COUNT(o.id) FILTER (WHERE o.email_send_status = 'failed'))::int AS failed_email_count
            FROM waitlist_slots s
            LEFT JOIN waitlist_offers o
            ON o.slot_id = s.id
            AND o.clinic_id = s.clinic_id
            WHERE s.clinic_id = $1
            GROUP BY s.id
            ORDER BY s.created_at DESC
            LIMIT 100;
            """,
            clinic_uuid,
        )

    broadcasts = []
    for row in rows:
        effective_status = row["status"]

        if (
            row["status"] == "broadcasting"
            and row["offers_sent"] > 0
            and row["pending_offers"] == 0
            and row["accepted_offers"] == 0
            and row["declined_offers"] > 0
            and row["expired_offers"] == 0
        ):
            effective_status = "declined"

        if (
            row["status"] == "broadcasting"
            and row["offers_sent"] > 0
            and row["pending_offers"] == 0
            and row["accepted_offers"] == 0
            and row["expired_offers"] > 0
        ):
            effective_status = "expired"

        broadcasts.append(
            {
                "id": row["id"],
                "slot_time": iso_or_none(row["slot_time"]),
                "clinician": row["clinician"],
                "appointment_type": row["appointment_type"],
                "slot_value_pence": row["slot_value_pence"],
                "slot_value": row["slot_value_pence"],
                "status": effective_status,
                "accepted_by": row["accepted_by"],
                "created_at": iso_or_none(row["created_at"]),
                "locked_at": iso_or_none(row["locked_at"]),
                "offers_sent": row["offers_sent"],
                "accepted_offers": row["accepted_offers"],
                "declined_offers": row["declined_offers"],
                "expired_offers": row["expired_offers"],
                "pending_offers": row["pending_offers"],
                "sent_email_count": row["sent_email_count"],
                "failed_email_count": row["failed_email_count"],
            }
        )

    return broadcasts


@app.get("/api/appointments")
async def api_appointments(
    request: Request,
    status: str | None = None,
    from_date: datetime | None = None,
    to_date: datetime | None = None,
    limit: int = 100,
):
    auth_redirect = require_auth(request)
    if auth_redirect:
        raise HTTPException(status_code=401, detail="Authentication required")

    clinic_uuid = uuid.UUID(str(get_session_clinic_id(request)))
    status_filter = None
    if status is not None:
        try:
            status_filter = normalize_appointment_status(status)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
    max_limit = max(1, min(safe_int(limit, 100), 500))
    async with request.app.state.pool.acquire() as conn:
        rows = await conn.fetch(
            """
            SELECT
                a.id::text, a.patient_id::text, a.patient_email, a.patient_name,
                a.source, a.appointment_type, a.clinician, a.appointment_time,
                a.slot_value_pence, a.status, a.notes, a.completed_at,
                a.cancelled_at, a.no_show_at, a.created_at, a.updated_at
            FROM appointments a
            WHERE a.clinic_id = $1
              AND ($2::text IS NULL OR a.status = $2)
              AND ($3::timestamptz IS NULL OR a.appointment_time >= $3)
              AND ($4::timestamptz IS NULL OR a.appointment_time <= $4)
            ORDER BY a.appointment_time ASC
            LIMIT $5;
            """,
            clinic_uuid,
            status_filter,
            from_date,
            to_date,
            max_limit,
        )
    return [serialize_appointment(row) for row in rows]


@app.post("/api/appointments")
async def api_create_appointment(request: Request, appointment: AppointmentCreate):
    auth_redirect = require_auth(request)
    if auth_redirect:
        raise HTTPException(status_code=401, detail="Authentication required")

    clinic_uuid = uuid.UUID(str(get_session_clinic_id(request)))
    async with request.app.state.pool.acquire() as conn:
        async with conn.transaction():
            row, _, _ = await create_appointment_record(conn, clinic_uuid, appointment)
    await log_clinical_event(
        request.app.state.pool,
        "appointment_created",
        clinic_id=str(clinic_uuid),
        details={"appointment_id": row["id"], "source": row["source"]},
    )
    return serialize_appointment(row)


@app.patch("/api/appointments/{appointment_id}")
async def api_update_appointment(appointment_id: str, update: AppointmentUpdate, request: Request):
    auth_redirect = require_auth(request)
    if auth_redirect:
        raise HTTPException(status_code=401, detail="Authentication required")

    try:
        appointment_uuid = uuid.UUID(appointment_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail="Appointment not found") from exc
    clinic_uuid = uuid.UUID(str(get_session_clinic_id(request)))
    payload = update.model_dump(exclude_unset=True)
    if "appointment_type" in payload:
        try:
            payload["appointment_type"] = normalize_appointment_type(payload.get("appointment_type"))
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
    if "status" in payload and payload.get("status") is not None:
        try:
            payload["status"] = normalize_appointment_status(payload.get("status"))
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    async with request.app.state.pool.acquire() as conn:
        async with conn.transaction():
            if payload.get("status"):
                await update_appointment_status(conn, clinic_uuid, appointment_uuid, payload.pop("status"))
            fields = [
                field
                for field in ["appointment_type", "clinician", "appointment_time", "slot_value_pence", "notes"]
                if field in payload
            ]
            if fields:
                assignments = []
                values = []
                for index, field in enumerate(fields, start=1):
                    value = payload.get(field)
                    if field in {"clinician", "notes"}:
                        value = clean_optional_string(value)
                    assignments.append(f"{field} = ${index}")
                    values.append(value)
                assignments.append("updated_at = now()")
                values.extend([appointment_uuid, clinic_uuid])
                row = await conn.fetchrow(
                    f"""
                    UPDATE appointments
                    SET {", ".join(assignments)}
                    WHERE id = ${len(values) - 1} AND clinic_id = ${len(values)}
                    RETURNING id::text, patient_id::text, patient_email, patient_name, source,
                              appointment_type, clinician, appointment_time, slot_value_pence,
                              status, notes, completed_at, cancelled_at, no_show_at,
                              created_at, updated_at
                    """,
                    *values,
                )
            else:
                row = await fetch_appointment(conn, appointment_uuid, clinic_uuid)
    if not row:
        raise HTTPException(status_code=404, detail="Appointment not found")
    await log_clinical_event(
        request.app.state.pool,
        "appointment_updated",
        clinic_id=str(clinic_uuid),
        details={"appointment_id": appointment_id, "fields": sorted(update.model_fields_set)},
    )
    if update.status in {"completed", "cancelled", "no_show"}:
        await log_clinical_event(
            request.app.state.pool,
            {
                "completed": "appointment_completed",
                "cancelled": "appointment_cancelled",
                "no_show": "appointment_no_show",
            }[update.status],
            clinic_id=str(clinic_uuid),
            details={"appointment_id": appointment_id},
        )
    return serialize_appointment(row)


async def _appointment_status_endpoint(request: Request, appointment_id: str, status: str, event_type: str):
    auth_redirect = require_auth(request)
    if auth_redirect:
        raise HTTPException(status_code=401, detail="Authentication required")
    try:
        appointment_uuid = uuid.UUID(appointment_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail="Appointment not found") from exc
    clinic_uuid = uuid.UUID(str(get_session_clinic_id(request)))
    async with request.app.state.pool.acquire() as conn:
        async with conn.transaction():
            row = await update_appointment_status(conn, clinic_uuid, appointment_uuid, status)
    await log_clinical_event(
        request.app.state.pool,
        event_type,
        clinic_id=str(clinic_uuid),
        details={"appointment_id": appointment_id},
    )
    return serialize_appointment(row)


@app.post("/api/appointments/{appointment_id}/complete")
async def api_complete_appointment(appointment_id: str, request: Request):
    return await _appointment_status_endpoint(request, appointment_id, "completed", "appointment_completed")


@app.post("/api/appointments/{appointment_id}/cancel")
async def api_cancel_appointment(appointment_id: str, request: Request):
    return await _appointment_status_endpoint(request, appointment_id, "cancelled", "appointment_cancelled")


@app.post("/api/appointments/{appointment_id}/no-show")
async def api_no_show_appointment(appointment_id: str, request: Request):
    return await _appointment_status_endpoint(request, appointment_id, "no_show", "appointment_no_show")


def validate_import_rows(rows: list[dict]) -> tuple[list[tuple[int, AppointmentCreate]], list[dict]]:
    valid = []
    invalid = []
    for index, row in enumerate(rows):
        try:
            appointment = AppointmentCreate(**row)
            normalize_appointment_type(appointment.appointment_type)
            normalize_appointment_source(appointment.source)
            if appointment.slot_value_pence < 0:
                raise ValueError("slot_value_pence cannot be negative")
            valid.append((index, appointment))
        except (ValidationError, ValueError) as exc:
            invalid.append({"index": index, "reason": str(exc), "row": row})
    return valid, invalid


EMAIL_RE = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")
PATIENT_IMPORT_CONSENT_STATUSES = {"consented", "not_consented", "unknown"}


async def validate_patient_import_rows(
    conn,
    clinic_uuid: uuid.UUID,
    rows: list[dict],
) -> tuple[list[tuple[int, dict]], list[dict]]:
    valid: list[tuple[int, dict]] = []
    invalid: list[dict] = []
    seen_emails: set[str] = set()
    normalized_candidates: list[tuple[int, dict]] = []

    for index, row in enumerate(rows):
        raw_email = normalize_email(row.get("email"))
        if not raw_email or not EMAIL_RE.match(raw_email):
            invalid.append({"index": index, "reason": "email is required and must be valid", "row": row})
            continue
        if raw_email in seen_emails:
            invalid.append({"index": index, "reason": "duplicate email in submitted CSV", "row": row})
            continue
        seen_emails.add(raw_email)

        first_name = clean_optional_text(row.get("first_name")) or raw_email.split("@", 1)[0]
        consent_status = (clean_optional_text(row.get("consent_status")) or "unknown").lower()
        if consent_status not in PATIENT_IMPORT_CONSENT_STATUSES:
            invalid.append({"index": index, "reason": "consent_status must be consented, not_consented, or unknown", "row": row})
            continue

        try:
            preferred_type = normalize_appointment_type(row.get("preferred_appointment_type"))
        except ValueError as exc:
            invalid.append({"index": index, "reason": str(exc), "row": row})
            continue

        normalized_candidates.append(
            (
                index,
                {
                    "first_name": first_name,
                    "last_name": clean_optional_text(row.get("last_name")),
                    "email": raw_email,
                    "phone": clean_optional_text(row.get("phone")),
                    "consent_status": consent_status,
                    "priority": clamp_patient_priority(row.get("priority", 3)),
                    "preferred_appointment_type": preferred_type,
                    "preferred_clinician": clean_optional_text(row.get("preferred_clinician")),
                    "notes": clean_optional_text(row.get("notes")),
                },
            )
        )

    if normalized_candidates:
        emails = [row["email"] for _, row in normalized_candidates]
        existing_rows = await conn.fetch(
            """
            SELECT id::text, lower(email) AS email
            FROM patients
            WHERE clinic_id = $1
              AND lower(email) = ANY($2::text[])
            """,
            clinic_uuid,
            emails,
        )
        existing_by_email = {row["email"]: row["id"] for row in existing_rows}
        for index, row in normalized_candidates:
            row["action"] = "update" if row["email"] in existing_by_email else "create"
            if row["email"] in existing_by_email:
                row["existing_patient_id"] = existing_by_email[row["email"]]
            valid.append((index, row))

    return valid, invalid


@app.post("/api/appointments/import-preview")
async def api_appointment_import_preview(payload: AppointmentImportRows, request: Request):
    auth_redirect = require_auth(request)
    if auth_redirect:
        raise HTTPException(status_code=401, detail="Authentication required")
    clinic_id = get_session_clinic_id(request)
    valid, invalid = validate_import_rows(payload.rows)
    await log_clinical_event(
        request.app.state.pool,
        "appointment_import_preview",
        clinic_id=clinic_id,
        details={"valid_rows": len(valid), "invalid_rows": len(invalid), "total_rows": len(payload.rows)},
    )
    return {
        "valid_rows": [row.model_dump(mode="json") for _, row in valid],
        "invalid_rows": invalid,
        "summary": {"valid": len(valid), "invalid": len(invalid), "total": len(payload.rows)},
    }


@app.post("/api/appointments/import-commit")
async def api_appointment_import_commit(payload: AppointmentImportRows, request: Request):
    auth_redirect = require_auth(request)
    if auth_redirect:
        raise HTTPException(status_code=401, detail="Authentication required")
    clinic_uuid = uuid.UUID(str(get_session_clinic_id(request)))
    valid, invalid = validate_import_rows(payload.rows)
    created_appointments = 0
    created_patients = 0
    updated_patients = 0
    errors = list(invalid)
    async with request.app.state.pool.acquire() as conn:
        for index, row in valid:
            try:
                async with conn.transaction():
                    created_row, created_patient, updated_patient = await create_appointment_record(
                        conn,
                        clinic_uuid,
                        row,
                        source_override="import",
                    )
                    created_appointments += 1
                    created_patients += 1 if created_patient else 0
                    updated_patients += 1 if updated_patient and not created_patient else 0
            except Exception as exc:
                errors.append({"index": index, "reason": str(exc), "row": row.model_dump(mode="json")})
    await log_clinical_event(
        request.app.state.pool,
        "appointment_imported",
        clinic_id=str(clinic_uuid),
        details={"created_appointments": created_appointments, "errors": len(errors)},
    )
    return {
        "created_appointments": created_appointments,
        "created_patients": created_patients,
        "updated_patients": updated_patients,
        "errors": errors,
    }


@app.get("/api/appointments/recovered")
async def api_recovered_appointments(request: Request):
    auth_redirect = require_auth(request)
    if auth_redirect:
        raise HTTPException(status_code=401, detail="Authentication required")

    clinic_uuid = uuid.UUID(str(get_session_clinic_id(request)))
    async with request.app.state.pool.acquire() as conn:
        rows = await conn.fetch(
            """
            SELECT id::text, patient_email AS patient, appointment_time AS slot_time,
                   clinician, appointment_type, slot_value_pence, status,
                   created_at AS confirmed_at
            FROM appointments
            WHERE clinic_id = $1
              AND source = 'recovered'
              AND status IN ('booked', 'completed')
            ORDER BY appointment_time DESC
            LIMIT 100;
            """,
            clinic_uuid,
        )
    return [
        {
            "id": row["id"],
            "patient": row["patient"],
            "slot_time": iso_or_none(row["slot_time"]),
            "clinician": row["clinician"],
            "appointment_type": row["appointment_type"],
            "slot_value_pence": row["slot_value_pence"],
            "status": row["status"],
            "confirmed_at": iso_or_none(row["confirmed_at"]),
        }
        for row in rows
    ]


@app.get("/api/analytics/summary")
async def api_analytics_summary(request: Request):
    auth_redirect = require_auth(request)
    if auth_redirect:
        raise HTTPException(status_code=401, detail="Authentication required")

    clinic_uuid = uuid.UUID(str(get_session_clinic_id(request)))
    async with request.app.state.pool.acquire() as conn:
        slot_summary = await conn.fetchrow(
            """
            SELECT
                COUNT(*)::int AS total_broadcasts,
                (COUNT(*) FILTER (WHERE status = 'locked' OR accepted_by IS NOT NULL))::int AS slots_recovered,
                COALESCE(SUM(slot_value_pence), 0)::int AS total_revenue_at_risk_pence,
                COALESCE(SUM(slot_value_pence) FILTER (WHERE status = 'locked' OR accepted_by IS NOT NULL), 0)::int AS total_revenue_saved_pence,
                AVG(slot_value_pence) FILTER (WHERE status = 'locked' OR accepted_by IS NOT NULL)::float AS average_recovered_slot_value_pence
            FROM waitlist_slots
            WHERE clinic_id = $1;
            """,
            clinic_uuid,
        )
        offer_summary = await conn.fetchrow(
            """
            SELECT
                COUNT(*)::int AS offers_sent,
                (COUNT(*) FILTER (WHERE status = 'accepted'))::int AS accepted_offers,
                (COUNT(*) FILTER (WHERE status = 'declined'))::int AS declined_offers,
                (COUNT(*) FILTER (WHERE status = 'expired'))::int AS expired_offers,
                (COUNT(*) FILTER (WHERE status = 'sent'))::int AS pending_offers,
                (AVG(EXTRACT(EPOCH FROM (accepted_at - created_at)) / 60)
                    FILTER (WHERE status = 'accepted' AND accepted_at IS NOT NULL))::float AS avg_response_minutes
            FROM waitlist_offers
            WHERE clinic_id = $1;
            """,
            clinic_uuid,
        )
        top_rows = await conn.fetch(
            """
            SELECT COALESCE(NULLIF(clinician, ''), 'Unassigned') AS clinician,
                   COUNT(*)::int AS recovered
            FROM waitlist_slots
            WHERE clinic_id = $1
              AND (status = 'locked' OR accepted_by IS NOT NULL)
            GROUP BY COALESCE(NULLIF(clinician, ''), 'Unassigned')
            ORDER BY recovered DESC, clinician ASC
            LIMIT 5;
            """,
            clinic_uuid,
        )
        appointment_summary = await conn.fetchrow(
            """
            SELECT
                (COUNT(*) FILTER (WHERE status = 'booked'))::int AS booked_appointments,
                (COUNT(*) FILTER (WHERE status = 'completed'))::int AS completed_appointments,
                (COUNT(*) FILTER (WHERE status = 'cancelled'))::int AS cancelled_appointments,
                (COUNT(*) FILTER (WHERE status = 'no_show'))::int AS no_show_appointments,
                COALESCE(SUM(slot_value_pence) FILTER (WHERE status = 'completed'), 0)::int AS total_completed_revenue_pence
            FROM appointments
            WHERE clinic_id = $1;
            """,
            clinic_uuid,
        )

    total_broadcasts = slot_summary["total_broadcasts"] if slot_summary else 0
    slots_recovered = slot_summary["slots_recovered"] if slot_summary else 0
    recovery_rate = round((slots_recovered / total_broadcasts) * 100, 1) if total_broadcasts else 0.0
    avg_response = offer_summary["avg_response_minutes"] if offer_summary else None
    avg_recovered_value = slot_summary["average_recovered_slot_value_pence"] if slot_summary else None

    return {
        "total_broadcasts": total_broadcasts,
        "offers_sent": offer_summary["offers_sent"] if offer_summary else 0,
        "slots_recovered": slots_recovered,
        "recovery_rate": recovery_rate,
        "accepted_offers": offer_summary["accepted_offers"] if offer_summary else 0,
        "declined_offers": offer_summary["declined_offers"] if offer_summary else 0,
        "expired_offers": offer_summary["expired_offers"] if offer_summary else 0,
        "pending_offers": offer_summary["pending_offers"] if offer_summary else 0,
        "avg_response_minutes": round(avg_response, 1) if avg_response is not None else None,
        "total_revenue_saved_pence": slot_summary["total_revenue_saved_pence"] if slot_summary else 0,
        "total_revenue_at_risk_pence": slot_summary["total_revenue_at_risk_pence"] if slot_summary else 0,
        "average_recovered_slot_value_pence": round(avg_recovered_value) if avg_recovered_value is not None else None,
        "booked_appointments": appointment_summary["booked_appointments"] if appointment_summary else 0,
        "completed_appointments": appointment_summary["completed_appointments"] if appointment_summary else 0,
        "cancelled_appointments": appointment_summary["cancelled_appointments"] if appointment_summary else 0,
        "no_show_appointments": appointment_summary["no_show_appointments"] if appointment_summary else 0,
        "total_completed_revenue_pence": appointment_summary["total_completed_revenue_pence"] if appointment_summary else 0,
        "top_clinicians": [
            {"clinician": row["clinician"], "recovered": row["recovered"]}
            for row in top_rows
        ],
        "total_revenue_saved": None,
    }


def parse_audit_details(value) -> dict | str | None:
    if value is None:
        return None
    if isinstance(value, dict):
        return value
    try:
        return json.loads(value)
    except Exception:
        return str(value)


@app.get("/api/activity")
async def api_activity(request: Request, limit: int = 50, event_type: str | None = None):
    auth_redirect = require_auth(request)
    if auth_redirect:
        raise HTTPException(status_code=401, detail="Authentication required")

    clinic_uuid = uuid.UUID(str(get_session_clinic_id(request)))
    max_limit = max(1, min(safe_int(limit, 50), 100))
    event_filter = clean_optional_text(event_type)
    async with request.app.state.pool.acquire() as conn:
        rows = await conn.fetch(
            """
            SELECT id::text, event_type, slot_id::text, offer_id::text,
                   patient_email_hash, success, details, created_at
            FROM audit_log
            WHERE clinic_id = $1
              AND ($2::text IS NULL OR event_type = $2)
            ORDER BY created_at DESC
            LIMIT $3
            """,
            clinic_uuid,
            event_filter,
            max_limit,
        )
    return {
        "events": [
            {
                "id": row["id"],
                "event_type": row["event_type"],
                "slot_id": row["slot_id"],
                "offer_id": row["offer_id"],
                "patient_email_hash": row["patient_email_hash"],
                "success": row["success"],
                "details": parse_audit_details(row["details"]),
                "created_at": iso_or_none(row["created_at"]),
            }
            for row in rows
        ]
    }


@app.get("/api/export/clinic-summary")
async def api_export_clinic_summary(request: Request):
    auth_redirect = require_auth(request)
    if auth_redirect:
        raise HTTPException(status_code=401, detail="Authentication required")

    clinic_id = get_session_clinic_id(request)
    clinic_uuid = uuid.UUID(str(clinic_id))
    clinic_settings = await get_clinic_settings(request.app.state.pool, clinic_id)
    async with request.app.state.pool.acquire() as conn:
        lifecycle_rows = await conn.fetch(
            """
            SELECT lifecycle_status, COUNT(*)::int AS count
            FROM patients
            WHERE clinic_id = $1
            GROUP BY lifecycle_status
            """,
            clinic_uuid,
        )
        appointment_rows = await conn.fetch(
            """
            SELECT status, COUNT(*)::int AS count
            FROM appointments
            WHERE clinic_id = $1
            GROUP BY status
            """,
            clinic_uuid,
        )
        offer_rows = await conn.fetch(
            """
            SELECT status, COUNT(*)::int AS count
            FROM waitlist_offers
            WHERE clinic_id = $1
            GROUP BY status
            """,
            clinic_uuid,
        )
        totals = await conn.fetchrow(
            """
            SELECT
                (SELECT COUNT(*)::int FROM waitlist_slots WHERE clinic_id = $1) AS broadcast_count,
                (SELECT COALESCE(SUM(slot_value_pence), 0)::int
                   FROM waitlist_slots
                   WHERE clinic_id = $1 AND (status = 'locked' OR accepted_by IS NOT NULL)) AS revenue_saved_pence
            """,
            clinic_uuid,
        )
    await log_clinical_event(
        request.app.state.pool,
        "clinic_summary_exported",
        clinic_id=clinic_id,
    )
    return {
        "clinic_settings": {
            "clinic_name": clinic_settings["clinic_name"],
            "contact_email": clinic_settings["contact_email"],
            "phone": clinic_settings["phone"],
            "reply_to_email": clinic_settings["reply_to_email"],
            "default_slot_value_pence": clinic_settings["default_slot_value_pence"],
            "default_expiry_minutes": clinic_settings["default_expiry_minutes"],
            "gdpr_notice": clinic_settings["gdpr_notice"],
        },
        "patients_by_lifecycle_status": {row["lifecycle_status"] or "unknown": row["count"] for row in lifecycle_rows},
        "appointments_by_status": {row["status"] or "unknown": row["count"] for row in appointment_rows},
        "broadcast_count": totals["broadcast_count"] if totals else 0,
        "offers_by_status": {row["status"] or "unknown": row["count"] for row in offer_rows},
        "revenue_saved_pence": totals["revenue_saved_pence"] if totals else 0,
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }


@app.post("/api/patients/import-preview")
async def api_patient_import_preview(payload: PatientImportRows, request: Request):
    auth_redirect = require_auth(request)
    if auth_redirect:
        raise HTTPException(status_code=401, detail="Authentication required")

    clinic_uuid = uuid.UUID(str(get_session_clinic_id(request)))
    async with request.app.state.pool.acquire() as conn:
        valid, invalid = await validate_patient_import_rows(conn, clinic_uuid, payload.rows)
    await log_clinical_event(
        request.app.state.pool,
        "patient_import_preview",
        clinic_id=str(clinic_uuid),
        details={"valid_rows": len(valid), "invalid_rows": len(invalid), "total_rows": len(payload.rows)},
    )
    valid_rows = [row for _, row in valid]
    return {
        "valid_rows": valid_rows,
        "invalid_rows": invalid,
        "summary": {
            "valid": len(valid),
            "invalid": len(invalid),
            "total": len(payload.rows),
            "creates": sum(1 for row in valid_rows if row.get("action") == "create"),
            "updates": sum(1 for row in valid_rows if row.get("action") == "update"),
        },
    }


@app.post("/api/patients/import-commit")
async def api_patient_import_commit(payload: PatientImportRows, request: Request):
    auth_redirect = require_auth(request)
    if auth_redirect:
        raise HTTPException(status_code=401, detail="Authentication required")

    clinic_uuid = uuid.UUID(str(get_session_clinic_id(request)))
    created_patients = 0
    updated_patients = 0
    skipped_rows = 0
    errors = []
    now = datetime.now(timezone.utc)

    async with request.app.state.pool.acquire() as conn:
        valid, invalid = await validate_patient_import_rows(conn, clinic_uuid, payload.rows)
        errors.extend(invalid)
        skipped_rows += len(invalid)
        for index, row in valid:
            try:
                consented_at = now if row["consent_status"] == "consented" else None
                if row.get("action") == "update":
                    await conn.execute(
                        """
                        UPDATE patients
                        SET first_name = $3,
                            last_name = $4,
                            phone = $5,
                            consent_status = $6,
                            consented_at = CASE
                                WHEN $6 = 'consented' THEN COALESCE(consented_at, $7)
                                ELSE consented_at
                            END,
                            notes = $8,
                            priority = $9,
                            preferred_appointment_type = $10,
                            preferred_clinician = $11,
                            archived_at = NULL,
                            lifecycle_status = CASE
                                WHEN lifecycle_status = 'archived' THEN 'waitlist'
                                ELSE lifecycle_status
                            END,
                            updated_at = $7
                        WHERE clinic_id = $1 AND lower(email) = lower($2)
                        """,
                        clinic_uuid,
                        row["email"],
                        row["first_name"],
                        row["last_name"],
                        row["phone"],
                        row["consent_status"],
                        now,
                        row["notes"],
                        row["priority"],
                        row["preferred_appointment_type"],
                        row["preferred_clinician"],
                    )
                    updated_patients += 1
                else:
                    await conn.execute(
                        """
                        INSERT INTO patients (
                            id, clinic_id, first_name, last_name, email, phone,
                            consent_status, consent_source, consented_at, notes,
                            priority, preferred_appointment_type, preferred_clinician,
                            lifecycle_status
                        )
                        VALUES ($1, $2, $3, $4, $5, $6, $7, 'csv_import', $8, $9, $10, $11, $12, 'waitlist')
                        """,
                        uuid.uuid4(),
                        clinic_uuid,
                        row["first_name"],
                        row["last_name"],
                        row["email"],
                        row["phone"],
                        row["consent_status"],
                        consented_at,
                        row["notes"],
                        row["priority"],
                        row["preferred_appointment_type"],
                        row["preferred_clinician"],
                    )
                    created_patients += 1
            except Exception as exc:
                skipped_rows += 1
                errors.append({"index": index, "reason": str(exc), "row": row})

    await log_clinical_event(
        request.app.state.pool,
        "patient_imported",
        clinic_id=str(clinic_uuid),
        details={
            "created_patients": created_patients,
            "updated_patients": updated_patients,
            "skipped_rows": skipped_rows,
            "errors": len(errors),
        },
    )
    return {
        "created_patients": created_patients,
        "updated_patients": updated_patients,
        "skipped_rows": skipped_rows,
        "errors": errors,
    }


@app.get("/api/patients")
async def api_patients(
    request: Request,
    include_archived: bool = False,
    lifecycle_status: str | None = None,
):
    auth_redirect = require_auth(request)
    if auth_redirect:
        raise HTTPException(status_code=401, detail="Authentication required")

    clinic_uuid = uuid.UUID(str(get_session_clinic_id(request)))
    lifecycle_filter = None
    if lifecycle_status is not None:
        try:
            lifecycle_filter = normalize_lifecycle_status(lifecycle_status)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
    async with request.app.state.pool.acquire() as conn:
        rows = await conn.fetch(
            """
            SELECT id::text, first_name, last_name, email, phone, consent_status,
                   consent_source, consented_at, notes, priority, preferred_appointment_type,
                   preferred_clinician, last_contacted_at, last_response_at,
                   accepted_count, declined_count, offer_count, lifecycle_status,
                   booked_at, completed_at, archived_at,
                   created_at, updated_at
            FROM patients
            WHERE clinic_id = $1
              AND ($2::boolean OR archived_at IS NULL)
              AND ($3::text IS NULL OR lifecycle_status = $3)
            ORDER BY created_at DESC;
            """,
            clinic_uuid,
            include_archived,
            lifecycle_filter,
        )

    patients = [serialize_patient(row) for row in rows]
    return {
        "patients": patients,
        "total": len(patients),
        "consented": sum(1 for patient in patients if patient["consent_status"] == "consented"),
    }


@app.get("/api/patients/{patient_id}/export")
async def api_patient_export(patient_id: str, request: Request):
    auth_redirect = require_auth(request)
    if auth_redirect:
        raise HTTPException(status_code=401, detail="Authentication required")

    try:
        patient_uuid = uuid.UUID(patient_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail="Patient not found") from exc

    clinic_uuid = uuid.UUID(str(get_session_clinic_id(request)))
    async with request.app.state.pool.acquire() as conn:
        patient = await conn.fetchrow(
            """
            SELECT id::text, first_name, last_name, email, phone, consent_status,
                   consent_source, consented_at, notes, priority, preferred_appointment_type,
                   preferred_clinician, last_contacted_at, last_response_at,
                   accepted_count, declined_count, offer_count, lifecycle_status,
                   booked_at, completed_at, archived_at,
                   created_at, updated_at
            FROM patients
            WHERE id = $1 AND clinic_id = $2
            """,
            patient_uuid,
            clinic_uuid,
        )
        if not patient:
            raise HTTPException(status_code=404, detail="Patient not found")
        email = patient["email"]
        offers = await conn.fetch(
            """
            SELECT o.id::text, o.slot_id::text, o.status, o.email_send_status,
                   o.sent_at, o.failed_at, o.created_at, o.accepted_at, o.declined_at,
                   s.slot_time, s.clinician, s.appointment_type
            FROM waitlist_offers o
            LEFT JOIN waitlist_slots s ON s.id = o.slot_id AND s.clinic_id = o.clinic_id
            WHERE o.clinic_id = $1 AND lower(o.patient_email) = lower($2)
            ORDER BY o.created_at DESC
            """,
            clinic_uuid,
            email,
        )
        appointments = await conn.fetch(
            """
            SELECT id::text, patient_id::text, patient_email, patient_name, source,
                   appointment_type, clinician, appointment_time, slot_value_pence,
                   status, notes, completed_at, cancelled_at, no_show_at,
                   created_at, updated_at
            FROM appointments
            WHERE clinic_id = $1
              AND (patient_id = $2 OR lower(patient_email) = lower($3))
            ORDER BY appointment_time DESC
            """,
            clinic_uuid,
            patient_uuid,
            email,
        )
        email_hash = hashlib.sha256(email.strip().lower().encode("utf-8")).hexdigest()
        audit_rows = await conn.fetch(
            """
            SELECT event_type, success, created_at
            FROM audit_log
            WHERE clinic_id = $1 AND patient_email_hash = $2
            ORDER BY created_at DESC
            LIMIT 100
            """,
            clinic_uuid,
            email_hash,
        )

    await log_clinical_event(
        request.app.state.pool,
        "patient_data_exported",
        clinic_id=str(clinic_uuid),
        patient_email=email,
        details={"patient_id": patient_id},
    )
    return {
        "patient": serialize_patient(patient),
        "offers": [
            {
                "id": row["id"],
                "slot_id": row["slot_id"],
                "status": row["status"],
                "email_send_status": row["email_send_status"],
                "sent_at": iso_or_none(row["sent_at"]),
                "failed_at": iso_or_none(row["failed_at"]),
                "created_at": iso_or_none(row["created_at"]),
                "accepted_at": iso_or_none(row["accepted_at"]),
                "declined_at": iso_or_none(row["declined_at"]),
                "slot_time": iso_or_none(row["slot_time"]),
                "clinician": row["clinician"],
                "appointment_type": row["appointment_type"],
            }
            for row in offers
        ],
        "appointments": [serialize_appointment(row) for row in appointments],
        "audit_summary": [
            {
                "event_type": row["event_type"],
                "success": row["success"],
                "created_at": iso_or_none(row["created_at"]),
            }
            for row in audit_rows
        ],
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }


@app.post("/api/patients")
async def api_create_patient(request: Request, patient: PatientCreate):
    auth_redirect = require_auth(request)
    if auth_redirect:
        raise HTTPException(status_code=401, detail="Authentication required")

    clinic_uuid = uuid.UUID(str(get_session_clinic_id(request)))
    patient_id = uuid.uuid4()
    email = str(patient.email).lower().strip()
    consented_at = datetime.now(timezone.utc) if patient.consent_status == "consented" else None
    try:
        preferred_appointment_type = normalize_appointment_type(patient.preferred_appointment_type)
        lifecycle_status = normalize_lifecycle_status(patient.lifecycle_status)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    preferred_clinician = clean_optional_string(patient.preferred_clinician)
    now = datetime.now(timezone.utc)
    booked_at = now if lifecycle_status == "booked" else None
    completed_at = now if lifecycle_status == "completed" else None
    archived_at = now if lifecycle_status in {"archived", "completed"} else None

    try:
        async with request.app.state.pool.acquire() as conn:
            row = await conn.fetchrow(
                """
                INSERT INTO patients (
                    id, clinic_id, first_name, last_name, email, phone,
                    consent_status, consent_source, consented_at, notes,
                    priority, preferred_appointment_type, preferred_clinician,
                    lifecycle_status, booked_at, completed_at, archived_at
                )
                VALUES ($1, $2, $3, $4, $5, $6, $7, 'manual', $8, $9, $10, $11, $12, $13, $14, $15, $16)
                RETURNING id::text, first_name, last_name, email, phone, consent_status,
                          consent_source, consented_at, notes, priority,
                          preferred_appointment_type, preferred_clinician,
                          last_contacted_at, last_response_at, accepted_count,
                          declined_count, offer_count, lifecycle_status,
                          booked_at, completed_at, archived_at, created_at, updated_at;
                """,
                patient_id,
                clinic_uuid,
                patient.first_name.strip(),
                clean_optional_string(patient.last_name),
                email,
                clean_optional_string(patient.phone),
                patient.consent_status,
                consented_at,
                clean_optional_string(patient.notes),
                patient.priority,
                preferred_appointment_type,
                preferred_clinician,
                lifecycle_status,
                booked_at,
                completed_at,
                archived_at,
            )
    except asyncpg.UniqueViolationError:
        return JSONResponse({"error": "Patient already exists on this waitlist"}, status_code=400)

    return serialize_patient(row)


@app.patch("/api/patients/{patient_id}")
async def api_update_patient(patient_id: str, update: PatientUpdate, request: Request):
    auth_redirect = require_auth(request)
    if auth_redirect:
        raise HTTPException(status_code=401, detail="Authentication required")

    try:
        patient_uuid = uuid.UUID(patient_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail="Patient not found") from exc

    clinic_uuid = uuid.UUID(str(get_session_clinic_id(request)))
    payload = update.model_dump(exclude_unset=True)
    allowed_fields = {
        "first_name",
        "last_name",
        "email",
        "phone",
        "consent_status",
        "notes",
        "priority",
        "preferred_appointment_type",
        "preferred_clinician",
        "lifecycle_status",
    }
    fields = [field for field in update.model_fields_set if field in allowed_fields]
    if "first_name" in fields and payload.get("first_name") is None:
        raise HTTPException(status_code=400, detail="first_name cannot be empty")
    if "preferred_appointment_type" in fields:
        try:
            payload["preferred_appointment_type"] = normalize_appointment_type(payload.get("preferred_appointment_type"))
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
    if "lifecycle_status" in fields and payload.get("lifecycle_status") is None:
        raise HTTPException(status_code=400, detail="lifecycle_status must be waitlist, booked, completed, or archived")
    if "lifecycle_status" in fields:
        try:
            payload["lifecycle_status"] = normalize_lifecycle_status(payload.get("lifecycle_status"))
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    if not fields:
        async with request.app.state.pool.acquire() as conn:
            row = await conn.fetchrow(
                """
                SELECT id::text, first_name, last_name, email, phone, consent_status,
                       consent_source, consented_at, notes, priority, preferred_appointment_type,
                       preferred_clinician, last_contacted_at, last_response_at,
                       accepted_count, declined_count, offer_count, lifecycle_status,
                       booked_at, completed_at, archived_at,
                       created_at, updated_at
                FROM patients
                WHERE id = $1 AND clinic_id = $2 AND archived_at IS NULL
                """,
                patient_uuid,
                clinic_uuid,
            )
        if not row:
            raise HTTPException(status_code=404, detail="Patient not found")
        return serialize_patient(row)

    assignments = []
    values = []
    for index, field in enumerate(fields, start=1):
        value = payload.get(field)
        if field == "email" and value is not None:
            value = str(value).lower().strip()
        elif field in {
            "first_name",
            "last_name",
            "phone",
            "consent_status",
            "notes",
            "preferred_appointment_type",
            "preferred_clinician",
            "lifecycle_status",
        }:
            value = clean_optional_string(value)
        assignments.append(f"{field} = ${index}")
        values.append(value)

    if "consent_status" in fields and payload.get("consent_status") == "consented":
        assignments.append("consented_at = COALESCE(consented_at, now())")
    lifecycle_value = payload.get("lifecycle_status") if "lifecycle_status" in fields else None
    if lifecycle_value == "booked":
        assignments.append("booked_at = COALESCE(booked_at, now())")
    if lifecycle_value == "completed":
        assignments.append("completed_at = COALESCE(completed_at, now())")
    if lifecycle_value in {"archived", "completed"}:
        assignments.append("archived_at = COALESCE(archived_at, now())")
    assignments.append("updated_at = now()")
    values.extend([patient_uuid, clinic_uuid])

    try:
        async with request.app.state.pool.acquire() as conn:
            row = await conn.fetchrow(
                f"""
                UPDATE patients
                SET {", ".join(assignments)}
                WHERE id = ${len(values) - 1}
                  AND clinic_id = ${len(values)}
                  AND archived_at IS NULL
                RETURNING id::text, first_name, last_name, email, phone, consent_status,
                          consent_source, consented_at, notes, priority,
                          preferred_appointment_type, preferred_clinician,
                          last_contacted_at, last_response_at, accepted_count,
                          declined_count, offer_count, lifecycle_status,
                          booked_at, completed_at, archived_at, created_at, updated_at;
                """,
                *values,
            )
    except asyncpg.UniqueViolationError:
        return JSONResponse({"error": "Patient already exists on this waitlist"}, status_code=400)

    if not row:
        raise HTTPException(status_code=404, detail="Patient not found")
    return serialize_patient(row)


@app.post("/api/patients/{patient_id}/archive")
async def api_archive_patient(patient_id: str, request: Request):
    auth_redirect = require_auth(request)
    if auth_redirect:
        raise HTTPException(status_code=401, detail="Authentication required")

    try:
        patient_uuid = uuid.UUID(patient_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail="Patient not found") from exc

    clinic_uuid = uuid.UUID(str(get_session_clinic_id(request)))
    async with request.app.state.pool.acquire() as conn:
        result = await conn.execute(
            """
            UPDATE patients
            SET lifecycle_status = 'archived',
                archived_at = COALESCE(archived_at, now()),
                updated_at = now()
            WHERE id = $1 AND clinic_id = $2 AND archived_at IS NULL
            """,
            patient_uuid,
            clinic_uuid,
        )
    if result.endswith(" 0"):
        raise HTTPException(status_code=404, detail="Patient not found")
    return {"status": "archived"}


@app.post("/api/patients/{patient_id}/mark-booked")
async def api_mark_patient_booked(patient_id: str, request: Request):
    auth_redirect = require_auth(request)
    if auth_redirect:
        raise HTTPException(status_code=401, detail="Authentication required")

    try:
        patient_uuid = uuid.UUID(patient_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail="Patient not found") from exc

    clinic_uuid = uuid.UUID(str(get_session_clinic_id(request)))
    async with request.app.state.pool.acquire() as conn:
        result = await conn.execute(
            """
            UPDATE patients
            SET lifecycle_status = 'booked',
                booked_at = COALESCE(booked_at, now()),
                updated_at = now()
            WHERE id = $1 AND clinic_id = $2 AND archived_at IS NULL
            """,
            patient_uuid,
            clinic_uuid,
        )
    if result.endswith(" 0"):
        raise HTTPException(status_code=404, detail="Patient not found")
    return {"status": "booked"}


@app.post("/api/patients/{patient_id}/mark-completed")
async def api_mark_patient_completed(patient_id: str, request: Request):
    auth_redirect = require_auth(request)
    if auth_redirect:
        raise HTTPException(status_code=401, detail="Authentication required")

    try:
        patient_uuid = uuid.UUID(patient_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail="Patient not found") from exc

    clinic_uuid = uuid.UUID(str(get_session_clinic_id(request)))
    async with request.app.state.pool.acquire() as conn:
        result = await conn.execute(
            """
            UPDATE patients
            SET lifecycle_status = 'completed',
                completed_at = COALESCE(completed_at, now()),
                archived_at = COALESCE(archived_at, now()),
                updated_at = now()
            WHERE id = $1 AND clinic_id = $2
            """,
            patient_uuid,
            clinic_uuid,
        )
    if result.endswith(" 0"):
        raise HTTPException(status_code=404, detail="Patient not found")
    return {"status": "completed"}


@app.get("/api/recovery/recommendations")
async def api_recovery_recommendations(
    request: Request,
    appointment_type: str | None = None,
    clinician: str | None = None,
    limit: int = 10,
):
    auth_redirect = require_auth(request)
    if auth_redirect:
        raise HTTPException(status_code=401, detail="Authentication required")

    clinic_uuid = uuid.UUID(str(get_session_clinic_id(request)))
    try:
        appointment_type_norm = normalize_appointment_type(appointment_type)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    clinician_norm = clean_optional_string(clinician)
    max_limit = max(1, min(safe_int(limit, 10), 50))
    now = datetime.now(timezone.utc)

    async with request.app.state.pool.acquire() as conn:
        rows = await conn.fetch(
            """
            SELECT id::text, first_name, last_name, email, phone, priority,
                   preferred_appointment_type, preferred_clinician,
                   last_contacted_at, last_response_at, accepted_count,
                   declined_count, offer_count, lifecycle_status
            FROM patients
            WHERE clinic_id = $1
              AND consent_status = 'consented'
              AND archived_at IS NULL
              AND lifecycle_status = 'waitlist'
            """,
            clinic_uuid,
        )

    recommendations = []
    for row in rows:
        score = 100
        priority = clamp_patient_priority(row["priority"])
        accepted_count = safe_int(row["accepted_count"], 0)
        declined_count = safe_int(row["declined_count"], 0)
        offer_count = safe_int(row["offer_count"], 0)
        score -= priority * 8
        score += accepted_count * 12
        score -= declined_count * 4
        score -= offer_count
        reason_labels = []

        if priority <= 2:
            reason_labels.append("High priority")
        if appointment_type_norm and row["preferred_appointment_type"]:
            if row["preferred_appointment_type"].strip().lower() == appointment_type_norm.lower():
                score += 15
                reason_labels.append("Matches appointment type")
        if clinician_norm and row["preferred_clinician"]:
            if row["preferred_clinician"].strip().lower() == clinician_norm.lower():
                score += 10
                reason_labels.append("Matches clinician")
        if accepted_count > 0:
            reason_labels.append("Accepted before")
        if accepted_count == 0 and declined_count == 0:
            reason_labels.append("No response history")

        last_contacted_at = row["last_contacted_at"]
        if last_contacted_at:
            if last_contacted_at.tzinfo is None:
                last_contacted_at = last_contacted_at.replace(tzinfo=timezone.utc)
            age = now - last_contacted_at
            if age <= timedelta(hours=24):
                score -= 25
                reason_labels.append("Recently contacted")
            elif age <= timedelta(days=7):
                score -= 10
                reason_labels.append("Recently contacted")

        recommendations.append(
            {
                "id": row["id"],
                "first_name": row["first_name"],
                "last_name": row["last_name"],
                "email": row["email"],
                "phone": row["phone"],
                "priority": priority,
                "preferred_appointment_type": row["preferred_appointment_type"],
                "preferred_clinician": row["preferred_clinician"],
                "accepted_count": accepted_count,
                "declined_count": declined_count,
                "offer_count": offer_count,
                "lifecycle_status": row["lifecycle_status"],
                "last_contacted_at": iso_or_none(row["last_contacted_at"]),
                "last_response_at": iso_or_none(row["last_response_at"]),
                "score": score,
                "reason_labels": reason_labels,
            }
        )

    recommendations.sort(key=lambda item: item["score"], reverse=True)
    return {"recommendations": recommendations[:max_limit]}


@app.get("/slot-status/{slot_id}", response_model=SlotStatusResponse)
async def slot_status(slot_id: str, request: Request) -> SlotStatusResponse:
    auth_redirect = require_auth(request)
    if auth_redirect:
        raise HTTPException(status_code=401, detail="Authentication required")

    clinic_id = get_session_clinic_id(request)
    slot = await get_slot_or_404(request.app.state.pool, slot_id, clinic_id)
    await expire_stale_offers(request.app.state.pool, slot_id, clinic_id)
    slot = await get_slot_or_404(request.app.state.pool, slot_id, clinic_id)
    return await build_slot_status_response(request.app.state.pool, slot)


@app.get("/api/debug/slot/{slot_id}")
async def api_debug_slot(slot_id: str, request: Request):
    if os.getenv("ALLOW_DEBUG_ENDPOINTS", "").lower() != "true":
        raise HTTPException(status_code=404, detail="Not found")

    auth_redirect = require_auth(request)
    if auth_redirect:
        raise HTTPException(status_code=401, detail="Authentication required")

    try:
        slot_uuid = uuid.UUID(slot_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail="Slot not found") from exc

    clinic_uuid = uuid.UUID(str(get_session_clinic_id(request)))
    async with request.app.state.pool.acquire() as conn:
        slot = await conn.fetchrow(
            """
            SELECT id::text, status, accepted_by, locked_at
            FROM waitlist_slots
            WHERE id = $1 AND clinic_id = $2
            """,
            slot_uuid,
            clinic_uuid,
        )
        if not slot:
            raise HTTPException(status_code=404, detail="Slot not found")

        offer_rows = await conn.fetch(
            """
            SELECT patient_email, status, accepted_at, declined_at, created_at
            FROM waitlist_offers
            WHERE slot_id = $1 AND clinic_id = $2
            ORDER BY created_at ASC
            """,
            slot_uuid,
            clinic_uuid,
        )

    return {
        "id": slot["id"],
        "status": slot["status"],
        "accepted_by": slot["accepted_by"],
        "locked_at": iso_or_none(slot["locked_at"]),
        "offers": [
            {
                "patient_email": row["patient_email"],
                "status": row["status"],
                "accepted_at": iso_or_none(row["accepted_at"]),
                "declined_at": iso_or_none(row["declined_at"]),
                "created_at": iso_or_none(row["created_at"]),
            }
            for row in offer_rows
        ],
    }


@app.get("/offer/{token}", response_class=HTMLResponse)
async def view_offer(token: str, request: Request) -> HTMLResponse:
    offer_id = verify_secure_token(token)
    if not offer_id:
        return HTMLResponse(
            "<h1>Link Expired or Invalid</h1><p>This invitation is no longer valid.</p>",
            status_code=400,
        )

    pool: asyncpg.Pool = request.app.state.pool
    offer = await db_get_offer_with_slot(pool, offer_id)
    if not offer:
        return HTMLResponse(
            "<h1>Offer Not Found</h1><p>This appointment offer may have expired.</p>",
            status_code=404,
        )

    clinic_settings = await get_clinic_settings(pool, str(offer["clinic_id"]))
    clinic_name = html.escape(clinic_settings["clinic_name"])
    slot_time = offer["slot_time"].astimezone(timezone.utc).strftime("%A %d %B at %H:%M UTC")
    clinician = html.escape(offer["clinician"] or "your clinician")
    appointment_type = html.escape(offer["appointment_type"]) if offer["appointment_type"] else ""
    status = html.escape(offer["offer_status"])
    expiry = ""
    if offer["offer_expires_at"]:
        expiry_time = offer["offer_expires_at"].astimezone(timezone.utc).strftime("%A %d %B at %H:%M UTC")
        expiry = f'<div class="row"><span class="label">Expires</span><span class="value">{html.escape(expiry_time)}</span></div>'

    return HTMLResponse(
        f"""
        <!DOCTYPE html>
        <html lang="en">
        <head>
          <meta charset="UTF-8">
          <meta name="viewport" content="width=device-width, initial-scale=1.0">
          <title>Appointment Offer - {clinic_name}</title>
          <style>
            * {{ box-sizing: border-box; }}
            body {{
              margin: 0;
              min-height: 100vh;
              display: grid;
              place-items: center;
              padding: 24px;
              background: #f8fafc;
              color: #0f172a;
              font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
            }}
            .card {{
              width: min(100%, 520px);
              border: 1px solid #e2e8f0;
              border-radius: 24px;
              background: #ffffff;
              padding: 42px;
              text-align: center;
              box-shadow: 0 0 0 1px rgba(0,0,0,0.03), 0 18px 50px rgba(15,23,42,0.10);
            }}
            .badge {{
              width: 68px;
              height: 68px;
              display: grid;
              place-items: center;
              margin: 0 auto 22px;
              border-radius: 999px;
              background: #ccfbf1;
              color: #0f766e;
              font-size: 30px;
              font-weight: 800;
            }}
            h1 {{ margin: 0; font-size: 25px; letter-spacing: -0.03em; }}
            .lead {{ margin: 12px auto 0; max-width: 390px; color: #64748b; line-height: 1.65; font-size: 15px; }}
            .details {{
              margin: 28px 0;
              border: 1px solid #e2e8f0;
              border-radius: 18px;
              background: #f8fafc;
              padding: 18px;
              text-align: left;
            }}
            .row {{ display: flex; justify-content: space-between; gap: 18px; padding: 8px 0; }}
            .label {{ color: #64748b; font-size: 12px; font-weight: 800; text-transform: uppercase; letter-spacing: .08em; }}
            .value {{ color: #0f172a; font-size: 14px; font-weight: 700; text-align: right; }}
            .actions {{ display: grid; gap: 12px; }}
            button {{
              width: 100%;
              height: 48px;
              border-radius: 14px;
              border: 0;
              font-size: 14px;
              font-weight: 800;
              cursor: pointer;
            }}
            .accept {{ background: #0d9488; color: #fff; }}
            .decline {{ background: #f1f5f9; color: #334155; border: 1px solid #cbd5e1; }}
            .status {{ margin-top: 18px; color: #94a3b8; font-size: 12px; font-weight: 700; }}
          </style>
        </head>
        <body>
          <main class="card">
            <div class="badge">⏱</div>
            <h1>Appointment available at {clinic_name}</h1>
            <p class="lead">Please choose whether you would like to claim this appointment. Your response is only recorded after pressing one of the buttons below.</p>
            <div class="details">
              <div class="row"><span class="label">Appointment</span><span class="value">{html.escape(slot_time)}</span></div>
              <div class="row"><span class="label">Clinician</span><span class="value">{clinician}</span></div>
              {f'<div class="row"><span class="label">Type</span><span class="value">{appointment_type}</span></div>' if appointment_type else ""}
              {expiry}
            </div>
            <div class="actions">
              <form method="post" action="/accept/{html.escape(token)}">
                <button class="accept" type="submit">Accept Appointment</button>
              </form>
              <form method="post" action="/decline/{html.escape(token)}">
                <button class="decline" type="submit">Decline Offer</button>
              </form>
            </div>
            <p class="status">Current offer status: {status}</p>
          </main>
        </body>
        </html>
        """
    )


@app.post("/accept/{token}", response_class=HTMLResponse)
async def accept_offer(token: str, request: Request, background_tasks: BackgroundTasks) -> HTMLResponse:
    offer_id = verify_secure_token(token)
    if not offer_id:
        return HTMLResponse("<h1>Link Expired or Invalid</h1><p>This invitation is no longer valid.</p>", status_code=400)

    pool: asyncpg.Pool = request.app.state.pool
    now = datetime.now(timezone.utc)
    try:
        parsed_offer_id = uuid.UUID(offer_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail="Offer not found") from exc

    async with pool.acquire() as conn:
        async with conn.transaction():
            offer = await conn.fetchrow(
                """
                SELECT id, slot_id, patient_email, status, expires_at
                FROM waitlist_offers
                WHERE id = $1
                FOR UPDATE
                """,
                parsed_offer_id,
            )
            if not offer:
                raise HTTPException(status_code=404, detail="Offer not found")

            if offer["status"] == "accepted":
                return HTMLResponse(
                    "<h1>Appointment Already Confirmed</h1><p>This offer has already been accepted.</p>",
                    status_code=200,
                )
            if offer["status"] == "declined":
                return HTMLResponse(
                    "<h1>Offer Already Declined</h1><p>This appointment offer was already declined.</p>",
                    status_code=409,
                )

            slot = await conn.fetchrow(
                """
                SELECT id, clinic_id, slot_time, clinician, appointment_type, slot_value_pence, status, accepted_by
                FROM waitlist_slots
                WHERE id = $1
                FOR UPDATE
                """,
                offer["slot_id"],
            )
            if not slot:
                raise HTTPException(status_code=404, detail="Slot not found")

            if offer["status"] == "expired" or (
                offer["expires_at"] is not None and offer["expires_at"] <= now
            ):
                await conn.execute(
                    """
                    UPDATE waitlist_offers
                    SET status = 'expired', expired_at = $2
                    WHERE id = $1 AND status = 'sent'
                    """,
                    offer["id"],
                    now,
                )
                return HTMLResponse(
                    "<h1>Offer Expired</h1><p>This appointment offer has expired.</p>",
                    status_code=409,
                )

            if offer["status"] != "sent":
                return HTMLResponse(
                    "<h1>Offer Unavailable</h1><p>This appointment offer can no longer be accepted.</p>",
                    status_code=409,
                )

            if slot["status"] == "locked":
                return HTMLResponse(
                    f"<h1>This slot is already locked.</h1><p>Accepted by {slot['accepted_by']}.</p>",
                    status_code=409,
                )

            await conn.execute(
                """
                UPDATE waitlist_slots
                SET status = 'locked', accepted_by = $2, locked_at = $3
                WHERE id = $1
                """,
                slot["id"],
                offer["patient_email"],
                now,
            )
            await conn.execute(
                """
                UPDATE waitlist_offers
                SET status = 'accepted', accepted_at = $2
                WHERE id = $1
                """,
                offer["id"],
                now,
            )
            await conn.execute(
                """
                UPDATE waitlist_offers
                SET status = 'expired'
                WHERE slot_id = $1 AND id <> $2 AND clinic_id = $3
                """,
                slot["id"],
                offer["id"],
                slot["clinic_id"],
            )
            await conn.execute(
                """
                UPDATE patients
                SET accepted_count = accepted_count + 1,
                    last_response_at = $3,
                    lifecycle_status = 'booked',
                    booked_at = COALESCE(booked_at, $3),
                    updated_at = $3
                WHERE clinic_id = $1
                  AND lower(email) = lower($2)
                  AND archived_at IS NULL
                """,
                slot["clinic_id"],
                offer["patient_email"],
                now,
            )
            await upsert_recovered_appointment_for_accept(conn, slot, offer, now)

    background_tasks.add_task(
        log_clinical_event,
        pool,
        "offer_accepted",
        clinic_id=str(slot["clinic_id"]),
        slot_id=str(slot["id"]),
        offer_id=str(offer["id"]),
        patient_email=str(offer["patient_email"]),
        client_ip=request.client.host if request.client else None,
        details={
            "clinician": slot["clinician"],
            "user_agent": request.headers.get("user-agent"),
            "accept_token_offer_id": offer_id,
            "accepted_at": now.isoformat(),
        },
    )

    slot_time = slot["slot_time"].astimezone(timezone.utc).strftime("%A %d %B at %H:%M UTC")
    clinician = html.escape(slot["clinician"] or "your clinician")
    patient_email = html.escape(offer["patient_email"])
    clinic_settings = await get_clinic_settings(pool, str(slot["clinic_id"]))
    clinic_name = html.escape(clinic_settings["clinic_name"])

    return HTMLResponse(
        f"""
        <!DOCTYPE html>
        <html lang="en">
        <head>
          <meta charset="UTF-8">
          <meta name="viewport" content="width=device-width, initial-scale=1.0">
          <title>Appointment Confirmed - {clinic_name}</title>
          <style>
            :root {{
              color-scheme: light;
              --clinical: #0f766e;
              --clinical-dark: #115e59;
              --slate-950: #020617;
              --slate-700: #334155;
              --slate-500: #64748b;
              --slate-200: #e2e8f0;
              --emerald-50: #ecfdf5;
              --emerald-500: #10b981;
            }}
            * {{ box-sizing: border-box; }}
            body {{
              margin: 0;
              min-height: 100vh;
              display: grid;
              place-items: center;
              padding: 24px;
              background:
                radial-gradient(circle at top, rgba(15, 118, 110, 0.12), transparent 34rem),
                linear-gradient(135deg, #f8fafc 0%, #eef2f7 100%);
              color: var(--slate-950);
              font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
            }}
            .card {{
              width: min(100%, 560px);
              overflow: hidden;
              border: 1px solid rgba(226, 232, 240, 0.95);
              border-radius: 28px;
              background: rgba(255, 255, 255, 0.94);
              box-shadow: 0 24px 70px rgba(15, 23, 42, 0.14);
              backdrop-filter: blur(18px);
            }}
            .header {{
              padding: 34px 34px 24px;
              text-align: center;
              border-bottom: 1px solid var(--slate-200);
            }}
            .icon {{
              width: 72px;
              height: 72px;
              margin: 0 auto 18px;
              display: grid;
              place-items: center;
              border-radius: 999px;
              background: var(--emerald-50);
              color: var(--clinical);
              box-shadow: 0 0 0 8px rgba(16, 185, 129, 0.08);
            }}
            h1 {{
              margin: 0;
              font-size: clamp(28px, 5vw, 38px);
              line-height: 1.05;
              letter-spacing: -0.04em;
            }}
            .subtitle {{
              margin: 14px auto 0;
              max-width: 420px;
              color: var(--slate-500);
              font-size: 15px;
              line-height: 1.6;
            }}
            .content {{ padding: 28px 34px 34px; }}
            .detail-grid {{
              display: grid;
              gap: 12px;
            }}
            .detail {{
              display: flex;
              align-items: center;
              justify-content: space-between;
              gap: 18px;
              padding: 16px;
              border: 1px solid var(--slate-200);
              border-radius: 18px;
              background: #f8fafc;
            }}
            .label {{
              color: var(--slate-500);
              font-size: 12px;
              font-weight: 800;
              letter-spacing: 0.08em;
              text-transform: uppercase;
            }}
            .value {{
              color: var(--slate-950);
              font-size: 14px;
              font-weight: 750;
              text-align: right;
            }}
            .notice {{
              margin-top: 20px;
              padding: 16px;
              border-radius: 18px;
              background: #f0fdfa;
              color: var(--clinical-dark);
              font-size: 14px;
              font-weight: 650;
              line-height: 1.5;
            }}
            .brand {{
              margin-top: 22px;
              text-align: center;
              color: #94a3b8;
              font-size: 12px;
              font-weight: 700;
              letter-spacing: 0.12em;
              text-transform: uppercase;
            }}
          </style>
        </head>
        <body>
          <main class="card">
            <section class="header">
              <div class="icon" aria-hidden="true">
                <svg width="34" height="34" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
                  <path d="M20 6 9 17l-5-5"></path>
                </svg>
              </div>
              <h1>Appointment confirmed with {clinic_name}</h1>
              <p class="subtitle">Your appointment has been claimed successfully. {clinic_name} has been notified and the slot is now reserved for you.</p>
            </section>
            <section class="content">
              <div class="detail-grid">
                <div class="detail">
                  <span class="label">Appointment</span>
                  <span class="value">{html.escape(slot_time)}</span>
                </div>
                <div class="detail">
                  <span class="label">Clinician</span>
                  <span class="value">{clinician}</span>
                </div>
                <div class="detail">
                  <span class="label">Confirmed for</span>
                  <span class="value">{patient_email}</span>
                </div>
              </div>
              <div class="notice">You do not need to do anything else right now. {clinic_name} will contact you if any further information is needed.</div>
              <div class="brand">{clinic_name}</div>
            </section>
          </main>
        </body>
        </html>
        """
    )


async def db_get_offer_with_slot(pool: asyncpg.Pool, offer_id: str) -> asyncpg.Record | None:
    try:
        parsed = uuid.UUID(offer_id)
    except ValueError:
        return None
    async with pool.acquire() as conn:
        return await conn.fetchrow(
            """
            SELECT
                o.id            AS offer_id,
                o.patient_email AS offer_email,
                o.status        AS offer_status,
                o.expires_at    AS offer_expires_at,
                s.id            AS slot_id,
                s.clinic_id     AS clinic_id,
                s.slot_time     AS slot_time,
                s.clinician     AS clinician,
                s.appointment_type AS appointment_type,
                s.status        AS slot_status,
                s.accepted_by   AS accepted_by,
                s.locked_at     AS locked_at
            FROM waitlist_offers o
            JOIN waitlist_slots  s ON s.id = o.slot_id AND s.clinic_id = o.clinic_id
            WHERE o.id = $1;
            """,
            parsed,
        )


async def db_decline_offer(pool: asyncpg.Pool, offer_id: uuid.UUID) -> dict | None:
    now = datetime.now(timezone.utc)
    async with pool.acquire() as conn:
        async with conn.transaction():
            offer_row = await conn.fetchrow(
                """
                UPDATE waitlist_offers
                SET status = 'declined', declined_at = $1
                WHERE id = $2 AND status = 'sent'
                RETURNING id, slot_id, patient_email;
                """,
                now, offer_id,
            )
            if not offer_row:
                return None
            slot_row = await conn.fetchrow(
                """
                SELECT
                    s.id, s.clinic_id, s.slot_time, s.clinician, s.status, s.accepted_by,
                    COUNT(o.id) FILTER (WHERE o.status = 'sent') AS remaining_sent
                FROM waitlist_slots  s
                LEFT JOIN waitlist_offers o ON o.slot_id = s.id AND o.clinic_id = s.clinic_id
                WHERE s.id = $1
                GROUP BY s.id;
                """,
                offer_row["slot_id"],
            )
    if not slot_row:
        return {
            "offer_id": str(offer_row["id"]), "patient_email": offer_row["patient_email"],
            "slot_id": str(offer_row["slot_id"]), "slot_time": None, "clinician": None,
            "slot_status": "unknown", "remaining_sent": 0, "clinic_id": None,
        }
    return {
        "offer_id": str(offer_row["id"]), "patient_email": offer_row["patient_email"],
        "slot_id": str(slot_row["id"]), "slot_time": slot_row["slot_time"],
        "clinician": slot_row["clinician"], "slot_status": slot_row["status"],
        "remaining_sent": int(slot_row["remaining_sent"]), "clinic_id": str(slot_row["clinic_id"]),
    }


@app.post("/decline/{token}", response_class=HTMLResponse)
async def decline_offer(token: str, request: Request, background_tasks: BackgroundTasks):
    offer_id = verify_secure_token(token)
    if not offer_id:
        return HTMLResponse(content=_html_decline_page("invalid", None, None, 0), status_code=400)

    try:
        parsed_offer_id = uuid.UUID(offer_id)
    except ValueError:
        log.warning(f"/decline called with non-UUID offer_id: {offer_id!r}")
        return HTMLResponse(content=_html_decline_page("invalid", None, None, 0), status_code=400)

    pool: asyncpg.Pool = request.app.state.pool
    existing = await db_get_offer_with_slot(pool, offer_id)

    if not existing:
        return HTMLResponse(content=_html_decline_page("not_found", None, None, 0), status_code=404)

    clinic_settings = await get_clinic_settings(pool, str(existing["clinic_id"]))
    clinic_name = clinic_settings["clinic_name"]

    if existing["offer_status"] == "accepted":
        return HTMLResponse(content=_html_decline_page("already_accepted", existing["slot_time"], existing["clinician"], 0, clinic_name), status_code=200)
    if existing["offer_status"] in ("declined", "expired"):
        return HTMLResponse(content=_html_decline_page("already_declined", existing["slot_time"], existing["clinician"], 0, clinic_name), status_code=200)
    if existing["slot_status"] == "locked":
        return HTMLResponse(content=_html_decline_page("slot_taken", existing["slot_time"], existing["clinician"], 0, clinic_name), status_code=200)

    try:
        result = await db_decline_offer(pool, parsed_offer_id)
    except asyncpg.PostgresError as e:
        log.error(f"PostgresError on /decline/{offer_id}: {e}", exc_info=True)
        return HTMLResponse(content=_html_decline_page("error", None, None, 0), status_code=500)
    except Exception as e:
        log.error(f"Unexpected error on /decline/{offer_id}: {e}", exc_info=True)
        return HTMLResponse(content=_html_decline_page("error", None, None, 0), status_code=500)

    if result is None:
        return HTMLResponse(content=_html_decline_page("already_declined", existing["slot_time"], existing["clinician"], 0, clinic_name), status_code=200)

    if result.get("clinic_id"):
        async with pool.acquire() as conn:
            await conn.execute(
                """
                UPDATE patients
                SET declined_count = declined_count + 1,
                    last_response_at = $3,
                    updated_at = $3
                WHERE clinic_id = $1
                  AND lower(email) = lower($2)
                  AND archived_at IS NULL
                """,
                uuid.UUID(result["clinic_id"]),
                result["patient_email"],
                datetime.now(timezone.utc),
            )

    background_tasks.add_task(
        log_clinical_event,
        pool,
        "offer_declined",
        clinic_id=result.get("clinic_id"),
        slot_id=result["slot_id"],
        offer_id=result["offer_id"],
        patient_email=result["patient_email"],
        client_ip=request.client.host if request.client else None,
        details={"remaining_sent": result["remaining_sent"], "clinician": result["clinician"]},
    )
    log.info(f"Offer {offer_id} declined by {result['patient_email']} — {result['remaining_sent']} offer(s) still pending for slot {result['slot_id']}")
    return HTMLResponse(content=_html_decline_page("success", result["slot_time"], result["clinician"], result["remaining_sent"], clinic_name), status_code=200)


# =========================
# AUTH ROUTES
# =========================

@app.post("/signup")
async def signup(request: Request, clinic_name: str = Form(...), email: str = Form(...), password: str = Form(...)):
    pool = request.app.state.pool
    normalized_email = email.lower().strip()
    cleaned_clinic_name = clinic_name.strip()
    if not cleaned_clinic_name:
        return JSONResponse({"error": "Clinic name is required"}, status_code=400)

    try:
        hashed = hash_password(password)
    except ValueError:
        return JSONResponse({"error": "Password too long (max 72 characters)"}, status_code=400)

    try:
        async with pool.acquire() as conn:
            async with conn.transaction():
                clinic_id = generate_uuid()
                user_id = generate_uuid()

                await conn.execute(
                    """
                    INSERT INTO clinics (id, name)
                    VALUES ($1, $2)
                    """,
                    clinic_id,
                    cleaned_clinic_name
                )

                await conn.execute(
                    """
                    INSERT INTO users (id, clinic_id, email, hashed_password, is_owner)
                    VALUES ($1, $2, $3, $4, TRUE)
                    """,
                    user_id,
                    clinic_id,
                    normalized_email,
                    hashed
                )

        request.session["user_id"] = str(user_id)
        request.session["clinic_id"] = str(clinic_id)

        return RedirectResponse(url="/app/dashboard", status_code=303)

    except asyncpg.UniqueViolationError:
        return JSONResponse({"error": "An account with this email already exists"}, status_code=400)
    except Exception as e:
        log.error(f"Signup error: {e}", exc_info=True)
        return JSONResponse({"error": "Account creation failed. Please try again."}, status_code=500)


@app.post("/login")
async def login(request: Request, email: str = Form(...), password: str = Form(...)):
    pool = request.app.state.pool
    normalized_email = email.lower().strip()

    async with pool.acquire() as conn:
        user = await conn.fetchrow(
            """
            SELECT id, clinic_id, hashed_password
            FROM users
            WHERE email = $1
            """,
            normalized_email
        )

    if not user:
        return JSONResponse({"error": "Invalid credentials"}, status_code=401)

    if not verify_password(password, user["hashed_password"]):
        return JSONResponse({"error": "Invalid credentials"}, status_code=401)

    request.session["user_id"] = str(user["id"])
    request.session["clinic_id"] = str(user["clinic_id"])

    return RedirectResponse(url="/app/dashboard", status_code=303)


@app.post("/logout")
async def logout(request: Request):
    request.session.clear()
    return JSONResponse({"status": "logged_out"})


def _html_decline_page(
    state: str,
    slot_time: "datetime | None",
    clinician: "str | None",
    remaining: int,
    clinic_name: str = "Your clinic",
) -> str:
    escaped_clinic_name = html.escape(clinic_name or "Your clinic")
    config = {
        "success": {"emoji": "👋", "title": "Offer declined", "accent": "#6366f1", "badge_bg": "#eef2ff"},
        "already_declined": {"emoji": "✓", "title": "Already Recorded", "accent": "#6b7280", "badge_bg": "#f9fafb"},
        "already_accepted": {"emoji": "📅", "title": "You Confirmed This Appointment", "accent": "#059669", "badge_bg": "#ecfdf5"},
        "slot_taken": {"emoji": "⚡", "title": "Slot Already Filled", "accent": "#d97706", "badge_bg": "#fffbeb"},
        "not_found": {"emoji": "🔍", "title": "Link Not Found", "accent": "#6b7280", "badge_bg": "#f9fafb"},
        "invalid": {"emoji": "⚠️", "title": "Invalid Link", "accent": "#dc2626", "badge_bg": "#fef2f2"},
        "error": {"emoji": "⚠️", "title": "Something Went Wrong", "accent": "#dc2626", "badge_bg": "#fef2f2"}
    }
    cfg = config.get(state, config["error"])
    formatted_time = slot_time.strftime("%A %d %B %Y at %I:%M %p") if slot_time else "the requested slot"
    clinician_str = f" with {clinician}" if clinician else ""

    if state == "success":
        body = f"We'll offer the <strong>{formatted_time}</strong> slot{clinician_str} to the next patient on the list.<br><br>{escaped_clinic_name} will be in touch when another suitable appointment becomes available." if remaining > 0 else f"All patients have now responded for the <strong>{formatted_time}</strong> slot{clinician_str}.<br><br>{escaped_clinic_name} has been notified."
    elif state == "already_accepted":
        body = f"You previously confirmed your appointment on <strong>{formatted_time}</strong>.<br><br>If you need to cancel, please contact the practice directly."
    elif state == "slot_taken":
        body = "Another patient confirmed this slot just before your response arrived.<br><br>We'll contact you when another suitable appointment becomes available."
    elif state == "already_declined":
        body = "Your preference was already saved — no further action is needed."
    elif state in ("not_found", "invalid"):
        body = "This link may have already been used or has expired.<br><br>Please contact the practice directly if you need assistance."
    else:
        body = "We encountered a problem processing your response.<br><br>Please try again in a moment or contact the practice directly."

    return f"""<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>{cfg['title']} — {escaped_clinic_name}</title><style>*,*::before,*::after{{box-sizing:border-box;margin:0;padding:0;}}body{{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:#f8fafc;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:24px;-webkit-font-smoothing:antialiased;}}.card{{background:#ffffff;border-radius:24px;padding:52px 44px 40px;max-width:460px;width:100%;text-align:center;box-shadow:0 0 0 1px rgba(0,0,0,0.04),0 4px 6px rgba(0,0,0,0.04),0 16px 40px rgba(0,0,0,0.07);}}.badge{{width:68px;height:68px;background:{cfg['badge_bg']};border-radius:50%;display:flex;align-items:center;justify-content:center;margin:0 auto 24px;font-size:28px;line-height:1;}}h1{{font-size:20px;font-weight:700;color:#0f172a;letter-spacing:-0.3px;margin-bottom:6px;}}.state-label{{display:inline-flex;align-items:center;gap:6px;font-size:12px;font-weight:600;color:{cfg['accent']};background:{cfg['badge_bg']};padding:4px 10px;border-radius:20px;margin-bottom:28px;letter-spacing:0.2px;}}.state-dot{{width:6px;height:6px;background:{cfg['accent']};border-radius:50%;flex-shrink:0;}}.divider{{height:1px;background:#f1f5f9;margin:0 0 24px;}}.body{{font-size:14px;color:#475569;line-height:1.75;}}.footer{{margin-top:32px;padding-top:20px;border-top:1px solid #f1f5f9;font-size:11px;font-weight:700;color:#cbd5e1;letter-spacing:1.2px;text-transform:uppercase;}}</style></head><body><div class="card"><div class="badge">{cfg['emoji']}</div><h1>{cfg['title']}</h1><div class="state-label"><span class="state-dot"></span>Response recorded</div><div class="divider"></div><p class="body">{body}</p><p class="footer">{escaped_clinic_name}</p></div></body></html>"""


async def ensure_schema(pool: asyncpg.Pool) -> None:
    async with pool.acquire() as conn:
        # =========================
        # AUTH TABLES
        # =========================

        await conn.execute("""
        CREATE TABLE IF NOT EXISTS clinics (
            id UUID PRIMARY KEY,
            name TEXT NOT NULL,
            created_at TIMESTAMPTZ NOT NULL DEFAULT now()
        );
        """)

        await conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id UUID PRIMARY KEY,
            clinic_id UUID NOT NULL REFERENCES clinics(id) ON DELETE CASCADE,
            email TEXT NOT NULL UNIQUE,
            hashed_password TEXT,
            google_id TEXT UNIQUE,
            is_owner BOOLEAN NOT NULL DEFAULT FALSE,
            created_at TIMESTAMPTZ NOT NULL DEFAULT now()
        );
        """)

        await conn.execute("""
        CREATE TABLE IF NOT EXISTS patients (
            id UUID PRIMARY KEY,
            clinic_id UUID NOT NULL REFERENCES clinics(id) ON DELETE CASCADE,
            first_name TEXT NOT NULL,
            last_name TEXT,
            email TEXT NOT NULL,
            phone TEXT,
            consent_status TEXT NOT NULL DEFAULT 'consented',
            consent_source TEXT DEFAULT 'manual',
            consented_at TIMESTAMPTZ,
            notes TEXT,
            created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
            updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
        );
        """)

        await conn.execute("""
        CREATE UNIQUE INDEX IF NOT EXISTS idx_patients_clinic_email
        ON patients(clinic_id, lower(email));
        """)

        await conn.execute("""
        CREATE INDEX IF NOT EXISTS idx_patients_clinic_id
        ON patients(clinic_id);
        """)

        await conn.execute("""
        CREATE INDEX IF NOT EXISTS idx_patients_consent_status
        ON patients(consent_status);
        """)

        await conn.execute("""
        ALTER TABLE patients
        ADD COLUMN IF NOT EXISTS priority INTEGER NOT NULL DEFAULT 3;
        """)

        await conn.execute("""
        ALTER TABLE patients
        ADD COLUMN IF NOT EXISTS preferred_appointment_type TEXT;
        """)

        await conn.execute("""
        ALTER TABLE patients
        ADD COLUMN IF NOT EXISTS preferred_clinician TEXT;
        """)

        await conn.execute("""
        ALTER TABLE patients
        ADD COLUMN IF NOT EXISTS last_contacted_at TIMESTAMPTZ;
        """)

        await conn.execute("""
        ALTER TABLE patients
        ADD COLUMN IF NOT EXISTS last_response_at TIMESTAMPTZ;
        """)

        await conn.execute("""
        ALTER TABLE patients
        ADD COLUMN IF NOT EXISTS accepted_count INTEGER NOT NULL DEFAULT 0;
        """)

        await conn.execute("""
        ALTER TABLE patients
        ADD COLUMN IF NOT EXISTS declined_count INTEGER NOT NULL DEFAULT 0;
        """)

        await conn.execute("""
        ALTER TABLE patients
        ADD COLUMN IF NOT EXISTS offer_count INTEGER NOT NULL DEFAULT 0;
        """)

        await conn.execute("""
        ALTER TABLE patients
        ADD COLUMN IF NOT EXISTS lifecycle_status TEXT NOT NULL DEFAULT 'waitlist';
        """)

        await conn.execute("""
        ALTER TABLE patients
        ADD COLUMN IF NOT EXISTS archived_at TIMESTAMPTZ;
        """)

        await conn.execute("""
        ALTER TABLE patients
        ADD COLUMN IF NOT EXISTS booked_at TIMESTAMPTZ;
        """)

        await conn.execute("""
        ALTER TABLE patients
        ADD COLUMN IF NOT EXISTS completed_at TIMESTAMPTZ;
        """)

        await conn.execute("""
        CREATE INDEX IF NOT EXISTS idx_patients_clinic_priority
        ON patients(clinic_id, priority);
        """)

        await conn.execute("""
        CREATE INDEX IF NOT EXISTS idx_patients_clinic_consent_archived
        ON patients(clinic_id, consent_status, archived_at);
        """)

        await conn.execute("""
        CREATE INDEX IF NOT EXISTS idx_patients_last_contacted
        ON patients(last_contacted_at);
        """)

        await conn.execute("""
        CREATE INDEX IF NOT EXISTS idx_patients_lifecycle_status
        ON patients(clinic_id, lifecycle_status);
        """)

        await conn.execute("""
        ALTER TABLE clinics
        ADD COLUMN IF NOT EXISTS display_name TEXT;
        """)

        await conn.execute("""
        ALTER TABLE clinics
        ADD COLUMN IF NOT EXISTS contact_email TEXT;
        """)

        await conn.execute("""
        ALTER TABLE clinics
        ADD COLUMN IF NOT EXISTS phone TEXT;
        """)

        await conn.execute("""
        ALTER TABLE clinics
        ADD COLUMN IF NOT EXISTS sender_name TEXT;
        """)

        await conn.execute("""
        ALTER TABLE clinics
        ADD COLUMN IF NOT EXISTS reply_to_email TEXT;
        """)

        await conn.execute("""
        ALTER TABLE clinics
        ADD COLUMN IF NOT EXISTS default_slot_value_pence INTEGER NOT NULL DEFAULT 0;
        """)

        await conn.execute("""
        ALTER TABLE clinics
        ADD COLUMN IF NOT EXISTS default_expiry_minutes INTEGER NOT NULL DEFAULT 240;
        """)

        await conn.execute("""
        ALTER TABLE clinics
        ADD COLUMN IF NOT EXISTS gdpr_notice TEXT;
        """)

        await conn.execute("""
        ALTER TABLE clinics
        ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ NOT NULL DEFAULT now();
        """)

        await conn.execute("""
        CREATE INDEX IF NOT EXISTS idx_clinics_updated_at
        ON clinics(updated_at);
        """)

        await conn.execute(
            """
            CREATE TABLE IF NOT EXISTS waitlist_slots (
                id UUID PRIMARY KEY,
                clinic_id UUID REFERENCES clinics(id) ON DELETE CASCADE,
                slot_time TIMESTAMPTZ NOT NULL,
                clinician TEXT,
                appointment_type TEXT,
                slot_value_pence INTEGER NOT NULL DEFAULT 0,
                status TEXT NOT NULL DEFAULT 'broadcasting',
                accepted_by TEXT,
                created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
                locked_at TIMESTAMPTZ
            )
            """
        )
        await conn.execute(
            """
            CREATE TABLE IF NOT EXISTS waitlist_offers (
                id UUID PRIMARY KEY,
                clinic_id UUID REFERENCES clinics(id) ON DELETE CASCADE,
                slot_id UUID NOT NULL REFERENCES waitlist_slots(id) ON DELETE CASCADE,
                patient_email TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'sent',
                created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
                accepted_at TIMESTAMPTZ,
                declined_at TIMESTAMPTZ
            )
            """
        )
        await conn.execute(
            """
            CREATE TABLE IF NOT EXISTS appointments (
                id UUID PRIMARY KEY,
                clinic_id UUID NOT NULL REFERENCES clinics(id),
                patient_id UUID REFERENCES patients(id),
                patient_email TEXT NOT NULL,
                patient_name TEXT,
                slot_id UUID REFERENCES waitlist_slots(id),
                source TEXT NOT NULL DEFAULT 'manual',
                appointment_type TEXT,
                clinician TEXT,
                appointment_time TIMESTAMPTZ NOT NULL,
                slot_value_pence INTEGER NOT NULL DEFAULT 0,
                status TEXT NOT NULL DEFAULT 'booked',
                notes TEXT,
                completed_at TIMESTAMPTZ,
                cancelled_at TIMESTAMPTZ,
                no_show_at TIMESTAMPTZ,
                created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
                updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
            )
            """
        )
        await conn.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_waitlist_offers_slot_id
            ON waitlist_offers(slot_id)
            """
        )
        await conn.execute("""
        CREATE INDEX IF NOT EXISTS idx_appointments_clinic_time
        ON appointments(clinic_id, appointment_time);
        """)

        await conn.execute("""
        CREATE INDEX IF NOT EXISTS idx_appointments_clinic_status
        ON appointments(clinic_id, status);
        """)

        await conn.execute("""
        CREATE INDEX IF NOT EXISTS idx_appointments_patient_id
        ON appointments(patient_id);
        """)

        await conn.execute("""
        CREATE INDEX IF NOT EXISTS idx_appointments_slot_id
        ON appointments(slot_id);
        """)

        await conn.execute("""
        CREATE UNIQUE INDEX IF NOT EXISTS idx_appointments_unique_slot
        ON appointments(slot_id)
        WHERE slot_id IS NOT NULL;
        """)
        await conn.execute(
            """
            CREATE TABLE IF NOT EXISTS audit_log (
                id BIGSERIAL PRIMARY KEY,
                clinic_id UUID REFERENCES clinics(id) ON DELETE SET NULL,
                event_type TEXT NOT NULL,
                slot_id UUID,
                offer_id UUID,
                patient_email_hash TEXT,
                client_ip TEXT,
                success BOOLEAN NOT NULL DEFAULT TRUE,
                details TEXT,
                created_at TIMESTAMPTZ NOT NULL DEFAULT now()
            )
            """
        )
        await conn.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_audit_log_slot_id
            ON audit_log(slot_id)
            WHERE slot_id IS NOT NULL
            """
        )

        await conn.execute("""
        ALTER TABLE waitlist_slots
        ADD COLUMN IF NOT EXISTS clinic_id UUID REFERENCES clinics(id) ON DELETE CASCADE;
        """)

        await conn.execute("""
        ALTER TABLE waitlist_slots
        ADD COLUMN IF NOT EXISTS appointment_type TEXT;
        """)

        await conn.execute("""
        ALTER TABLE waitlist_slots
        ADD COLUMN IF NOT EXISTS slot_value_pence INTEGER NOT NULL DEFAULT 0;
        """)

        await conn.execute("""
        ALTER TABLE waitlist_slots
        ADD COLUMN IF NOT EXISTS expires_at TIMESTAMPTZ;
        """)

        await conn.execute("""
        ALTER TABLE waitlist_slots
        ADD COLUMN IF NOT EXISTS expired_at TIMESTAMPTZ;
        """)

        await conn.execute("""
        ALTER TABLE waitlist_offers
        ADD COLUMN IF NOT EXISTS clinic_id UUID REFERENCES clinics(id) ON DELETE CASCADE;
        """)

        await conn.execute("""
        ALTER TABLE waitlist_offers
        ADD COLUMN IF NOT EXISTS expires_at TIMESTAMPTZ;
        """)

        await conn.execute("""
        ALTER TABLE waitlist_offers
        ADD COLUMN IF NOT EXISTS expired_at TIMESTAMPTZ;
        """)

        await conn.execute("""
        ALTER TABLE waitlist_offers
        ADD COLUMN IF NOT EXISTS email_send_status TEXT;
        """)

        await conn.execute("""
        ALTER TABLE waitlist_offers
        ADD COLUMN IF NOT EXISTS email_provider_id TEXT;
        """)

        await conn.execute("""
        ALTER TABLE waitlist_offers
        ADD COLUMN IF NOT EXISTS email_failed_reason TEXT;
        """)

        await conn.execute("""
        ALTER TABLE waitlist_offers
        ADD COLUMN IF NOT EXISTS sent_at TIMESTAMPTZ;
        """)

        await conn.execute("""
        ALTER TABLE waitlist_offers
        ADD COLUMN IF NOT EXISTS failed_at TIMESTAMPTZ;
        """)

        await conn.execute("""
        ALTER TABLE audit_log
        ADD COLUMN IF NOT EXISTS clinic_id UUID REFERENCES clinics(id) ON DELETE SET NULL;
        """)

        await conn.execute("""
        CREATE INDEX IF NOT EXISTS idx_waitlist_slots_clinic_id
        ON waitlist_slots(clinic_id);
        """)

        await conn.execute("""
        CREATE INDEX IF NOT EXISTS idx_waitlist_offers_clinic_id
        ON waitlist_offers(clinic_id);
        """)

        await conn.execute("""
        CREATE INDEX IF NOT EXISTS idx_waitlist_slots_expires_at
        ON waitlist_slots(expires_at);
        """)

        await conn.execute("""
        CREATE INDEX IF NOT EXISTS idx_waitlist_offers_expires_at
        ON waitlist_offers(expires_at);
        """)

        await conn.execute("""
        CREATE INDEX IF NOT EXISTS idx_audit_log_clinic_id
        ON audit_log(clinic_id);
        """)


async def create_broadcast_slot(pool: asyncpg.Pool, request: DashboardOfferRequest, clinic_id: str) -> asyncpg.Record:
    slot_id = uuid.uuid4()
    clinic_uuid = uuid.UUID(str(clinic_id))
    clinic_settings = await get_clinic_settings(pool, clinic_id)
    expiry_minutes = clamp_expiry_minutes(safe_int(clinic_settings["default_expiry_minutes"], 240))
    expires_at = datetime.now(timezone.utc) + timedelta(minutes=expiry_minutes)
    slot_value_pence = (
        request.slot_value_pence
        if request.slot_value_pence > 0
        else clinic_settings["default_slot_value_pence"]
    )
    try:
        appointment_type = normalize_appointment_type(request.appointment_type)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    async with pool.acquire() as conn:
        return await conn.fetchrow(
            """
            INSERT INTO waitlist_slots (
                id, clinic_id, slot_time, clinician, appointment_type, slot_value_pence, status, expires_at
            )
            VALUES ($1, $2, $3, $4, $5, $6, 'broadcasting', $7)
            RETURNING
                id::text,
                clinic_id::text,
                slot_time,
                clinician,
                appointment_type,
                slot_value_pence,
                status,
                accepted_by,
                locked_at,
                expires_at
            """,
            slot_id,
            clinic_uuid,
            request.slot_time,
            request.clinician,
            appointment_type,
            slot_value_pence,
            expires_at,
        )


async def create_waitlist_offers(
    pool: asyncpg.Pool,
    slot_id: str,
    emails: list[EmailStr],
    clinic_id: str,
) -> list[asyncpg.Record]:
    clinic_uuid = uuid.UUID(str(clinic_id))
    slot_uuid = uuid.UUID(slot_id)
    async with pool.acquire() as conn:
        slot_expires_at = await conn.fetchval(
            """
            SELECT expires_at
            FROM waitlist_slots
            WHERE id = $1 AND clinic_id = $2
            """,
            slot_uuid,
            clinic_uuid,
        )
        expires_at = slot_expires_at or datetime.now(timezone.utc) + timedelta(hours=4)
        rows = [
            (uuid.uuid4(), clinic_uuid, slot_uuid, str(email).lower(), expires_at)
            for email in emails
        ]
        await conn.executemany(
            """
            INSERT INTO waitlist_offers (id, clinic_id, slot_id, patient_email, status, expires_at, email_send_status)
            VALUES ($1, $2, $3, $4, 'sent', $5, 'pending')
            """,
            rows,
        )
        now = datetime.now(timezone.utc)
        normalized_emails = [str(email).lower() for email in emails]
        await conn.execute(
            """
            UPDATE patients
            SET offer_count = offer_count + 1,
                last_contacted_at = $3,
                updated_at = $3
            WHERE clinic_id = $1
              AND lower(email) = ANY($2::text[])
              AND archived_at IS NULL
            """,
            clinic_uuid,
            normalized_emails,
            now,
        )
        return await conn.fetch(
            """
            SELECT id::text, slot_id::text, patient_email, status
            FROM waitlist_offers
            WHERE slot_id = $1 AND clinic_id = $2
            ORDER BY created_at ASC
            """,
            slot_uuid,
            clinic_uuid,
        )


async def expire_stale_offers(pool: asyncpg.Pool, slot_id: str, clinic_id: str) -> None:
    slot_uuid = uuid.UUID(str(slot_id))
    clinic_uuid = uuid.UUID(str(clinic_id))
    now = datetime.now(timezone.utc)

    async with pool.acquire() as conn:
        await conn.execute(
            """
            UPDATE waitlist_offers
            SET status = 'expired', expired_at = $3
            WHERE slot_id = $1
              AND clinic_id = $2
              AND status = 'sent'
              AND expires_at IS NOT NULL
              AND expires_at <= $3
            """,
            slot_uuid,
            clinic_uuid,
            now,
        )

        summary = await conn.fetchrow(
            """
            SELECT
                s.status,
                COUNT(o.id)::int AS offers_sent,
                (COUNT(o.id) FILTER (WHERE o.status = 'sent'))::int AS pending_offers,
                (COUNT(o.id) FILTER (WHERE o.status = 'accepted'))::int AS accepted_offers,
                (COUNT(o.id) FILTER (WHERE o.status = 'expired'))::int AS expired_offers
            FROM waitlist_slots s
            LEFT JOIN waitlist_offers o
              ON o.slot_id = s.id
             AND o.clinic_id = s.clinic_id
            WHERE s.id = $1 AND s.clinic_id = $2
            GROUP BY s.id
            """,
            slot_uuid,
            clinic_uuid,
        )

        if (
            summary
            and summary["status"] == "broadcasting"
            and summary["offers_sent"] > 0
            and summary["pending_offers"] == 0
            and summary["accepted_offers"] == 0
            and summary["expired_offers"] > 0
        ):
            try:
                await conn.execute(
                    """
                    UPDATE waitlist_slots
                    SET status = 'expired', expired_at = $3
                    WHERE id = $1
                      AND clinic_id = $2
                      AND status = 'broadcasting'
                    """,
                    slot_uuid,
                    clinic_uuid,
                    now,
                )
            except asyncpg.PostgresError:
                log.exception(
                    "Failed to mark slot %s expired after stale offers expired; using effective status.",
                    slot_id,
                )


async def get_slot_or_404(pool: asyncpg.Pool, slot_id: str, clinic_id: str) -> asyncpg.Record:
    try:
        parsed_slot_id = uuid.UUID(slot_id)
        parsed_clinic_id = uuid.UUID(str(clinic_id))
    except ValueError as exc:
        raise HTTPException(status_code=404, detail="Slot not found") from exc

    async with pool.acquire() as conn:
        slot = await conn.fetchrow(
            """
            SELECT id::text, clinic_id::text, slot_time, clinician, status, accepted_by, locked_at
            FROM waitlist_slots
            WHERE id = $1 AND clinic_id = $2
            """,
            parsed_slot_id,
            parsed_clinic_id,
        )
    if not slot:
        raise HTTPException(status_code=404, detail="Slot not found")
    return slot


async def build_broadcast_response(pool: asyncpg.Pool, slot_id: str, clinic_id: str) -> BroadcastResponse:
    slot = await get_slot_or_404(pool, slot_id, clinic_id)
    status = await build_slot_status_response(pool, slot)
    return BroadcastResponse(**status.model_dump(exclude={"locked_at", "offers"}))


async def build_slot_status_response(pool: asyncpg.Pool, slot: asyncpg.Record) -> SlotStatusResponse:
    slot_uuid = uuid.UUID(slot["id"])
    clinic_uuid = uuid.UUID(str(slot["clinic_id"])) if slot["clinic_id"] else None

    async with pool.acquire() as conn:
        if clinic_uuid:
            offer_rows = await conn.fetch(
                """
                SELECT patient_email, status
                FROM waitlist_offers
                WHERE slot_id = $1 AND clinic_id = $2
                ORDER BY created_at ASC
                """,
                slot_uuid,
                clinic_uuid,
            )
        else:
            offer_rows = await conn.fetch(
                """
                SELECT patient_email, status
                FROM waitlist_offers
                WHERE slot_id = $1
                ORDER BY created_at ASC
                """,
                slot_uuid,
            )

        offers_sent = len(offer_rows)
        has_offers = len(offer_rows) > 0
        all_declined = has_offers and all(row["status"] == "declined" for row in offer_rows)
        pending_offers = sum(1 for row in offer_rows if row["status"] == "sent")
        accepted_offers = sum(1 for row in offer_rows if row["status"] == "accepted")
        expired_offers = sum(1 for row in offer_rows if row["status"] == "expired")
        response_status = slot["status"]

        if all_declined and slot["status"] == "broadcasting":
            response_status = "declined"
        if (
            slot["status"] == "broadcasting"
            and offers_sent > 0
            and pending_offers == 0
            and accepted_offers == 0
            and expired_offers > 0
        ):
            response_status = "expired"

    offers = [
        {"patient_email": row["patient_email"], "status": row["status"]}
        for row in offer_rows
    ]

    return SlotStatusResponse(
        slot_id=slot["id"],
        slot_time=slot["slot_time"],
        clinician=slot["clinician"],
        status=response_status,
        offers_sent=offers_sent,
        accepted_by=slot["accepted_by"],
        locked_at=slot["locked_at"],
        offers=offers,
    )


async def notify_slot_update(pool: asyncpg.Pool, slot_id: uuid.UUID) -> None:
    try:
        async with pool.acquire() as conn:
            await conn.execute("SELECT pg_notify('slot_updates', $1)", str(slot_id))
    except Exception:
        logger.exception("Failed to notify dashboard listeners for slot %s", slot_id)


async def send_waitlist_offer_emails(pool: asyncpg.Pool, slot: asyncpg.Record, offers: list[asyncpg.Record]) -> None:
    api_key = (resend.api_key or "").strip()
    if not api_key or api_key == "re_your_key_here":
        logger.error("Resend is not configured; skipping %s outbound waitlist emails.", len(offers))
        reason = "Resend API key is not configured"
        async with pool.acquire() as conn:
            await conn.executemany(
                """
                UPDATE waitlist_offers
                SET email_send_status = 'failed',
                    failed_at = now(),
                    email_failed_reason = $2
                WHERE id = $1
                """,
                [(uuid.UUID(str(offer["id"])), reason) for offer in offers],
            )
        await asyncio.gather(
            *(
                log_clinical_event(
                    pool,
                    "email_send_failed",
                    clinic_id=str(slot["clinic_id"]),
                    slot_id=str(slot["id"]),
                    offer_id=str(offer["id"]),
                    patient_email=str(offer["patient_email"]),
                    success=False,
                    details={"reason": reason},
                )
                for offer in offers
            ),
            return_exceptions=True,
        )
        return

    try:
        clinic_settings = await get_clinic_settings(pool, str(slot["clinic_id"]))
    except Exception:
        logger.exception("Failed to load clinic settings for waitlist offer emails.")
        clinic_settings = {
            "clinic_name": "Your clinic",
            "reply_to_email": None,
            "gdpr_notice": DEFAULT_GDPR_NOTICE,
            "default_expiry_minutes": 240,
        }

    await asyncio.gather(
        *(send_offer_email_to_patient(pool, slot, offer, clinic_settings) for offer in offers),
        return_exceptions=True,
    )


async def send_offer_email_to_patient(
    pool: asyncpg.Pool,
    slot: asyncpg.Record,
    offer: asyncpg.Record,
    clinic_settings: dict,
) -> None:
    api_key = (resend.api_key or "").strip()
    recipient = str(offer["patient_email"])
    if not api_key or api_key == "re_your_key_here":
        logger.error("Resend is not configured; skipping outbound waitlist email to %s.", recipient)
        return

    from_email = get_resend_from_email()
    clinic_name = clinic_settings["clinic_name"]
    payload = {
        "from": from_email,
        "to": recipient,
        "subject": f"Appointment available at {clinic_name}",
        "html": build_offer_email_html(slot, offer, clinic_settings),
    }
    if clinic_settings.get("reply_to_email"):
        payload["reply_to"] = clinic_settings["reply_to_email"]

    async with SMTP_SEMAPHORE:
        try:
            loop = asyncio.get_running_loop()
            result = await loop.run_in_executor(
                None,
                lambda: resend.Emails.send(payload),
            )
            provider_id = None
            if isinstance(result, dict):
                provider_id = result.get("id")
            elif hasattr(result, "id"):
                provider_id = getattr(result, "id")
            async with pool.acquire() as conn:
                await conn.execute(
                    """
                    UPDATE waitlist_offers
                    SET email_send_status = 'sent',
                        sent_at = now(),
                        email_provider_id = $2,
                        email_failed_reason = NULL,
                        failed_at = NULL
                    WHERE id = $1
                    """,
                    uuid.UUID(str(offer["id"])),
                    clean_optional_text(provider_id),
                )
        except Exception:
            reason = "Email send failed"
            if "resend.dev" in from_email.lower():
                logger.exception(
                    "Failed to send waitlist offer email to %s. Testing sender %s may only send to verified Resend recipients; verify swiftslot.org and use a domain sender.",
                    recipient,
                    from_email,
                )
                reason = "Test sender may only send to verified Resend recipients"
            else:
                logger.exception("Failed to send waitlist offer email to %s", recipient)
            async with pool.acquire() as conn:
                await conn.execute(
                    """
                    UPDATE waitlist_offers
                    SET email_send_status = 'failed',
                        failed_at = now(),
                        email_failed_reason = $2
                    WHERE id = $1
                    """,
                    uuid.UUID(str(offer["id"])),
                    reason[:240],
                )
            await log_clinical_event(
                pool,
                "email_send_failed",
                clinic_id=str(slot["clinic_id"]),
                slot_id=str(slot["id"]),
                offer_id=str(offer["id"]),
                patient_email=recipient,
                success=False,
                details={"sender": from_email, "reason": reason},
            )


def build_offer_email_html(slot: asyncpg.Record, offer: asyncpg.Record, clinic_settings: dict) -> str:
    offer_url = f"{settings.render_external_url}/offer/{generate_secure_token(str(offer['id']))}"
    accept_url = f"{offer_url}#accept"
    decline_url = f"{offer_url}#decline"
    clinic_name = html.escape(clinic_settings["clinic_name"])
    clinician = html.escape(slot["clinician"]) if slot["clinician"] else ""
    try:
        appointment_type_value = slot["appointment_type"]
    except KeyError:
        appointment_type_value = None
    appointment_type = html.escape(appointment_type_value) if appointment_type_value else ""
    slot_time = slot["slot_time"].astimezone(timezone.utc).strftime("%A %d %B at %H:%M UTC")
    expiry_text = "This offer is time-limited and may be withdrawn once it expires or another patient accepts it."
    try:
        expires_at_value = slot["expires_at"]
    except KeyError:
        expires_at_value = None
    if expires_at_value:
        expires_at = expires_at_value.astimezone(timezone.utc).strftime("%A %d %B at %H:%M UTC")
        expiry_text = f"This offer expires on {html.escape(expires_at)}, unless another patient accepts it first."
    gdpr_notice = html.escape(clinic_settings.get("gdpr_notice") or DEFAULT_GDPR_NOTICE)

    return f"""
    <div style="font-family: Arial, sans-serif; line-height: 1.5; color: #0f172a;">
      <h2 style="margin: 0 0 12px;">Appointment available at {clinic_name}</h2>
      <p>An appointment is available on <strong>{html.escape(slot_time)}</strong>.</p>
      {f"<p><strong>Clinician:</strong> {clinician}</p>" if clinician else ""}
      {f"<p><strong>Appointment type:</strong> {appointment_type}</p>" if appointment_type else ""}
      <p>Please open the secure offer page below to accept or decline. The first patient to accept locks the slot.</p>
      <p style="font-size: 13px; color: #64748b;">{expiry_text}</p>
      <table role="presentation" cellspacing="0" cellpadding="0" style="margin: 24px 0 12px;">
        <tr>
          <td style="border-radius: 8px; background: #0f766e;">
            <a href="{accept_url}" target="_blank" style="display: inline-block; padding: 12px 18px; color: #ffffff; text-decoration: none; font-weight: 700; border-radius: 8px;">
              Accept appointment
            </a>
          </td>
          <td style="width: 10px;"></td>
          <td style="border-radius: 8px; background: #f1f5f9;">
            <a href="{decline_url}" target="_blank" style="display: inline-block; padding: 12px 18px; color: #334155; text-decoration: none; font-weight: 700; border-radius: 8px; border: 1px solid #cbd5e1;">
              Decline offer
            </a>
          </td>
        </tr>
      </table>
      <p style="font-size: 13px; color: #64748b;">If the button does not work, copy and paste this link into your browser:<br>{offer_url}</p>
      <p style="font-size: 12px; color: #64748b; margin-top: 24px;">{gdpr_notice}</p>
    </div>
    """
