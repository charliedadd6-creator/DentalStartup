import asyncio
import base64
import hashlib
import html
import hmac
import json
import logging
import os
import time
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Annotated

import asyncpg
import resend
from fastapi import BackgroundTasks, FastAPI, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from models_auth import UserCreate, UserLogin, generate_uuid
from pydantic import BaseModel, EmailStr, Field, field_validator
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


def safe_int(value, default=0):
    try:
        return int(value)
    except Exception:
        return default


def clamp_expiry_minutes(value: int) -> int:
    return max(5, min(value, 1440))


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
    }


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
                (COUNT(o.id) FILTER (WHERE o.status = 'sent'))::int AS pending_offers
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
            }
        )

    return broadcasts


@app.get("/api/appointments/recovered")
async def api_recovered_appointments(request: Request):
    auth_redirect = require_auth(request)
    if auth_redirect:
        raise HTTPException(status_code=401, detail="Authentication required")

    clinic_uuid = uuid.UUID(str(get_session_clinic_id(request)))
    async with request.app.state.pool.acquire() as conn:
        rows = await conn.fetch(
            """
            SELECT
                id::text AS id,
                accepted_by AS patient,
                slot_time,
                clinician,
                appointment_type,
                slot_value_pence,
                status,
                locked_at AS confirmed_at
            FROM waitlist_slots
            WHERE clinic_id = $1
              AND (status = 'locked' OR accepted_by IS NOT NULL)
            ORDER BY locked_at DESC NULLS LAST, created_at DESC
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
        "top_clinicians": [
            {"clinician": row["clinician"], "recovered": row["recovered"]}
            for row in top_rows
        ],
        "total_revenue_saved": None,
    }


@app.get("/api/patients")
async def api_patients(request: Request):
    auth_redirect = require_auth(request)
    if auth_redirect:
        raise HTTPException(status_code=401, detail="Authentication required")

    clinic_uuid = uuid.UUID(str(get_session_clinic_id(request)))
    async with request.app.state.pool.acquire() as conn:
        rows = await conn.fetch(
            """
            SELECT id::text, first_name, last_name, email, phone, consent_status,
                   consent_source, consented_at, notes, created_at, updated_at
            FROM patients
            WHERE clinic_id = $1
            ORDER BY created_at DESC;
            """,
            clinic_uuid,
        )

    patients = [
        {
            "id": row["id"],
            "first_name": row["first_name"],
            "last_name": row["last_name"],
            "email": row["email"],
            "phone": row["phone"],
            "consent_status": row["consent_status"],
            "consent_source": row["consent_source"],
            "consented_at": iso_or_none(row["consented_at"]),
            "notes": row["notes"],
            "created_at": iso_or_none(row["created_at"]),
            "updated_at": iso_or_none(row["updated_at"]),
        }
        for row in rows
    ]
    return {
        "patients": patients,
        "total": len(patients),
        "consented": sum(1 for patient in patients if patient["consent_status"] == "consented"),
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
        async with request.app.state.pool.acquire() as conn:
            row = await conn.fetchrow(
                """
                INSERT INTO patients (
                    id, clinic_id, first_name, last_name, email, phone,
                    consent_status, consent_source, consented_at, notes
                )
                VALUES ($1, $2, $3, $4, $5, $6, $7, 'manual', $8, $9)
                RETURNING id::text, first_name, last_name, email, phone, consent_status,
                          consent_source, consented_at, notes, created_at, updated_at;
                """,
                patient_id,
                clinic_uuid,
                patient.first_name.strip(),
                patient.last_name.strip() if patient.last_name else None,
                email,
                patient.phone.strip() if patient.phone else None,
                patient.consent_status,
                consented_at,
                patient.notes,
            )
    except asyncpg.UniqueViolationError:
        return JSONResponse({"error": "Patient already exists on this waitlist"}, status_code=400)

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
        "created_at": iso_or_none(row["created_at"]),
        "updated_at": iso_or_none(row["updated_at"]),
    }


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
                SELECT id, clinic_id, slot_time, clinician, status, accepted_by
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
            JOIN waitlist_slots  s ON s.id = o.slot_id
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
                LEFT JOIN waitlist_offers o ON o.slot_id = s.id
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

    background_tasks.add_task(
        log_clinical_event,
        pool,
        "offer_declined",
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
                    clinic_name
                )

                await conn.execute(
                    """
                    INSERT INTO users (id, clinic_id, email, hashed_password, is_owner)
                    VALUES ($1, $2, $3, $4, TRUE)
                    """,
                    user_id,
                    clinic_id,
                    email.lower().strip(),
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

    async with pool.acquire() as conn:
        user = await conn.fetchrow(
            """
            SELECT id, clinic_id, hashed_password
            FROM users
            WHERE email = $1
            """,
            email
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
            CREATE INDEX IF NOT EXISTS idx_waitlist_offers_slot_id
            ON waitlist_offers(slot_id)
            """
        )
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
            request.appointment_type,
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
            INSERT INTO waitlist_offers (id, clinic_id, slot_id, patient_email, status, expires_at)
            VALUES ($1, $2, $3, $4, 'sent', $5)
            """,
            rows,
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
        *(send_offer_email_to_patient(slot, offer, clinic_settings) for offer in offers),
        return_exceptions=True,
    )


async def send_offer_email_to_patient(slot: asyncpg.Record, offer: asyncpg.Record, clinic_settings: dict) -> None:
    api_key = (resend.api_key or "").strip()
    recipient = str(offer["patient_email"])
    if not api_key or api_key == "re_your_key_here":
        logger.error("Resend is not configured; skipping outbound waitlist email to %s.", recipient)
        return

    from_email = os.getenv("RESEND_FROM_EMAIL", "SwiftSlot <onboarding@resend.dev>")
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
            await loop.run_in_executor(
                None,
                lambda: resend.Emails.send(payload),
            )
        except Exception:
            logger.exception("Failed to send waitlist offer email to %s", recipient)


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
