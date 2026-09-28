"""
Database setup: connection pool creation, schema bootstrap, and the
one-time recovered-appointments backfill. Extracted from app.py
(Stage 1 refactor).

Route handlers should keep using request.app.state.pool — this module
only owns *creating* that pool and setting up the schema at startup.
"""
import asyncpg

from config import logger


async def create_db_pool(settings) -> asyncpg.Pool:
    """Create the asyncpg connection pool from validated Settings."""
    pool = await asyncpg.create_pool(
        dsn=settings.database_url,
        min_size=settings.db_min_size,
        max_size=settings.db_max_size,
    )
    async with pool.acquire() as conn:
        await conn.fetchval("SELECT 1")
    return pool


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
        CREATE TABLE IF NOT EXISTS access_requests (
            id UUID PRIMARY KEY,
            clinic_name TEXT,
            contact_name TEXT NOT NULL,
            contact_email TEXT NOT NULL,
            phone TEXT,
            practice_type TEXT,
            practice_size TEXT,
            message TEXT,
            status TEXT NOT NULL DEFAULT 'new',
            source TEXT NOT NULL DEFAULT 'landing',
            created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
            updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
        );
        """)

        await conn.execute("""
        CREATE INDEX IF NOT EXISTS idx_access_requests_status
        ON access_requests(status);
        """)

        await conn.execute("""
        CREATE INDEX IF NOT EXISTS idx_access_requests_created_at
        ON access_requests(created_at);
        """)

        await conn.execute("""
        ALTER TABLE access_requests
        ADD COLUMN IF NOT EXISTS notes TEXT;
        """)

        await conn.execute("""
        ALTER TABLE users
        ADD COLUMN IF NOT EXISTS role TEXT NOT NULL DEFAULT 'clinic_user';
        """)

        await conn.execute("""
        UPDATE users
        SET role = 'clinic_admin'
        WHERE is_owner = TRUE
          AND (role IS NULL OR role = 'clinic_user');
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
        ALTER TABLE clinics
        ADD COLUMN IF NOT EXISTS onboarding_completed_at TIMESTAMPTZ;
        """)

        await conn.execute("""
        ALTER TABLE clinics
        ADD COLUMN IF NOT EXISTS onboarding_step TEXT;
        """)

        await conn.execute("""
        ALTER TABLE clinics
        ADD COLUMN IF NOT EXISTS pilot_status TEXT NOT NULL DEFAULT 'setup';
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


