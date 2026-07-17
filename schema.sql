-- Database Schema Migration / Design File
-- Designed by Senior Backend Architect
-- Target Database: PostgreSQL

-- Enable UUID extension if not already present
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- ==========================================
-- 1. CLINICS TABLE
-- ==========================================
-- Clinics managed by SwiftSlot. Contains base parameters and clinical configuration.
CREATE TABLE clinics (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name TEXT NOT NULL,
    display_name TEXT,
    contact_email TEXT,
    phone TEXT,
    sender_name TEXT,
    reply_to_email TEXT,
    default_slot_value_pence INT NOT NULL DEFAULT 0,
    default_expiry_minutes INT NOT NULL DEFAULT 240,
    gdpr_notice TEXT,
    onboarding_completed_at TIMESTAMPTZ,
    onboarding_step TEXT,
    pilot_status TEXT NOT NULL DEFAULT 'setup' CHECK (pilot_status IN ('setup', 'testing', 'live', 'paused', 'churned')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ==========================================
-- 2. PATIENTS TABLE
-- ==========================================
-- Short-notice waitlist patients. Represents GDPR consent and waitlist lifecycle status.
CREATE TABLE patients (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    clinic_id UUID NOT NULL REFERENCES clinics(id) ON DELETE CASCADE,
    first_name TEXT NOT NULL,
    last_name TEXT,
    email TEXT NOT NULL,
    phone TEXT,
    consent_status TEXT NOT NULL DEFAULT 'consented' CHECK (consent_status IN ('consented', 'pending', 'withdrawn', 'not_consented', 'unknown')),
    consent_source TEXT DEFAULT 'manual',
    consented_at TIMESTAMPTZ,
    notes TEXT,
    priority INT NOT NULL DEFAULT 3 CHECK (priority BETWEEN 1 AND 5),
    preferred_appointment_type TEXT,
    preferred_clinician TEXT,
    last_contacted_at TIMESTAMPTZ,
    last_response_at TIMESTAMPTZ,
    accepted_count INT NOT NULL DEFAULT 0 CHECK (accepted_count >= 0),
    declined_count INT NOT NULL DEFAULT 0 CHECK (declined_count >= 0),
    offer_count INT NOT NULL DEFAULT 0 CHECK (offer_count >= 0),
    lifecycle_status TEXT NOT NULL DEFAULT 'waitlist' CHECK (lifecycle_status IN ('waitlist', 'booked', 'completed', 'archived')),
    booked_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    archived_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),

    -- Ensure unique emails within a single clinic
    CONSTRAINT idx_patients_clinic_email_unique UNIQUE (clinic_id, email)
);

-- Indexing for performance & rapid waitlist lookups
CREATE INDEX idx_patients_clinic_id ON patients(clinic_id);
CREATE INDEX idx_patients_consent_status ON patients(consent_status);
CREATE INDEX idx_patients_lifecycle_status ON patients(clinic_id, lifecycle_status);
CREATE INDEX idx_patients_priority ON patients(clinic_id, priority);

-- ==========================================
-- 3. BROADCASTS / WAITLIST_SLOTS TABLE
-- ==========================================
-- Repetition of waitlist_slots that act as the source records for short-notice notifications.
CREATE TABLE waitlist_slots (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    clinic_id UUID NOT NULL REFERENCES clinics(id) ON DELETE CASCADE,
    slot_time TIMESTAMPTZ NOT NULL,
    clinician TEXT,
    appointment_type TEXT,
    slot_value_pence INT NOT NULL DEFAULT 0 CHECK (slot_value_pence >= 0),
    status TEXT NOT NULL DEFAULT 'broadcasting' CHECK (status IN ('broadcasting', 'locked', 'declined', 'expired')),
    accepted_by TEXT, -- Email of patient who accepted
    expires_at TIMESTAMPTZ,
    expired_at TIMESTAMPTZ,
    locked_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_waitlist_slots_clinic_id ON waitlist_slots(clinic_id);
CREATE INDEX idx_waitlist_slots_expires_at ON waitlist_slots(expires_at);

-- ==========================================
-- 4. WAITLIST_OFFERS TABLE
-- ==========================================
-- Specific offers sent out to patients during a broadcast.
CREATE TABLE waitlist_offers (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    clinic_id UUID NOT NULL REFERENCES clinics(id) ON DELETE CASCADE,
    slot_id UUID NOT NULL REFERENCES waitlist_slots(id) ON DELETE CASCADE,
    patient_email TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'sent' CHECK (status IN ('sent', 'accepted', 'declined', 'expired')),
    email_send_status TEXT NOT NULL DEFAULT 'pending' CHECK (email_send_status IN ('pending', 'sent', 'failed')),
    email_provider_id TEXT,
    email_failed_reason TEXT,
    sent_at TIMESTAMPTZ,
    failed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    accepted_at TIMESTAMPTZ,
    declined_at TIMESTAMPTZ,
    expires_at TIMESTAMPTZ,
    expired_at TIMESTAMPTZ
);

CREATE INDEX idx_waitlist_offers_clinic_id ON waitlist_offers(clinic_id);
CREATE INDEX idx_waitlist_offers_slot_id ON waitlist_offers(slot_id);
CREATE INDEX idx_waitlist_offers_expires_at ON waitlist_offers(expires_at);

-- ==========================================
-- 5. APPOINTMENTS TABLE
-- ==========================================
-- Appointments created either manually or recovered through waitlist.
CREATE TABLE appointments (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    clinic_id UUID NOT NULL REFERENCES clinics(id) ON DELETE CASCADE,
    patient_id UUID REFERENCES patients(id) ON DELETE SET NULL,
    patient_name TEXT,
    patient_email TEXT NOT NULL,
    slot_id UUID REFERENCES waitlist_slots(id) ON DELETE SET NULL,
    source TEXT NOT NULL DEFAULT 'manual' CHECK (source IN ('manual', 'recovered', 'import', 'integration')),
    appointment_type TEXT,
    clinician TEXT,
    appointment_time TIMESTAMPTZ NOT NULL,
    slot_value_pence INT NOT NULL DEFAULT 0 CHECK (slot_value_pence >= 0),
    status TEXT NOT NULL DEFAULT 'booked' CHECK (status IN ('booked', 'completed', 'cancelled', 'no_show')),
    notes TEXT,
    completed_at TIMESTAMPTZ,
    cancelled_at TIMESTAMPTZ,
    no_show_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_appointments_clinic_time ON appointments(clinic_id, appointment_time);
CREATE INDEX idx_appointments_clinic_status ON appointments(clinic_id, status);
CREATE INDEX idx_appointments_patient_id ON appointments(patient_id);
CREATE INDEX idx_appointments_slot_id ON appointments(slot_id);

-- Avoid dual booking/recovering of the same waitlist slot ID
CREATE UNIQUE INDEX idx_appointments_unique_slot ON appointments(slot_id) WHERE slot_id IS NOT NULL;

-- ==========================================
-- 6. ACCESS_REQUESTS TABLE
-- ==========================================
-- Leads or clinics requesting access to SwiftSlot pilot.
CREATE TABLE access_requests (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    clinic_name TEXT,
    contact_name TEXT NOT NULL,
    contact_email TEXT NOT NULL,
    phone TEXT,
    practice_type TEXT,
    practice_size TEXT,
    message TEXT,
    status TEXT NOT NULL DEFAULT 'new' CHECK (status IN ('new', 'contacted', 'qualified', 'rejected', 'converted')),
    source TEXT NOT NULL DEFAULT 'landing',
    notes TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_access_requests_status ON access_requests(status);
CREATE INDEX idx_access_requests_created_at ON access_requests(created_at);

-- ==========================================
-- 7. AUDIT LOG (AUDIT_EVENTS) TABLE
-- ==========================================
-- Tracks events and user/system activity for clinical review.
CREATE TABLE audit_log (
    id BIGSERIAL PRIMARY KEY,
    clinic_id UUID REFERENCES clinics(id) ON DELETE SET NULL,
    event_type TEXT NOT NULL,
    slot_id UUID,
    offer_id UUID,
    patient_email_hash TEXT,
    client_ip TEXT,
    success BOOLEAN NOT NULL DEFAULT TRUE,
    details TEXT, -- JSON structure stored as string/text (compatible with app.py parsing)
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_audit_log_clinic_id ON audit_log(clinic_id);
CREATE INDEX idx_audit_log_slot_id ON audit_log(slot_id) WHERE slot_id IS NOT NULL;

-- ==========================================
-- 8. COMPATIBILITY VIEWS & VIRTUAL ENTITIES
-- ==========================================

-- A. "broadcasts" View
-- Merges the raw slots with metrics on counts of offers and status for quick UI queries.
CREATE OR REPLACE VIEW broadcasts AS
SELECT
    s.id AS id,
    s.clinic_id AS clinic_id,
    s.slot_time AS slot_time,
    s.clinician AS clinician,
    s.appointment_type AS appointment_type,
    s.slot_value_pence AS slot_value_pence,
    COUNT(o.id)::INT AS offers_sent,
    COUNT(o.id) FILTER (WHERE o.email_send_status = 'sent')::INT AS sent_email_count,
    COUNT(o.id) FILTER (WHERE o.email_send_status = 'failed')::INT AS failed_email_count,
    s.status AS status,
    s.accepted_by AS accepted_by,
    s.created_at AS created_at
FROM waitlist_slots s
LEFT JOIN waitlist_offers o ON o.slot_id = s.id AND o.clinic_id = s.clinic_id
GROUP BY s.id;

-- B. "email_failures" View
-- Exposes all waitlist offers where the email dispatch failed, including reasons and failure timestamps.
CREATE OR REPLACE VIEW email_failures AS
SELECT
    o.id AS id,
    o.clinic_id AS clinic_id,
    o.slot_id AS slot_id,
    o.patient_email AS patient_email,
    o.email_provider_id AS provider_id,
    o.email_failed_reason AS reason,
    o.failed_at AS failed_at,
    o.created_at AS created_at
FROM waitlist_offers o
WHERE o.email_send_status = 'failed';

-- C. "audit_events" View
-- An architectural alias for audit_log to match UI/API driven nomenclature.
CREATE OR REPLACE VIEW audit_events AS
SELECT
    id,
    clinic_id,
    event_type,
    slot_id,
    offer_id,
    patient_email_hash,
    client_ip,
    success,
    details,
    created_at
FROM audit_log;

-- ==========================================
-- 9. COMPUTED / DERIVED METRICS FOR CLINICS
-- ==========================================
-- This function gets the total revenue saved for a given clinic_id by summing slot_value_pence of locked appointments.
CREATE OR REPLACE FUNCTION get_clinic_revenue_saved_pence(target_clinic_id UUID)
RETURNS BIGINT AS $$
BEGIN
    RETURN COALESCE(
        (SELECT SUM(slot_value_pence)
         FROM waitlist_slots
         WHERE clinic_id = target_clinic_id AND (status = 'locked' OR accepted_by IS NOT NULL)),
        0
    );
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;
