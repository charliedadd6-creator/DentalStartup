import uuid
from datetime import datetime
from pydantic import BaseModel, EmailStr
from typing import Optional

# =========================
# Database Models (Schema Definitions)
# =========================

class ClinicCreate(BaseModel):
    name: str

class UserCreate(BaseModel):
    clinic_name: str
    email: EmailStr
    password: str

class UserLogin(BaseModel):
    email: EmailStr
    password: str

class UserPublic(BaseModel):
    id: str
    clinic_id: str
    email: EmailStr
    is_owner: bool

# =========================
# Utility helpers
# =========================

def generate_uuid():
    return str(uuid.uuid4())

def utc_now():
    return datetime.utcnow()
