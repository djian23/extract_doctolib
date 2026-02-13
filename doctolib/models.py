from datetime import date, datetime
from typing import Any, Optional

from pydantic import BaseModel


# --- Auth ---

class LoginRequest(BaseModel):
    email: str
    password: str


class TwoFactorRequest(BaseModel):
    auth_code: str


class LoginResponse(BaseModel):
    success: bool
    requires_2fa: bool = False
    message: str = ""


class AuthStatus(BaseModel):
    authenticated: bool
    email: Optional[str] = None


# --- Appointments ---

class Appointment(BaseModel):
    id: int
    patient_id: Optional[int] = None
    patient_name: Optional[str] = None
    patient_email: Optional[str] = None
    patient_phone: Optional[str] = None
    start_date: Optional[datetime] = None
    end_date: Optional[datetime] = None
    duration: Optional[int] = None
    status: Optional[str] = None
    visit_motive: Optional[str] = None
    visit_motive_id: Optional[int] = None
    agenda_id: Optional[int] = None
    practice_id: Optional[int] = None
    notes: Optional[str] = None
    raw_data: Optional[dict[str, Any]] = None


class AppointmentList(BaseModel):
    items: list[Appointment]
    total: int


class AppointmentDetail(BaseModel):
    appointment: Appointment
    raw_data: dict[str, Any] = {}


# --- Patients ---

class Patient(BaseModel):
    id: int
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    email: Optional[str] = None
    phone: Optional[str] = None
    birthdate: Optional[date] = None
    gender: Optional[str] = None
    raw_data: Optional[dict[str, Any]] = None


class PatientList(BaseModel):
    items: list[Patient]
    total: int


# --- Availabilities ---

class AvailabilitySlot(BaseModel):
    datetime: str
    duration: Optional[int] = None
    raw_data: Optional[dict[str, Any]] = None


class AvailabilityDay(BaseModel):
    date: str
    slots: list[AvailabilitySlot]


class AvailabilityResponse(BaseModel):
    availabilities: list[AvailabilityDay]
    total_slots: int
