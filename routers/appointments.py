from typing import Optional

from fastapi import APIRouter, HTTPException, Query, Request

router = APIRouter(prefix="/appointments", tags=["Rendez-vous"])


def _require_auth(request: Request):
    client = request.app.state.doctolib_client
    if not client.is_authenticated:
        raise HTTPException(status_code=401, detail="Non authentifié. Appelez POST /auth/login d'abord.")
    return client


@router.get("")
def list_appointments(
    request: Request,
    start_date: Optional[str] = Query(None, description="Date de début (YYYY-MM-DD)"),
    end_date: Optional[str] = Query(None, description="Date de fin (YYYY-MM-DD)"),
):
    """
    Lister les rendez-vous.

    Retourne les données brutes de Doctolib Pro pour la période demandée.
    Par défaut : aujourd'hui → +30 jours.
    """
    client = _require_auth(request)
    try:
        data = client.get_appointments(start_date=start_date, end_date=end_date)
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Erreur Doctolib: {e}")
    return data


@router.get("/{appointment_id}")
def get_appointment(appointment_id: int, request: Request):
    """Obtenir les détails d'un rendez-vous spécifique."""
    client = _require_auth(request)
    try:
        data = client.get_appointment(appointment_id)
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Erreur Doctolib: {e}")
    return data
