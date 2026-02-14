from typing import Optional

from fastapi import APIRouter, HTTPException, Query, Request

router = APIRouter(prefix="/availabilities", tags=["Disponibilités"])


def _require_auth(request: Request):
    client = request.app.state.doctolib_client
    if not client.is_authenticated:
        raise HTTPException(status_code=401, detail="Non authentifié. Appelez POST /auth/login d'abord.")
    return client


@router.get("")
def list_availabilities(
    request: Request,
    agenda_ids: str = Query(..., description="IDs des agendas séparés par des tirets (ex: 12345-67890)"),
    visit_motive_ids: str = Query(..., description="ID du motif de visite"),
    practice_ids: str = Query(..., description="ID du cabinet"),
    start_date: Optional[str] = Query(None, description="Date de début (YYYY-MM-DD)"),
    limit: int = Query(3, ge=1, le=7, description="Nombre de jours à consulter (1-7)"),
):
    """
    Consulter les créneaux disponibles.

    Nécessite les IDs d'agenda, motif de visite et cabinet.
    """
    client = _require_auth(request)
    try:
        data = client.get_availabilities(
            agenda_ids=agenda_ids,
            visit_motive_ids=visit_motive_ids,
            practice_ids=practice_ids,
            start_date=start_date,
            limit=limit,
        )
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Erreur Doctolib: {e}")
    return data
