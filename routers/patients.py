from fastapi import APIRouter, HTTPException, Request

router = APIRouter(prefix="/patients", tags=["Patients"])


def _require_auth(request: Request):
    client = request.app.state.doctolib_client
    if not client.is_authenticated:
        raise HTTPException(status_code=401, detail="Non authentifié. Appelez POST /auth/login d'abord.")
    return client


@router.get("")
def list_patients(request: Request):
    """Lister les patients (master patients) du compte Doctolib Pro."""
    client = _require_auth(request)
    try:
        data = client.get_patients()
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Erreur Doctolib: {e}")
    return data
