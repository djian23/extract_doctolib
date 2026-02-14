from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from doctolib.models import (
    AuthStatus,
    LoginRequest,
    LoginResponse,
    TwoFactorRequest,
)

router = APIRouter(prefix="/auth", tags=["Authentification"])


@router.post("/login", response_model=LoginResponse)
def login(body: LoginRequest, request: Request):
    """Se connecter à Doctolib Pro avec email et mot de passe."""
    client = request.app.state.doctolib_client

    # Update credentials if different from config
    if body.email != client.email or body.password != client.password:
        client.email = body.email
        client.password = body.password

    result = client.login()
    status_code = 200 if result["success"] or result["requires_2fa"] else 401
    return JSONResponse(content=result, status_code=status_code)


@router.post("/2fa", response_model=LoginResponse)
def submit_2fa(body: TwoFactorRequest, request: Request):
    """Soumettre le code d'authentification à deux facteurs (2FA)."""
    client = request.app.state.doctolib_client

    if not client.requires_2fa:
        return JSONResponse(
            content={
                "success": False,
                "requires_2fa": False,
                "message": "Aucune 2FA en attente. Connectez-vous d'abord.",
            },
            status_code=400,
        )

    result = client.submit_2fa_code(body.auth_code)
    status_code = 200 if result["success"] else 401
    return JSONResponse(content=result, status_code=status_code)


@router.post("/resend-code")
def resend_2fa_code(request: Request):
    """Renvoyer le code 2FA par email."""
    client = request.app.state.doctolib_client
    if not client.requires_2fa:
        return JSONResponse(
            content={"message": "Aucune 2FA en attente. Connectez-vous d'abord."},
            status_code=400,
        )
    result = client.resend_2fa_code()
    return result


@router.get("/status", response_model=AuthStatus)
def auth_status(request: Request):
    """Vérifier l'état de l'authentification."""
    client = request.app.state.doctolib_client
    return AuthStatus(
        authenticated=client.is_authenticated,
        email=client.email if client.is_authenticated else None,
    )


@router.post("/logout")
def logout(request: Request):
    """Se déconnecter et réinitialiser la session."""
    client = request.app.state.doctolib_client
    client.logout()
    return {"message": "Déconnecté."}
