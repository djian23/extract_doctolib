from contextlib import asynccontextmanager

from fastapi import FastAPI

from config import settings
from doctolib.client import DoctolibClient
from routers import appointments, auth, availabilities, patients


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Initialize Doctolib client on startup
    app.state.doctolib_client = DoctolibClient(
        base_url=settings.doctolib_base_url,
        email=settings.doctolib_email,
        password=settings.doctolib_password,
    )
    yield
    # Cleanup on shutdown
    app.state.doctolib_client.logout()


app = FastAPI(
    title="Doctolib Pro API",
    description=(
        "API REST locale pour extraire les données de votre compte Doctolib Pro "
        "(rendez-vous, patients, disponibilités). "
        "Connectez-vous d'abord via POST /auth/login, puis utilisez les autres endpoints."
    ),
    version="1.0.0",
    lifespan=lifespan,
)

app.include_router(auth.router)
app.include_router(appointments.router)
app.include_router(patients.router)
app.include_router(availabilities.router)


@app.get("/", tags=["Status"])
def root():
    """Vérifier que l'API est en ligne."""
    client = app.state.doctolib_client
    return {
        "status": "ok",
        "service": "Doctolib Pro API",
        "authenticated": client.is_authenticated,
        "docs": "/docs",
    }


@app.get("/account", tags=["Compte"])
def account_info():
    """Retourne les données du compte Doctolib (agendas, IDs, etc.)."""
    from fastapi import HTTPException
    client = app.state.doctolib_client
    if not client.is_authenticated:
        raise HTTPException(status_code=401, detail="Non authentifié.")
    return client.get_account_info()


@app.get("/debug/endpoints", tags=["Debug"])
def debug_endpoints():
    """
    Teste /api/appointments.json avec différentes méthodes d'auth.
    Compare: cookies seuls, headers AJAX, Bearer token, domaine www.
    """
    from fastapi import HTTPException
    client = app.state.doctolib_client
    if not client.is_authenticated:
        raise HTTPException(status_code=401, detail="Non authentifié.")
    return client.debug_api_test()
