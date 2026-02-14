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
    Teste plusieurs endpoints sur les deux domaines Doctolib.
    Utile pour identifier les bons chemins d'API.
    """
    from fastapi import HTTPException
    client = app.state.doctolib_client
    if not client.is_authenticated:
        raise HTTPException(status_code=401, detail="Non authentifié.")

    test_paths = [
        "/api/events.json",
        "/events.json",
        "/api/appointments.json",
        "/appointments.json",
        "/account.json",
        "/api/account.json",
        "/api/patients.json",
        "/api/master_patients.json",
    ]

    agenda_ids = client._get_agenda_ids()
    results = {
        "auth_base_url": client.base_url,
        "api_base_url": client.api_base_url,
        "api_session_established": client._api_session_established,
        "agenda_ids": agenda_ids,
        "account_keys": list(client._account_data.keys())[:20],
        "cookies": list(client.session.cookies.keys()),
        "endpoints": [],
    }

    # Test paths on both domains
    for base_label, base_url in [("admin", client.api_base_url), ("pro", client.base_url)]:
        for path in test_paths:
            try:
                params = {"start_date": "2026-02-14", "end_date": "2026-02-15"}
                if agenda_ids and "event" in path:
                    params["agenda_ids"] = agenda_ids
                url = f"{base_url}{path}"
                resp = client.session.get(url, params=params)
                body = resp.text[:300] if resp.text else ""
                results["endpoints"].append({
                    "domain": base_label,
                    "path": path,
                    "full_url": url,
                    "status": resp.status_code,
                    "content_type": resp.headers.get("content-type", ""),
                    "body_preview": body,
                })
            except Exception as e:
                results["endpoints"].append({
                    "domain": base_label,
                    "path": path,
                    "status": "error",
                    "error": str(e),
                })

    return results
