import logging
import time
from datetime import date, datetime
from typing import Any, Optional

import cloudscraper

logger = logging.getLogger(__name__)


class DoctolibClient:
    """Client HTTP pour interagir avec l'API interne de Doctolib Pro."""

    DEFAULT_HEADERS = {
        "sec-fetch-dest": "document",
        "sec-fetch-mode": "navigate",
        "sec-fetch-site": "same-origin",
        "User-Agent": (
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        ),
    }

    def __init__(self, base_url: str, email: str, password: str):
        self.base_url = base_url.rstrip("/")
        self.email = email
        self.password = password
        self._authenticated = False
        self._requires_2fa = False
        self._account_data: dict[str, Any] = {}

        self.session = cloudscraper.create_scraper()
        self.session.headers.update(self.DEFAULT_HEADERS)

    @property
    def is_authenticated(self) -> bool:
        return self._authenticated

    @property
    def requires_2fa(self) -> bool:
        return self._requires_2fa

    def _url(self, path: str) -> str:
        return f"{self.base_url}{path}"

    def _get_json(self, path: str, params: Optional[dict] = None) -> dict[str, Any]:
        """GET request returning JSON. Raises on HTTP error."""
        resp = self.session.get(self._url(path), params=params)
        resp.raise_for_status()
        return resp.json()

    def _post_json(self, path: str, json_data: Optional[dict] = None) -> dict[str, Any]:
        """POST request with JSON body, returning JSON. Raises on HTTP error."""
        resp = self.session.post(self._url(path), json=json_data)
        resp.raise_for_status()
        return resp.json()

    # --- Authentication ---

    def login(self) -> dict[str, Any]:
        """
        Authenticate with Doctolib Pro.

        Returns a dict with keys:
          - success: bool
          - requires_2fa: bool
          - message: str
        """
        # Step 1: Initialize session (get cookies, CSRF token)
        try:
            resp = self.session.get(self._url("/sessions/new"))
            if resp.status_code in (503, 520):
                return {
                    "success": False,
                    "requires_2fa": False,
                    "message": "Bloqué par Cloudflare. Réessayez plus tard.",
                }
        except Exception as e:
            return {
                "success": False,
                "requires_2fa": False,
                "message": f"Erreur lors de l'initialisation de session: {e}",
            }

        # Step 2: POST login credentials
        login_payload = {
            "kind": "doctor",
            "username": self.email,
            "password": self.password,
            "remember": True,
            "remember_username": True,
        }

        try:
            resp = self.session.post(self._url("/login.json"), json=login_payload)
        except Exception as e:
            return {
                "success": False,
                "requires_2fa": False,
                "message": f"Erreur réseau lors du login: {e}",
            }

        if resp.status_code == 401:
            return {
                "success": False,
                "requires_2fa": False,
                "message": "Email ou mot de passe incorrect.",
            }

        if resp.status_code >= 400:
            return {
                "success": False,
                "requires_2fa": False,
                "message": f"Erreur HTTP {resp.status_code}: {resp.text[:200]}",
            }

        try:
            data = resp.json()
        except ValueError:
            return {
                "success": False,
                "requires_2fa": False,
                "message": "Réponse invalide du serveur (non-JSON).",
            }

        self._account_data = data

        # Step 3: Check if 2FA is required
        redirect = data.get("redirect") or data.get("redirection")
        if redirect and "two-factor" in str(redirect):
            self._requires_2fa = True
            # Send 2FA code via email
            try:
                self.session.post(
                    self._url("/api/accounts/send_auth_code"),
                    json={"two_factor_auth_method": "email"},
                )
            except Exception:
                pass  # Code may already be sent
            return {
                "success": False,
                "requires_2fa": True,
                "message": "Code 2FA envoyé par email. Soumettez-le via POST /auth/2fa.",
            }

        self._authenticated = True
        return {
            "success": True,
            "requires_2fa": False,
            "message": "Connecté avec succès à Doctolib Pro.",
        }

    def submit_2fa_code(self, code: str) -> dict[str, Any]:
        """Submit 2FA authentication code."""
        # Try multiple known Doctolib 2FA endpoints
        endpoints = [
            ("/api/accounts/two_factor_authentication", {"auth_code": code}),
            ("/login.json", {
                "kind": "doctor",
                "username": self.email,
                "password": self.password,
                "auth_code": code,
                "two_factor_auth_method": "email",
            }),
        ]

        last_resp = None
        for endpoint, payload in endpoints:
            try:
                resp = self.session.post(self._url(endpoint), json=payload)
                last_resp = resp
                logger.info(f"2FA attempt on {endpoint}: HTTP {resp.status_code}")
                if resp.status_code < 400:
                    # Try to capture response data
                    try:
                        resp_data = resp.json()
                        if resp_data and isinstance(resp_data, dict):
                            # If the 2FA response contains account data, store it
                            if "doctor" in resp_data or "agendas" in resp_data:
                                self._account_data = resp_data
                                logger.info("Account data updated from 2FA response")
                    except ValueError:
                        pass
                    break
            except Exception as e:
                logger.warning(f"2FA attempt on {endpoint} failed: {e}")
                continue

        if last_resp is None:
            return {
                "success": False,
                "requires_2fa": True,
                "message": "Erreur réseau sur tous les endpoints 2FA.",
            }

        if last_resp.status_code >= 400:
            return {
                "success": False,
                "requires_2fa": True,
                "message": f"Code 2FA invalide (HTTP {last_resp.status_code}).",
            }

        self._authenticated = True
        self._requires_2fa = False

        # Re-fetch full account data after successful 2FA
        self._refresh_account_data()

        return {
            "success": True,
            "requires_2fa": False,
            "message": "Authentification 2FA réussie.",
        }

    def _refresh_account_data(self) -> None:
        """Fetch full account data after authentication (post-2FA)."""
        account_endpoints = [
            "/api/accounts/current.json",
            "/account.json",
            "/api/account.json",
        ]
        for path in account_endpoints:
            try:
                resp = self.session.get(self._url(path))
                logger.info(f"Account refresh {path}: HTTP {resp.status_code}")
                if resp.status_code < 400:
                    data = resp.json()
                    if data and isinstance(data, dict):
                        self._account_data = data
                        logger.info(
                            f"Account data refreshed from {path}, "
                            f"keys: {list(data.keys())[:10]}"
                        )
                        return
            except Exception as e:
                logger.warning(f"Account refresh {path} failed: {e}")
                continue
        logger.warning("Could not refresh account data from any endpoint")

    def logout(self) -> None:
        """Reset session."""
        self._authenticated = False
        self._requires_2fa = False
        self._account_data = {}
        self.session = cloudscraper.create_scraper()
        self.session.headers.update(self.DEFAULT_HEADERS)

    def _get_agenda_ids(self) -> str:
        """Extract agenda IDs from account data, searching multiple structures."""
        agendas = []

        # Try "doctor.agendas" (login response structure)
        doctor = self._account_data.get("doctor", {})
        for agenda in doctor.get("agendas", []):
            aid = agenda.get("id")
            if aid:
                agendas.append(str(aid))

        # Try top-level "agendas" (account endpoint structure)
        if not agendas:
            for agenda in self._account_data.get("agendas", []):
                aid = agenda.get("id")
                if aid:
                    agendas.append(str(aid))

        # Try "data.agendas" variant
        if not agendas:
            data = self._account_data.get("data", {})
            if isinstance(data, dict):
                for agenda in data.get("agendas", []):
                    aid = agenda.get("id")
                    if aid:
                        agendas.append(str(aid))

        result = "-".join(agendas)
        logger.info(f"Agenda IDs extracted: '{result}' (from keys: {list(self._account_data.keys())[:10]})")
        return result

    # --- Appointments ---

    def get_appointments(
        self,
        start_date: Optional[str] = None,
        end_date: Optional[str] = None,
    ) -> Any:
        """
        Fetch appointments list.

        Args:
            start_date: Format YYYY-MM-DD (default: today)
            end_date: Format YYYY-MM-DD (default: +30 days)
        """
        from datetime import timedelta

        if not start_date:
            start_date = date.today().isoformat()
        if not end_date:
            end_date = (date.today() + timedelta(days=30)).isoformat()

        agenda_ids = self._get_agenda_ids()
        base_params = {"start_date": start_date, "end_date": end_date}
        params_with_agendas = {**base_params, **({"agenda_ids": agenda_ids} if agenda_ids else {})}

        # Try multiple known Doctolib Pro endpoints
        endpoints = [
            ("/api/events.json", params_with_agendas),
            ("/events.json", params_with_agendas),
            ("/api/calendar/events.json", params_with_agendas),
            ("/calendar/events.json", base_params),
            ("/appointments.json", base_params),
            ("/api/appointments.json", base_params),
        ]

        # If we have individual agenda IDs, also try per-agenda endpoints
        if agenda_ids:
            for aid in agenda_ids.split("-"):
                endpoints.append((f"/api/agendas/{aid}/events.json", base_params))

        errors = []
        for path, params in endpoints:
            try:
                resp = self.session.get(self._url(path), params=params)
                status = resp.status_code
                # Log response snippet for debugging
                body_preview = resp.text[:200] if resp.text else "(empty)"
                logger.info(
                    f"Appointments {path}: HTTP {status} | "
                    f"Body: {body_preview}"
                )
                if status < 400:
                    try:
                        data = resp.json()
                        # Validate it looks like real data (not a login page)
                        if isinstance(data, (list, dict)):
                            return data
                    except ValueError:
                        errors.append(f"{path}: HTTP {status} but invalid JSON")
                        continue
                else:
                    errors.append(f"{path}: HTTP {status}")
            except Exception as e:
                errors.append(f"{path}: {e}")
                logger.warning(f"Appointments attempt {path} failed: {e}")
                continue

        error_details = "; ".join(errors)
        raise RuntimeError(
            f"Aucun endpoint n'a fonctionné pour les rendez-vous. "
            f"Agenda IDs: '{agenda_ids}'. Détails: {error_details}"
        )

    def get_appointment(self, appointment_id: int) -> dict[str, Any]:
        """Fetch details of a specific appointment."""
        for path in [
            f"/api/events/{appointment_id}.json",
            f"/appointments/{appointment_id}/edit.json",
            f"/appointments/{appointment_id}.json",
        ]:
            try:
                resp = self.session.get(self._url(path))
                if resp.status_code < 400:
                    return resp.json()
            except Exception:
                continue
        raise RuntimeError(f"Rendez-vous {appointment_id} non trouvé.")

    # --- Patients ---

    def get_patients(self) -> Any:
        """Fetch master patients list."""
        for path in [
            "/api/patients.json",
            "/api/master_patients.json",
            "/account/master_patients.json",
        ]:
            try:
                resp = self.session.get(self._url(path))
                logger.info(f"Patients attempt {path}: HTTP {resp.status_code}")
                if resp.status_code < 400:
                    return resp.json()
            except Exception as e:
                logger.warning(f"Patients attempt {path} failed: {e}")
                continue
        raise RuntimeError("Aucun endpoint n'a fonctionné pour les patients.")

    # --- Availabilities ---

    def get_availabilities(
        self,
        agenda_ids: str,
        visit_motive_ids: str,
        practice_ids: str,
        start_date: Optional[str] = None,
        limit: int = 3,
    ) -> dict[str, Any]:
        """
        Fetch available slots.

        Args:
            agenda_ids: Dash-separated agenda IDs (e.g. "12345-67890")
            visit_motive_ids: Visit motive ID
            practice_ids: Practice ID
            start_date: Format YYYY-MM-DD (default: today)
            limit: Number of days to look ahead (3-7)
        """
        if not start_date:
            start_date = date.today().isoformat()

        params = {
            "start_date": start_date,
            "visit_motive_ids": visit_motive_ids,
            "agenda_ids": agenda_ids,
            "practice_ids": practice_ids,
            "insurance_sector": "public",
            "destroy_temporary": "true",
            "limit": limit,
        }

        return self._get_json("/availabilities.json", params=params)

    # --- Account ---

    def get_account_info(self) -> dict[str, Any]:
        """Return stored account data from login response."""
        return self._account_data
