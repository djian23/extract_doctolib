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

    # --- Authentication ---

    def _do_login(self, extra_payload: Optional[dict] = None) -> Any:
        """POST /login.json with optional extra fields. Returns (resp, data)."""
        payload = {
            "kind": "doctor",
            "username": self.email,
            "password": self.password,
            "remember": True,
            "remember_username": True,
        }
        if extra_payload:
            payload.update(extra_payload)

        resp = self.session.post(self._url("/login.json"), json=payload)
        data = None
        try:
            data = resp.json()
        except ValueError:
            pass
        return resp, data

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
        try:
            resp, data = self._do_login()
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

        if data is None:
            return {
                "success": False,
                "requires_2fa": False,
                "message": "Réponse invalide du serveur (non-JSON).",
            }

        self._account_data = data
        logger.info(f"Login response keys: {list(data.keys())}")

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

        # No 2FA needed - login complete
        self._authenticated = True
        return {
            "success": True,
            "requires_2fa": False,
            "message": "Connecté avec succès à Doctolib Pro.",
        }

    def submit_2fa_code(self, code: str) -> dict[str, Any]:
        """Submit 2FA authentication code."""
        # Step 1: Validate the 2FA code
        tfa_validated = False
        try:
            resp = self.session.post(
                self._url("/api/accounts/two_factor_authentication"),
                json={"auth_code": code},
            )
            logger.info(f"2FA validation: HTTP {resp.status_code}")
            try:
                tfa_data = resp.json()
                logger.info(f"2FA response keys: {list(tfa_data.keys()) if isinstance(tfa_data, dict) else type(tfa_data)}")
            except ValueError:
                tfa_data = None
            if resp.status_code < 400:
                tfa_validated = True
        except Exception as e:
            logger.warning(f"2FA validation endpoint failed: {e}")

        if not tfa_validated:
            # Fallback: try login.json with auth_code included
            try:
                resp, data = self._do_login(extra_payload={
                    "auth_code": code,
                    "two_factor_auth_method": "email",
                })
                logger.info(f"2FA via login.json: HTTP {resp.status_code}")
                if resp.status_code < 400 and data:
                    self._account_data = data
                    self._authenticated = True
                    self._requires_2fa = False
                    logger.info(f"Login+2FA combined success, keys: {list(data.keys())}")
                    return {
                        "success": True,
                        "requires_2fa": False,
                        "message": "Authentification 2FA réussie.",
                    }
            except Exception as e:
                logger.warning(f"Combined login+2FA failed: {e}")

            return {
                "success": False,
                "requires_2fa": True,
                "message": f"Code 2FA invalide.",
            }

        # Step 2: 2FA validated - now re-login to complete the session
        # The 2FA endpoint only validates the code in the session.
        # We need to POST /login.json again to get the full account data.
        logger.info("2FA validated, re-submitting login to complete session...")
        try:
            resp, data = self._do_login()
            logger.info(f"Post-2FA re-login: HTTP {resp.status_code}")
            if resp.status_code < 400 and data:
                logger.info(f"Post-2FA login keys: {list(data.keys())}")
                # Check if we got real account data (not another 2FA challenge)
                redirect = data.get("redirect") or data.get("redirection")
                if redirect and "two-factor" in str(redirect):
                    logger.warning("Still getting 2FA challenge after code validation")
                    # Try the combined approach
                    resp2, data2 = self._do_login(extra_payload={
                        "auth_code": code,
                        "two_factor_auth_method": "email",
                    })
                    logger.info(f"Combined login+2FA: HTTP {resp2.status_code}")
                    if resp2.status_code < 400 and data2:
                        data = data2
                        logger.info(f"Combined login+2FA keys: {list(data.keys())}")

                self._account_data = data
                self._authenticated = True
                self._requires_2fa = False
                return {
                    "success": True,
                    "requires_2fa": False,
                    "message": "Authentification 2FA réussie.",
                }
        except Exception as e:
            logger.warning(f"Post-2FA re-login failed: {e}")

        # If re-login didn't work, still mark as authenticated
        # (the 2FA was validated successfully)
        self._authenticated = True
        self._requires_2fa = False
        return {
            "success": True,
            "requires_2fa": False,
            "message": "Authentification 2FA réussie (session partielle).",
        }

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

        endpoints = [
            ("/api/appointments.json", params_with_agendas),
            ("/api/events.json", params_with_agendas),
            ("/events.json", params_with_agendas),
            ("/appointments.json", base_params),
        ]

        # Per-agenda endpoints
        if agenda_ids:
            for aid in agenda_ids.split("-"):
                endpoints.append((f"/api/agendas/{aid}/events.json", base_params))

        errors = []
        for path, params in endpoints:
            try:
                url = self._url(path)
                resp = self.session.get(url, params=params)
                status = resp.status_code
                body_preview = resp.text[:200] if resp.text else "(empty)"
                logger.info(f"Appointments {path}: HTTP {status} | Body: {body_preview}")
                if status < 400:
                    ct = resp.headers.get("content-type", "")
                    if "json" not in ct and "html" in ct:
                        errors.append(f"{path}: HTTP {status} but HTML response")
                        continue
                    try:
                        data = resp.json()
                        if isinstance(data, (list, dict)):
                            return data
                    except ValueError:
                        errors.append(f"{path}: HTTP {status} invalid JSON")
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
            f"/api/appointments/{appointment_id}.json",
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
        errors = []
        for path in [
            "/api/patients.json",
            "/api/master_patients.json",
            "/account/master_patients.json",
        ]:
            try:
                resp = self.session.get(self._url(path))
                logger.info(f"Patients {path}: HTTP {resp.status_code}")
                if resp.status_code < 400:
                    ct = resp.headers.get("content-type", "")
                    if "json" not in ct and "html" in ct:
                        errors.append(f"{path}: HTTP {resp.status_code} but HTML")
                        continue
                    return resp.json()
                else:
                    errors.append(f"{path}: HTTP {resp.status_code}")
            except Exception as e:
                errors.append(f"{path}: {e}")
                logger.warning(f"Patients attempt {path} failed: {e}")
                continue
        raise RuntimeError(f"Aucun endpoint n'a fonctionné pour les patients. Détails: {'; '.join(errors)}")

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

        resp = self.session.get(self._url("/availabilities.json"), params=params)
        resp.raise_for_status()
        return resp.json()

    # --- Account ---

    def get_account_info(self) -> dict[str, Any]:
        """Return stored account data from login response."""
        return self._account_data
