import logging
import time
from datetime import date, datetime
from typing import Any, Optional

import cloudscraper

logger = logging.getLogger(__name__)


class DoctolibClient:
    """Client HTTP pour interagir avec l'API interne de Doctolib Pro."""

    BROWSER_HEADERS = {
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36"
        ),
        "Accept-Language": "fr-FR,fr;q=0.9,en-US;q=0.8,en;q=0.7",
    }

    # Headers for page navigation (login, sessions)
    NAV_HEADERS = {
        "sec-fetch-dest": "document",
        "sec-fetch-mode": "navigate",
        "sec-fetch-site": "same-origin",
    }

    # Headers for AJAX/API calls (appointments, patients, etc.)
    API_HEADERS = {
        "Accept": "application/json",
        "Content-Type": "application/json",
        "X-Requested-With": "XMLHttpRequest",
        "sec-fetch-dest": "empty",
        "sec-fetch-mode": "cors",
        "sec-fetch-site": "same-origin",
    }

    def __init__(self, base_url: str, email: str, password: str):
        self.base_url = base_url.rstrip("/")
        self.email = email
        self.password = password
        self._authenticated = False
        self._requires_2fa = False
        self._account_data: dict[str, Any] = {}
        self._auth_token: Optional[str] = None
        self._tfa_response: Optional[dict] = None  # Store 2FA response for debug

        self.session = cloudscraper.create_scraper()
        self.session.headers.update(self.BROWSER_HEADERS)

    @property
    def is_authenticated(self) -> bool:
        return self._authenticated

    @property
    def requires_2fa(self) -> bool:
        return self._requires_2fa

    def _url(self, path: str) -> str:
        return f"{self.base_url}{path}"

    def _api_get(self, path: str, params: Optional[dict] = None) -> Any:
        """GET request with proper API/AJAX headers. Returns response object."""
        headers = {**self.API_HEADERS}
        if self._auth_token:
            headers["Authorization"] = f"Bearer {self._auth_token}"
        return self.session.get(self._url(path), params=params, headers=headers)

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
        logger.info(f"Login response keys: {list(data.keys())}")

        # Extract auth token if present
        self._extract_token(data)

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

    def _extract_token(self, data: dict) -> None:
        """Extract auth/refresh token from response data."""
        for key in ("refresh_token", "token", "access_token", "auth_token"):
            val = data.get(key)
            if val and isinstance(val, str):
                self._auth_token = val
                logger.info(f"Auth token extracted from '{key}' ({len(val)} chars)")
                return

    def submit_2fa_code(self, code: str) -> dict[str, Any]:
        """Submit 2FA authentication code.

        IMPORTANT: Uses session default headers (no API_HEADERS) for 2FA POSTs.
        """
        # The redirection from login tells us the 2FA path: /signin/two-factor
        # Try multiple possible 2FA validation endpoints
        strategies = [
            # Based on the /signin/two-factor redirect path
            ("POST", "/signin/two-factor.json", {"auth_code": code}),
            ("POST", "/signin/two-factor", {"auth_code": code}),
            ("POST", "/api/signin/two-factor", {"auth_code": code}),
            # Old endpoints (might work on some Doctolib versions)
            ("POST", "/api/accounts/two_factor_authentication", {"auth_code": code}),
            ("PUT", "/api/accounts/two_factor_authentication", {"auth_code": code}),
            # With email method specified
            ("POST", "/signin/two-factor.json", {
                "auth_code": code,
                "two_factor_auth_method": "email",
            }),
        ]

        all_attempts = []
        for method, endpoint, payload in strategies:
            try:
                if method == "PUT":
                    resp = self.session.put(self._url(endpoint), json=payload)
                else:
                    resp = self.session.post(self._url(endpoint), json=payload)
                logger.info(f"2FA {method} [{endpoint}]: HTTP {resp.status_code}")

                resp_data = None
                resp_text = resp.text[:300] if resp.text else ""
                try:
                    resp_data = resp.json()
                except ValueError:
                    pass

                all_attempts.append({
                    "method": method,
                    "endpoint": endpoint,
                    "status": resp.status_code,
                    "data": resp_data,
                    "body_preview": resp_text if resp_data is None else None,
                })

                if resp.status_code < 400:
                    # Check if still redirecting to 2FA (= not really authenticated)
                    if isinstance(resp_data, dict):
                        redir = resp_data.get("redirect") or resp_data.get("redirection")
                        if redir and "two-factor" in str(redir):
                            logger.info(f"2FA [{endpoint}]: still needs 2FA (redirection={redir})")
                            continue
                        self._extract_token(resp_data)
                        if any(k in resp_data for k in ("doctor", "agendas", "id")):
                            self._account_data = resp_data

                    self._authenticated = True
                    self._requires_2fa = False
                    self._tfa_response = {"attempts": all_attempts}
                    return {
                        "success": True,
                        "requires_2fa": False,
                        "message": f"2FA réussie via {method} {endpoint}.",
                        "debug": all_attempts,
                    }
            except Exception as e:
                all_attempts.append({"endpoint": endpoint, "error": str(e)})
                logger.warning(f"2FA [{endpoint}] failed: {e}")
                continue

        self._tfa_response = {"attempts": all_attempts}
        return {
            "success": False,
            "requires_2fa": True,
            "message": "Code 2FA invalide.",
            "debug": all_attempts,
        }

    def logout(self) -> None:
        """Reset session."""
        self._authenticated = False
        self._requires_2fa = False
        self._account_data = {}
        self._auth_token = None
        self._tfa_response = None
        self.session = cloudscraper.create_scraper()
        self.session.headers.update(self.BROWSER_HEADERS)

    def _get_agenda_ids(self) -> str:
        """Extract agenda IDs from account data, searching multiple structures."""
        agendas = []

        # Try "doctor.agendas" (login response structure)
        doctor = self._account_data.get("doctor", {})
        for agenda in doctor.get("agendas", []):
            aid = agenda.get("id")
            if aid:
                agendas.append(str(aid))

        # Try top-level "agendas"
        if not agendas:
            for agenda in self._account_data.get("agendas", []):
                aid = agenda.get("id")
                if aid:
                    agendas.append(str(aid))

        result = "-".join(agendas)
        logger.info(f"Agenda IDs: '{result}' (account keys: {list(self._account_data.keys())[:10]})")
        return result

    # --- Debug ---

    def debug_api_test(self) -> dict[str, Any]:
        """Test /api/appointments.json with multiple auth approaches."""
        url = self._url("/api/appointments.json")
        params = {"start_date": "2026-02-14", "end_date": "2026-02-15"}

        # Show account data values (redact long/sensitive values)
        account_summary = {}
        for k, v in self._account_data.items():
            if v is None:
                account_summary[k] = None
            elif isinstance(v, str):
                if len(v) > 50:
                    account_summary[k] = f"str({len(v)} chars): {v[:30]}..."
                elif k in ("password",):
                    account_summary[k] = "***"
                else:
                    account_summary[k] = v
            elif isinstance(v, (int, float, bool)):
                account_summary[k] = v
            elif isinstance(v, list):
                account_summary[k] = f"list({len(v)} items)"
            elif isinstance(v, dict):
                account_summary[k] = f"dict({list(v.keys())[:5]})"
            else:
                account_summary[k] = str(type(v))

        results = {
            "auth_token": f"{self._auth_token[:20]}..." if self._auth_token else None,
            "account_data": account_summary,
            "tfa_response": self._tfa_response,
            "tests": [],
        }

        # Test 1: Session cookies only (no special headers)
        try:
            resp = self.session.get(url, params=params)
            results["tests"].append({
                "name": "cookies_only",
                "status": resp.status_code,
                "body": resp.text[:300],
            })
        except Exception as e:
            results["tests"].append({"name": "cookies_only", "error": str(e)})

        # Test 2: With AJAX headers
        try:
            resp = self.session.get(url, params=params, headers=self.API_HEADERS)
            results["tests"].append({
                "name": "ajax_headers",
                "status": resp.status_code,
                "body": resp.text[:300],
            })
        except Exception as e:
            results["tests"].append({"name": "ajax_headers", "error": str(e)})

        # Test 3: With Bearer token
        if self._auth_token:
            try:
                headers = {
                    **self.API_HEADERS,
                    "Authorization": f"Bearer {self._auth_token}",
                }
                resp = self.session.get(url, params=params, headers=headers)
                results["tests"].append({
                    "name": "bearer_token",
                    "status": resp.status_code,
                    "body": resp.text[:300],
                })
            except Exception as e:
                results["tests"].append({"name": "bearer_token", "error": str(e)})

        # Test 4: Try www.doctolib.fr instead of pro.doctolib.fr
        www_url = url.replace("pro.doctolib.fr", "www.doctolib.fr")
        try:
            resp = self.session.get(www_url, params=params, headers=self.API_HEADERS)
            results["tests"].append({
                "name": "www_domain",
                "url": www_url,
                "status": resp.status_code,
                "body": resp.text[:300],
            })
        except Exception as e:
            results["tests"].append({"name": "www_domain", "error": str(e)})

        # Test 5: Try /api/appointments on www with Bearer
        if self._auth_token:
            try:
                headers = {
                    **self.API_HEADERS,
                    "Authorization": f"Bearer {self._auth_token}",
                }
                resp = self.session.get(www_url, params=params, headers=headers)
                results["tests"].append({
                    "name": "www_bearer",
                    "url": www_url,
                    "status": resp.status_code,
                    "body": resp.text[:300],
                })
            except Exception as e:
                results["tests"].append({"name": "www_bearer", "error": str(e)})

        # Show cookies per domain
        results["cookies"] = {}
        for cookie in self.session.cookies:
            domain = cookie.domain
            if domain not in results["cookies"]:
                results["cookies"][domain] = []
            results["cookies"][domain].append(cookie.name)

        return results

    # --- Appointments ---

    def get_appointments(
        self,
        start_date: Optional[str] = None,
        end_date: Optional[str] = None,
    ) -> Any:
        """Fetch appointments list."""
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

        if agenda_ids:
            for aid in agenda_ids.split("-"):
                endpoints.append((f"/api/agendas/{aid}/events.json", base_params))

        errors = []
        for path, params in endpoints:
            try:
                resp = self._api_get(path, params=params)
                status = resp.status_code
                body_preview = resp.text[:200] if resp.text else "(empty)"
                logger.info(f"Appointments {path}: HTTP {status} | Body: {body_preview}")
                if status < 400:
                    ct = resp.headers.get("content-type", "")
                    if "html" in ct and "json" not in ct:
                        errors.append(f"{path}: HTTP {status} but HTML")
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
                continue

        raise RuntimeError(
            f"Aucun endpoint n'a fonctionné. "
            f"Agenda IDs: '{agenda_ids}'. Détails: {'; '.join(errors)}"
        )

    def get_appointment(self, appointment_id: int) -> dict[str, Any]:
        """Fetch details of a specific appointment."""
        for path in [
            f"/api/appointments/{appointment_id}.json",
            f"/api/events/{appointment_id}.json",
            f"/appointments/{appointment_id}.json",
        ]:
            try:
                resp = self._api_get(path)
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
                resp = self._api_get(path)
                logger.info(f"Patients {path}: HTTP {resp.status_code}")
                if resp.status_code < 400:
                    ct = resp.headers.get("content-type", "")
                    if "html" in ct and "json" not in ct:
                        errors.append(f"{path}: HTTP {resp.status_code} but HTML")
                        continue
                    return resp.json()
                else:
                    errors.append(f"{path}: HTTP {resp.status_code}")
            except Exception as e:
                errors.append(f"{path}: {e}")
                continue
        raise RuntimeError(f"Aucun endpoint patients. Détails: {'; '.join(errors)}")

    # --- Availabilities ---

    def get_availabilities(
        self,
        agenda_ids: str,
        visit_motive_ids: str,
        practice_ids: str,
        start_date: Optional[str] = None,
        limit: int = 3,
    ) -> dict[str, Any]:
        """Fetch available slots."""
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

        resp = self._api_get("/availabilities.json", params=params)
        resp.raise_for_status()
        return resp.json()

    # --- Account ---

    def get_account_info(self) -> dict[str, Any]:
        """Return stored account data from login response."""
        return self._account_data
