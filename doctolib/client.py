import json
import logging
import re
import time
from datetime import date, datetime
from typing import Any, Optional

from curl_cffi.requests import Session as CurlSession

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

    def __init__(self, base_url: str, email: str, password: str):
        self.base_url = base_url.rstrip("/")
        self.email = email
        self.password = password
        self._authenticated = False
        self._requires_2fa = False
        self._account_data: dict[str, Any] = {}
        self._auth_token: Optional[str] = None
        self._csrf_token: Optional[str] = None
        self._admin_base_url: Optional[str] = None
        self._session_debug: dict[str, Any] = {}

        self.session = CurlSession(impersonate="chrome")
        self.session.headers.update(self.BROWSER_HEADERS)

    @property
    def is_authenticated(self) -> bool:
        return self._authenticated

    @property
    def requires_2fa(self) -> bool:
        return self._requires_2fa

    def _url(self, path: str, domain: Optional[str] = None) -> str:
        base = domain or self.base_url
        return f"{base}{path}"

    def _api_get(
        self,
        path: str,
        params: Optional[dict] = None,
        domain: Optional[str] = None,
    ) -> Any:
        """Simple GET with Accept: application/json + Referer + CSRF."""
        url = self._url(path, domain=domain)
        headers = {
            "Accept": "application/json",
            "Referer": f"{domain or self.base_url}/",
        }
        if self._csrf_token:
            headers["X-CSRF-Token"] = self._csrf_token
        return self.session.get(url, params=params, headers=headers)

    def _api_get_ajax(
        self,
        path: str,
        params: Optional[dict] = None,
        domain: Optional[str] = None,
    ) -> Any:
        """AJAX-style GET with XMLHttpRequest header."""
        url = self._url(path, domain=domain)
        headers = {
            "Accept": "application/json",
            "X-Requested-With": "XMLHttpRequest",
            "Referer": f"{domain or self.base_url}/",
            "sec-fetch-dest": "empty",
            "sec-fetch-mode": "cors",
            "sec-fetch-site": "same-origin",
        }
        if self._csrf_token:
            headers["X-CSRF-Token"] = self._csrf_token
        return self.session.get(url, params=params, headers=headers)

    # --- Authentication ---

    def login(self) -> dict[str, Any]:
        """
        Authenticate with Doctolib Pro.

        Returns a dict with keys: success, requires_2fa, message
        """
        # Step 1: Initialize session (get cookies, CSRF token)
        try:
            resp = self.session.get(self._url("/sessions/new"))
            if resp.status_code == 200:
                self._extract_csrf_token(resp.text)
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
        self._extract_token(data)

        # Step 3: Check if 2FA is required
        redirect = data.get("redirect") or data.get("redirection")
        if redirect and "two-factor" in str(redirect):
            self._requires_2fa = True
            try:
                send_headers = {
                    "Accept": "application/json",
                    "Content-Type": "application/json",
                    "X-Requested-With": "XMLHttpRequest",
                    "Referer": f"{self.base_url}/sessions/new",
                }
                if self._csrf_token:
                    send_headers["X-CSRF-Token"] = self._csrf_token
                self.session.post(
                    self._url("/api/accounts/send_auth_code"),
                    json={"two_factor_auth_method": "email"},
                    headers=send_headers,
                )
            except Exception:
                pass
            return {
                "success": False,
                "requires_2fa": True,
                "message": "Code 2FA envoyé par email. Soumettez-le via POST /auth/2fa.",
            }

        # No 2FA needed - login complete
        self._authenticated = True
        session_debug = self._complete_session()
        return {
            "success": True,
            "requires_2fa": False,
            "message": "Connecté avec succès à Doctolib Pro.",
            "debug": {"session_setup": session_debug},
        }

    def resend_2fa_code(self) -> dict[str, Any]:
        """Resend the 2FA code via email."""
        try:
            headers = {
                "Accept": "application/json",
                "Content-Type": "application/json",
                "X-Requested-With": "XMLHttpRequest",
                "Referer": f"{self.base_url}/sessions/new",
            }
            if self._csrf_token:
                headers["X-CSRF-Token"] = self._csrf_token

            resp = self.session.post(
                self._url("/api/accounts/send_auth_code"),
                json={"two_factor_auth_method": "email"},
                headers=headers,
            )
            return {
                "message": "Code 2FA renvoyé par email.",
                "status": resp.status_code,
                "response": resp.text[:200] if resp.text else "",
            }
        except Exception as e:
            return {"message": f"Erreur: {e}", "status": 500}

    def _extract_token(self, data: dict) -> None:
        """Extract auth/refresh token from response data."""
        for key in ("refresh_token", "token", "access_token", "auth_token"):
            val = data.get(key)
            if val and isinstance(val, str):
                self._auth_token = val
                logger.info(f"Auth token extracted from '{key}' ({len(val)} chars)")
                return

    def _extract_csrf_token(self, html: str) -> None:
        """Extract CSRF token from HTML meta tag (Rails convention)."""
        match = re.search(r'name="csrf-token"\s+content="([^"]+)"', html)
        if not match:
            match = re.search(r'content="([^"]+)"\s+name="csrf-token"', html)
        if match:
            self._csrf_token = match.group(1)
            logger.info(f"CSRF token extracted ({len(self._csrf_token)} chars)")

    def _summarize_dict(self, d: dict, max_depth: int = 2) -> dict[str, Any]:
        """Create a summary of a dict showing types and sizes."""
        summary = {}
        for k, v in list(d.items())[:30]:
            if v is None:
                summary[k] = None
            elif isinstance(v, str):
                summary[k] = f"str({len(v)})" if len(v) > 50 else v
            elif isinstance(v, bool):
                summary[k] = v
            elif isinstance(v, (int, float)):
                summary[k] = v
            elif isinstance(v, list):
                summary[k] = f"list({len(v)})"
                if v and max_depth > 0 and isinstance(v[0], dict):
                    summary[k + "[0]_keys"] = list(v[0].keys())[:10]
            elif isinstance(v, dict):
                summary[k] = f"dict({len(v)} keys)"
                if max_depth > 0:
                    summary[k + "_keys"] = list(v.keys())[:10]
        return summary

    def _process_embedded_data(self, embedded: dict, debug: dict) -> None:
        """Process embedded data from HTML to extract account info."""
        # Check all embedded data sources
        all_keys = [
            "initial_state", "window_data", "current_user",
            "data_props", "data_props_sq", "react_props",
        ]
        for key in all_keys:
            if key not in embedded:
                continue
            ed = embedded[key]
            if not isinstance(ed, dict):
                continue

            # Direct account data (has doctor/agendas at top level)
            if "doctor" in ed or "agendas" in ed:
                self._account_data = ed
                debug["account_from"] = f"embedded.{key}"
                return

            # Nested structures: check common wrapper patterns
            # e.g., data_props might have {currentUser: {doctor: ...}}
            for nested_key in ("currentUser", "current_user", "user", "account",
                               "data", "props", "state", "session"):
                nested = ed.get(nested_key)
                if isinstance(nested, dict):
                    if "doctor" in nested or "agendas" in nested:
                        self._account_data = nested
                        debug["account_from"] = f"embedded.{key}.{nested_key}"
                        return

            # If data_props has any useful structure, store it as account data
            # even without doctor/agendas keys (we'll need to explore the structure)
            if key == "data_props" and len(ed) > 0:
                self._account_data = ed
                debug["account_from"] = f"embedded.{key} (full)"

    def _extract_embedded_data(self, html: str) -> dict[str, Any]:
        """Extract embedded JSON data from HTML page (Rails/React/SPA apps)."""
        data = {}

        # Common patterns for embedded data
        patterns = [
            (r"window\.__INITIAL_STATE__\s*=\s*({.+?})\s*;", "initial_state"),
            (r"window\.__DATA__\s*=\s*({.+?})\s*;", "window_data"),
            (r"window\.currentUser\s*=\s*({.+?})\s*;", "current_user"),
            (r'data-props="([^"]+)"', "data_props"),
            (r"data-props='([^']+)'", "data_props_sq"),
            (r'data-react-props="([^"]+)"', "react_props"),
        ]

        for pattern, key in patterns:
            match = re.search(pattern, html, re.DOTALL)
            if match:
                raw = match.group(1)
                # Unescape HTML entities
                raw = (
                    raw.replace("&quot;", '"')
                    .replace("&amp;", "&")
                    .replace("&#39;", "'")
                    .replace("&lt;", "<")
                    .replace("&gt;", ">")
                )
                try:
                    parsed = json.loads(raw)
                    data[key] = parsed
                except (json.JSONDecodeError, ValueError):
                    data[key + "_raw"] = raw[:200]

        return data

    def submit_2fa_code(self, code: str) -> dict[str, Any]:
        """Submit 2FA authentication code.

        Flow:
        1. PUT /api/accounts/two_factor_authentication with existing session + CSRF
        2. Re-POST /login.json to complete authentication
        """
        all_attempts = []

        # Step 1: Validate 2FA code via PUT (use existing session, no page visit)
        endpoint = "/api/accounts/two_factor_authentication"
        tfa_validated = False
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "X-Requested-With": "XMLHttpRequest",
            "Referer": f"{self.base_url}/sessions/new",
            "sec-fetch-dest": "empty",
            "sec-fetch-mode": "cors",
            "sec-fetch-site": "same-origin",
        }
        if self._csrf_token:
            headers["X-CSRF-Token"] = self._csrf_token

        for method in ("PUT", "POST"):
            payload = {"auth_code": code}
            try:
                if method == "PUT":
                    resp = self.session.put(
                        self._url(endpoint), json=payload,
                        headers=headers, allow_redirects=False,
                    )
                else:
                    resp = self.session.post(
                        self._url(endpoint), json=payload,
                        headers=headers, allow_redirects=False,
                    )
                logger.info(f"2FA {method} [{endpoint}]: HTTP {resp.status_code}")

                resp_data = None
                try:
                    resp_data = resp.json()
                except ValueError:
                    pass

                attempt_info = {
                    "method": method,
                    "endpoint": endpoint,
                    "status": resp.status_code,
                    "data": resp_data,
                    "body_preview": resp.text[:300] if resp_data is None and resp.text else None,
                    "location": resp.headers.get("Location"),
                    "set_cookie_headers": [
                        v for k, v in resp.headers.items() if k.lower() == "set-cookie"
                    ][:5],
                }
                all_attempts.append(attempt_info)

                # 2xx = code validated (302 to signin = NOT validated)
                if resp.status_code in (200, 204):
                    tfa_validated = True

                    if isinstance(resp_data, dict):
                        redir = resp_data.get("redirect") or resp_data.get("redirection")
                        if redir and "two-factor" in str(redir):
                            tfa_validated = False
                            continue
                        self._extract_token(resp_data)
                        if any(k in resp_data for k in ("doctor", "agendas", "id")):
                            self._account_data = resp_data
                    break

                # 302 to signin = session lost, try next method
                if resp.status_code == 302:
                    location = resp.headers.get("Location", "")
                    if "signin" in location:
                        logger.warning(f"2FA {method}: redirected to signin, session lost")
                        continue

            except Exception as e:
                all_attempts.append({"method": method, "endpoint": endpoint, "error": str(e)})
                logger.warning(f"2FA {method} [{endpoint}] failed: {e}")
                continue

        if not tfa_validated:
            return {
                "success": False,
                "requires_2fa": True,
                "message": "Code 2FA invalide ou session expirée. Essayez POST /auth/login pour recommencer.",
                "debug": all_attempts,
            }

        # Step 3: Re-login now that 2FA is validated
        relogin_info = {}
        login_payload = {
            "kind": "doctor",
            "username": self.email,
            "password": self.password,
            "remember": True,
            "remember_username": True,
        }
        try:
            resp = self.session.post(self._url("/login.json"), json=login_payload)
            relogin_info = {
                "status": resp.status_code,
                "body_preview": resp.text[:500] if resp.text else "",
            }
            try:
                data = resp.json()
                relogin_info["data_keys"] = list(data.keys())[:20]

                redir = data.get("redirect") or data.get("redirection")
                if redir and "two-factor" in str(redir):
                    relogin_info["still_needs_2fa"] = True
                else:
                    relogin_info["still_needs_2fa"] = False
                    self._account_data = data
                    self._extract_token(data)
                    self._authenticated = True
                    self._requires_2fa = False
            except ValueError:
                relogin_info["json_parse_error"] = True
        except Exception as e:
            relogin_info["error"] = str(e)

        all_attempts.append({"step": "re-login", **relogin_info})

        if self._authenticated:
            session_debug = self._complete_session()
            return {
                "success": True,
                "requires_2fa": False,
                "message": "2FA validée et session authentifiée.",
                "debug": {
                    "attempts": all_attempts,
                    "session_setup": session_debug,
                },
            }

        return {
            "success": False,
            "requires_2fa": True,
            "message": "2FA validée mais session non authentifiée. Re-login échoué.",
            "debug": all_attempts,
        }

    def _complete_session(self) -> dict[str, Any]:
        """Complete session setup after authentication.

        After login/2FA, navigates to the dashboard to:
        1. Get additional session cookies
        2. Extract embedded data (account info, agendas)
        3. Get CSRF token
        4. Test if admin.doctolib.fr is accessible
        5. Navigate to more pages for data extraction
        """
        debug: dict[str, Any] = {"steps": []}

        # Step 1: Visit dashboard page to complete session
        try:
            resp = self.session.get(self._url("/"))
            ct = resp.headers.get("content-type", "")
            debug["steps"].append({
                "action": "GET /",
                "status": resp.status_code,
                "content_type": ct,
            })

            if resp.status_code == 200 and "text/html" in ct:
                self._extract_csrf_token(resp.text)
                embedded = self._extract_embedded_data(resp.text)
                if embedded:
                    debug["embedded_keys"] = list(embedded.keys())
                    # Show data_props content summary
                    for key, value in embedded.items():
                        if isinstance(value, dict):
                            debug[f"embedded_{key}_keys"] = list(value.keys())[:30]
                            debug[f"embedded_{key}_summary"] = self._summarize_dict(value)
                        elif isinstance(value, str):
                            debug[f"embedded_{key}_raw"] = value[:500]

                    # Try to extract account data from any embedded source
                    self._process_embedded_data(embedded, debug)
        except Exception as e:
            debug["steps"].append({"action": "GET /", "error": str(e)})

        # Step 2: Explore more HTML pages for embedded data
        html_pages = ["/calendar", "/agenda", "/settings", "/account"]
        for page_path in html_pages:
            try:
                resp = self.session.get(self._url(page_path))
                ct = resp.headers.get("content-type", "")
                step_info: dict[str, Any] = {
                    "action": f"GET {page_path}",
                    "status": resp.status_code,
                    "content_type": ct,
                }
                if resp.status_code == 200 and "text/html" in ct:
                    embedded = self._extract_embedded_data(resp.text)
                    if embedded:
                        step_info["embedded_keys"] = list(embedded.keys())
                        for key, value in embedded.items():
                            if isinstance(value, dict):
                                step_info[f"{key}_keys"] = list(value.keys())[:20]
                debug["steps"].append(step_info)
            except Exception as e:
                debug["steps"].append({"action": f"GET {page_path}", "error": str(e)})

        # Step 3: Try JSON endpoints for account data
        for path in ["/account.json", "/api/account.json", "/api/accounts.json"]:
            try:
                resp = self._api_get(path)
                body_preview = resp.text[:200] if resp.text else ""
                debug["steps"].append({
                    "action": f"GET {path}",
                    "status": resp.status_code,
                    "body_preview": body_preview,
                })
                if resp.status_code == 200:
                    try:
                        data = resp.json()
                        if isinstance(data, dict) and data:
                            self._account_data = data
                            debug["account_from"] = path
                            break
                    except ValueError:
                        pass
            except Exception as e:
                debug["steps"].append({"action": f"GET {path}", "error": str(e)})

        # Step 4: Test admin.doctolib.fr accessibility
        self._admin_base_url = None
        try:
            resp = self.session.get("https://admin.doctolib.fr/")
            ct = resp.headers.get("content-type", "")
            is_cloudflare = False
            if "text/html" in ct and resp.text:
                lower_text = resp.text[:2000].lower()
                is_cloudflare = any(
                    kw in lower_text
                    for kw in ("cloudflare", "cf-access", "access denied", "sign in")
                )

            debug["steps"].append({
                "action": "GET admin.doctolib.fr/",
                "status": resp.status_code,
                "content_type": ct,
                "cloudflare_blocked": is_cloudflare,
                "body_preview": resp.text[:400] if resp.text else "",
            })

            if resp.status_code == 200 and not is_cloudflare:
                self._admin_base_url = "https://admin.doctolib.fr"
                debug["admin_accessible"] = True

                # Try an API endpoint on admin
                try:
                    resp2 = self._api_get(
                        "/api/appointments.json",
                        params={"start_date": "2026-02-14", "end_date": "2026-02-15"},
                        domain="https://admin.doctolib.fr",
                    )
                    debug["steps"].append({
                        "action": "GET admin /api/appointments.json",
                        "status": resp2.status_code,
                        "body_preview": resp2.text[:300] if resp2.text else "",
                    })
                except Exception as e:
                    debug["steps"].append({
                        "action": "GET admin /api/appointments.json",
                        "error": str(e),
                    })
            else:
                debug["admin_accessible"] = False
        except Exception as e:
            debug["steps"].append({
                "action": "GET admin.doctolib.fr/",
                "error": str(e),
            })
            debug["admin_accessible"] = False

        # Step 5: Record session state
        debug["cookies"] = {}
        for cookie in self.session.cookies.jar:
            domain = cookie.domain
            if domain not in debug["cookies"]:
                debug["cookies"][domain] = []
            debug["cookies"][domain].append({
                "name": cookie.name,
                "path": cookie.path,
                "secure": cookie.secure,
            })

        debug["csrf_token"] = f"{self._csrf_token[:20]}..." if self._csrf_token else None
        debug["auth_token"] = bool(self._auth_token)
        debug["account_keys"] = (
            list(self._account_data.keys())[:15] if self._account_data else []
        )

        self._session_debug = debug
        return debug

    def logout(self) -> None:
        """Reset session."""
        self._authenticated = False
        self._requires_2fa = False
        self._account_data = {}
        self._auth_token = None
        self._csrf_token = None
        self._admin_base_url = None
        self._session_debug = {}
        self.session = CurlSession(impersonate="chrome")
        self.session.headers.update(self.BROWSER_HEADERS)

    def _get_agenda_ids(self) -> str:
        """Extract agenda IDs from account data, searching multiple structures."""
        agendas = []

        doctor = self._account_data.get("doctor", {})
        if isinstance(doctor, dict):
            for agenda in doctor.get("agendas", []):
                aid = agenda.get("id")
                if aid:
                    agendas.append(str(aid))

        if not agendas:
            for agenda in self._account_data.get("agendas", []):
                aid = agenda.get("id")
                if aid:
                    agendas.append(str(aid))

        result = "-".join(agendas)
        logger.info(
            f"Agenda IDs: '{result}' (account keys: {list(self._account_data.keys())[:10]})"
        )
        return result

    # --- Debug ---

    def debug_api_test(self) -> dict[str, Any]:
        """Comprehensive API test with multiple auth approaches and domains."""
        params = {"start_date": "2026-02-14", "end_date": "2026-02-15"}

        results: dict[str, Any] = {
            "csrf_token": f"{self._csrf_token[:20]}..." if self._csrf_token else None,
            "auth_token": f"{self._auth_token[:20]}..." if self._auth_token else None,
            "admin_base_url": self._admin_base_url,
            "account_keys": list(self._account_data.keys())[:15],
            "agenda_ids": self._get_agenda_ids(),
            "session_setup": self._session_debug,
            "tests": [],
        }

        # Build test configurations: (name, path, domain, method)
        test_configs = [
            # Pro.doctolib.fr - simple headers (Accept + Referer)
            ("pro_simple", "/api/appointments.json", None, "simple"),
            # Pro.doctolib.fr - AJAX headers (+ X-Requested-With)
            ("pro_ajax", "/api/appointments.json", None, "ajax"),
            # Pro.doctolib.fr - cookies only (no custom headers)
            ("pro_cookies_only", "/api/appointments.json", None, "cookies"),
            # Different endpoint paths on pro
            ("pro_events", "/api/events.json", None, "simple"),
            ("pro_calendar", "/calendar.json", None, "simple"),
            # HTML page scraping
            ("pro_html_appointments", "/appointments", None, "html"),
        ]

        # Admin.doctolib.fr tests (if accessible after 2FA)
        if self._admin_base_url:
            test_configs.extend([
                ("admin_simple", "/api/appointments.json", self._admin_base_url, "simple"),
                ("admin_ajax", "/api/appointments.json", self._admin_base_url, "ajax"),
                ("admin_events", "/api/events.json", self._admin_base_url, "simple"),
                ("admin_root", "/", self._admin_base_url, "html"),
            ])
        else:
            # Force-test admin even if not marked accessible
            test_configs.extend([
                ("admin_forced", "/api/appointments.json", "https://admin.doctolib.fr", "simple"),
                ("admin_forced_cookies", "/api/appointments.json", "https://admin.doctolib.fr", "cookies"),
            ])

        for name, path, domain, method in test_configs:
            try:
                if method == "simple":
                    resp = self._api_get(path, params=params, domain=domain)
                elif method == "ajax":
                    resp = self._api_get_ajax(path, params=params, domain=domain)
                elif method == "cookies":
                    url = self._url(path, domain=domain)
                    resp = self.session.get(url, params=params)
                elif method == "html":
                    url = self._url(path, domain=domain)
                    resp = self.session.get(url, params=params)

                ct = resp.headers.get("content-type", "")
                body = resp.text[:500] if resp.text else ""

                test_result: dict[str, Any] = {
                    "name": name,
                    "url": self._url(path, domain=domain),
                    "method": method,
                    "status": resp.status_code,
                    "content_type": ct,
                    "body": body,
                }

                # If HTML, check for embedded data
                if "text/html" in ct and resp.status_code == 200:
                    embedded = self._extract_embedded_data(resp.text)
                    if embedded:
                        test_result["embedded_keys"] = list(embedded.keys())

                results["tests"].append(test_result)
            except Exception as e:
                results["tests"].append({"name": name, "error": str(e)})

        # Show all cookies with domain details
        results["cookies"] = {}
        for cookie in self.session.cookies.jar:
            domain = cookie.domain
            if domain not in results["cookies"]:
                results["cookies"][domain] = []
            results["cookies"][domain].append({
                "name": cookie.name,
                "path": cookie.path,
                "secure": cookie.secure,
                "domain_specified": cookie.domain_specified,
                "domain_initial_dot": cookie.domain_initial_dot,
            })

        return results

    def debug_dashboard(self) -> dict[str, Any]:
        """Load dashboard and return full embedded data for inspection."""
        result: dict[str, Any] = {"pages": {}}

        # Load multiple pages and extract all embedded data
        pages = ["/", "/calendar", "/agenda", "/settings"]
        for page_path in pages:
            page_info: dict[str, Any] = {}
            try:
                resp = self.session.get(self._url(page_path))
                page_info["status"] = resp.status_code
                page_info["content_type"] = resp.headers.get("content-type", "")

                if resp.status_code == 200 and "text/html" in page_info["content_type"]:
                    page_info["html_size"] = len(resp.text)

                    # Extract embedded data
                    embedded = self._extract_embedded_data(resp.text)
                    if embedded:
                        page_info["embedded"] = {}
                        for key, value in embedded.items():
                            if isinstance(value, dict):
                                # Show full structure (truncate large values)
                                page_info["embedded"][key] = self._deep_summarize(value)
                            elif isinstance(value, str):
                                page_info["embedded"][key + "_raw"] = value[:1000]
                            else:
                                page_info["embedded"][key] = value

                    # Also look for all data- attributes with JSON
                    data_attrs = re.findall(
                        r'data-([a-z-]+)="([^"]{20,})"', resp.text
                    )
                    if data_attrs:
                        page_info["data_attributes"] = {}
                        for attr_name, attr_value in data_attrs[:10]:
                            decoded = (
                                attr_value.replace("&quot;", '"')
                                .replace("&amp;", "&")
                                .replace("&#39;", "'")
                            )
                            try:
                                parsed = json.loads(decoded)
                                if isinstance(parsed, dict):
                                    page_info["data_attributes"][attr_name] = (
                                        self._deep_summarize(parsed)
                                    )
                                else:
                                    page_info["data_attributes"][attr_name] = parsed
                            except (json.JSONDecodeError, ValueError):
                                page_info["data_attributes"][attr_name] = decoded[:200]

                    # Look for script tags with JSON assignments
                    script_data = re.findall(
                        r'<script[^>]*>\s*(?:var|const|let|window\.)\s*(\w+)\s*=\s*({.+?})\s*;?\s*</script>',
                        resp.text,
                        re.DOTALL,
                    )
                    if script_data:
                        page_info["script_vars"] = {}
                        for var_name, var_value in script_data[:5]:
                            try:
                                parsed = json.loads(var_value)
                                page_info["script_vars"][var_name] = (
                                    self._deep_summarize(parsed)
                                    if isinstance(parsed, dict)
                                    else parsed
                                )
                            except (json.JSONDecodeError, ValueError):
                                page_info["script_vars"][var_name] = var_value[:200]
                else:
                    page_info["body_preview"] = resp.text[:300] if resp.text else ""
            except Exception as e:
                page_info["error"] = str(e)

            result["pages"][page_path] = page_info

        return result

    def _deep_summarize(self, d: dict, max_depth: int = 3, current_depth: int = 0) -> Any:
        """Recursively summarize a dict, showing structure and small values."""
        if current_depth >= max_depth:
            return f"dict({len(d)} keys: {list(d.keys())[:5]})"

        summary = {}
        for k, v in list(d.items())[:30]:
            if v is None:
                summary[k] = None
            elif isinstance(v, bool):
                summary[k] = v
            elif isinstance(v, (int, float)):
                summary[k] = v
            elif isinstance(v, str):
                summary[k] = v if len(v) <= 100 else f"str({len(v)} chars): {v[:80]}..."
            elif isinstance(v, list):
                if not v:
                    summary[k] = []
                elif isinstance(v[0], dict):
                    summary[k] = f"list({len(v)} dicts)"
                    if len(v) > 0:
                        summary[k + "[0]"] = self._deep_summarize(
                            v[0], max_depth, current_depth + 1
                        )
                else:
                    summary[k] = v[:10] if len(v) <= 10 else f"list({len(v)}): {v[:5]}..."
            elif isinstance(v, dict):
                summary[k] = self._deep_summarize(v, max_depth, current_depth + 1)
        return summary

    # --- Appointments ---

    def get_appointments(
        self,
        start_date: Optional[str] = None,
        end_date: Optional[str] = None,
    ) -> Any:
        """Fetch appointments list, trying multiple endpoints and domains."""
        from datetime import timedelta

        if not start_date:
            start_date = date.today().isoformat()
        if not end_date:
            end_date = (date.today() + timedelta(days=30)).isoformat()

        agenda_ids = self._get_agenda_ids()
        base_params = {"start_date": start_date, "end_date": end_date}
        params_with_agendas = {
            **base_params,
            **({"agenda_ids": agenda_ids} if agenda_ids else {}),
        }

        # Build (path, params, domain, method) attempts
        attempts: list[tuple[str, dict, Optional[str], str]] = []

        # Pro.doctolib.fr with different headers
        for path in ["/api/appointments.json", "/api/events.json", "/events.json", "/appointments.json"]:
            attempts.append((path, params_with_agendas, None, "simple"))
            attempts.append((path, params_with_agendas, None, "ajax"))
            attempts.append((path, params_with_agendas, None, "cookies"))

        # Admin.doctolib.fr (if accessible)
        if self._admin_base_url:
            for path in ["/api/appointments.json", "/api/events.json", "/appointments.json"]:
                attempts.append((path, params_with_agendas, self._admin_base_url, "simple"))
                attempts.append((path, params_with_agendas, self._admin_base_url, "ajax"))

        # Per-agenda endpoints
        if agenda_ids:
            for aid in agenda_ids.split("-"):
                attempts.append(
                    (f"/api/agendas/{aid}/events.json", base_params, None, "simple")
                )

        # Different endpoint paths
        attempts.append(("/calendar.json", params_with_agendas, None, "simple"))

        # HTML page scraping as last resort
        attempts.append(("/appointments", base_params, None, "html"))

        errors = []
        for path, params, domain, method in attempts:
            try:
                domain_label = domain or self.base_url

                if method == "simple":
                    resp = self._api_get(path, params=params, domain=domain)
                elif method == "ajax":
                    resp = self._api_get_ajax(path, params=params, domain=domain)
                elif method == "cookies":
                    url = self._url(path, domain=domain)
                    resp = self.session.get(url, params=params)
                elif method == "html":
                    url = self._url(path, domain=domain)
                    resp = self.session.get(url, params=params)
                    if resp.status_code == 200 and "text/html" in resp.headers.get(
                        "content-type", ""
                    ):
                        embedded = self._extract_embedded_data(resp.text)
                        if embedded:
                            return {"source": "html_embedded", "data": embedded}
                    errors.append(f"{path}@{domain_label}: HTML scrape - no data")
                    continue

                status = resp.status_code
                if status < 400:
                    ct = resp.headers.get("content-type", "")
                    if "html" in ct and "json" not in ct:
                        errors.append(
                            f"{path}@{domain_label}[{method}]: HTTP {status} but HTML"
                        )
                        continue
                    try:
                        data = resp.json()
                        if isinstance(data, (list, dict)):
                            return data
                    except ValueError:
                        errors.append(
                            f"{path}@{domain_label}[{method}]: HTTP {status} invalid JSON"
                        )
                        continue
                else:
                    errors.append(f"{path}@{domain_label}[{method}]: HTTP {status}")
            except Exception as e:
                errors.append(f"{path}: {e}")
                continue

        raise RuntimeError(
            f"Aucun endpoint n'a fonctionné pour les rendez-vous. "
            f"Agenda IDs: '{agenda_ids}'. "
            f"Admin accessible: {bool(self._admin_base_url)}. "
            f"Détails: {'; '.join(errors[:10])}"
        )

    def get_appointment(self, appointment_id: int) -> dict[str, Any]:
        """Fetch details of a specific appointment."""
        domains = [None]
        if self._admin_base_url:
            domains.append(self._admin_base_url)

        for domain in domains:
            for path in [
                f"/api/appointments/{appointment_id}.json",
                f"/api/events/{appointment_id}.json",
                f"/appointments/{appointment_id}.json",
            ]:
                try:
                    resp = self._api_get(path, domain=domain)
                    if resp.status_code < 400:
                        ct = resp.headers.get("content-type", "")
                        if "json" in ct:
                            return resp.json()
                except Exception:
                    continue
        raise RuntimeError(f"Rendez-vous {appointment_id} non trouvé.")

    # --- Patients ---

    def get_patients(self) -> Any:
        """Fetch master patients list."""
        domains = [None]
        if self._admin_base_url:
            domains.append(self._admin_base_url)

        errors = []
        for domain in domains:
            for path in [
                "/api/patients.json",
                "/api/master_patients.json",
                "/account/master_patients.json",
            ]:
                try:
                    domain_label = domain or self.base_url
                    resp = self._api_get(path, domain=domain)
                    logger.info(
                        f"Patients {path}@{domain_label}: HTTP {resp.status_code}"
                    )
                    if resp.status_code < 400:
                        ct = resp.headers.get("content-type", "")
                        if "html" in ct and "json" not in ct:
                            errors.append(
                                f"{path}@{domain_label}: HTTP {resp.status_code} but HTML"
                            )
                            continue
                        return resp.json()
                    else:
                        errors.append(
                            f"{path}@{domain_label}: HTTP {resp.status_code}"
                        )
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

        domains = [None]
        if self._admin_base_url:
            domains.append(self._admin_base_url)

        for domain in domains:
            try:
                resp = self._api_get("/availabilities.json", params=params, domain=domain)
                if resp.status_code < 400:
                    return resp.json()
            except Exception:
                continue

        resp = self._api_get("/availabilities.json", params=params)
        resp.raise_for_status()
        return resp.json()

    # --- Account ---

    def get_account_info(self) -> dict[str, Any]:
        """Return stored account data from login response."""
        return self._account_data
