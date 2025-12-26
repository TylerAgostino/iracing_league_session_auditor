"""
iRacing API Handler for accessing the iRacing API.

This module provides classes and functions to interact with the iRacing API,
authenticate, retrieve session data, and validate sessions against expectations.
"""

import base64
import hashlib
import json
import secrets
import urllib.parse
import webbrowser
from datetime import datetime
from http.server import BaseHTTPRequestHandler, HTTPServer
from threading import Thread
from time import time
from typing import Any, Optional, cast

import requests

from ..exceptions import (
    UnauthorizedException,
)
from . import types

SessionDefinition = types.SessionDefinition
SessionTopLevelField = types.SessionTopLevelField

# pyright: reportUnknownVariableType=false
# pyright: reportUnknownMemberType=false
# pyright: reportUnknownArgumentType=false
# pyright: reportAny=false


def normalize_lists_in_dict(data: SessionDefinition) -> SessionDefinition:
    """
    Recursively normalize lists in dictionaries to ensure consistent hashing.

    This normalizes dictionary values that are lists by:
    1. For lists of dictionaries, sort them by a stable representation
    2. For lists of primitives, sort them directly
    3. For nested structures, recurse into them

    Args:
        data: dictionary to normalize

    Returns:
        Normalized dictionary
    """
    result = {}

    for key, value in data.items():
        if isinstance(value, dict):
            # Recurse into nested dictionaries
            result[key] = normalize_lists_in_dict(value)
        elif isinstance(value, list):
            normalized_list = []

            # Check if this is a list of dictionaries
            if value and all(isinstance(item, dict) for item in value):
                # For each dict in the list, normalize its contents first
                normalized_dicts = [
                    normalize_lists_in_dict(item)  # pyright: ignore[reportArgumentType]
                    for item in value
                ]

                # Sort the list of dicts based on a stable string representation
                normalized_list = sorted(
                    normalized_dicts, key=lambda x: json.dumps(x, sort_keys=True)
                )
            elif value and all(
                isinstance(item, (str, int, float, bool)) for item in value
            ):
                # For lists of primitives, just sort them directly
                try:
                    normalized_list = cast(
                        list[SessionDefinition],
                        sorted(value),  # pyright: ignore[reportArgumentType]
                    )
                except TypeError:
                    # If the items aren't directly comparable (e.g., mix of types)
                    # Convert to strings first for stable sorting
                    normalized_list = sorted(value, key=str)
            else:
                # For mixed lists or lists with complex nested structures,
                # normalize each item recursively
                normalized_items = []
                for item in value:
                    if isinstance(item, dict):
                        normalized_items.append(normalize_lists_in_dict(item))
                    elif isinstance(item, list):
                        normalized_items.append(normalize_list(item))
                    else:
                        normalized_items.append(item)

                # Try to sort the normalized items if possible
                try:
                    normalized_list = cast(
                        list[SessionDefinition],
                        sorted(
                            normalized_items,
                            key=lambda x: str(  # pyright: ignore[reportUnknownLambdaType]
                                x
                            ),
                        ),
                    )
                except TypeError:
                    normalized_list = normalized_items

            result[key] = normalized_list
        else:
            # For primitive values, keep as is
            result[key] = value

    return result


def normalize_list(lst: list[Any]) -> list[Any]:  # pyright: ignore[reportExplicitAny]
    """
    Normalize a list to ensure consistent ordering regardless of initial order.

    Args:
        lst: List to normalize

    Returns:
        Normalized list with consistent ordering
    """
    if not lst:
        return lst

    # For lists of primitives
    if all(isinstance(item, (str, int, float, bool)) for item in lst):
        try:
            return sorted(lst)
        except TypeError:
            # If the items aren't directly comparable (e.g., mix of types)
            return sorted(lst, key=str)

    # For lists of dictionaries
    if all(isinstance(item, dict) for item in lst):
        normalized_dicts = [normalize_lists_in_dict(item) for item in lst]
        return sorted(normalized_dicts, key=lambda x: json.dumps(x, sort_keys=True))

    # For mixed or nested lists
    normalized_items = []
    for item in lst:
        if isinstance(item, dict):
            normalized_items.append(normalize_lists_in_dict(item))
        elif isinstance(item, list):
            normalized_items.append(normalize_list(item))
        else:
            normalized_items.append(item)

    # Try to sort if possible, otherwise return as is
    try:
        return sorted(normalized_items, key=lambda x: str(x))
    except TypeError:
        return normalized_items


class iRacingAPIHandler(requests.Session):
    """
    Handler for interacting with the iRacing API.

    This class extends requests.Session to manage authentication and
    provide methods for retrieving and validating session data.

    Supports two OAuth 2.1 authentication flows:
    - Authorization Code Flow (for CLI with browser)
    - Password Limited Flow (for headless/Docker environments)
    """

    # OAuth endpoints
    OAUTH_AUTHORIZE_URL = "https://oauth.iracing.com/oauth2/authorize"
    OAUTH_TOKEN_URL = "https://oauth.iracing.com/oauth2/token"

    def __init__(
        self,
        email: Optional[str] = None,
        password: Optional[str] = None,
        client_id: str = "session-auditor",
        client_secret: Optional[str] = None,
        redirect_uri: str = "http://127.0.0.1:0/callback",
        use_password_flow: bool = False,
    ):
        """
        Initialize the API handler with OAuth 2.1 authentication.

        Args:
            email: iRacing account email (required for password flow, optional for auth code)
            password: iRacing account password (required for password flow)
            client_id: OAuth client ID (default: 'session-auditor')
            client_secret: OAuth client secret (required for password flow, optional for auth code)
            redirect_uri: OAuth redirect URI (default: http://127.0.0.1:0/callback)
            use_password_flow: If True, use Password Limited Flow; if False, use Authorization Code Flow
        """
        super().__init__()

        # Store credentials
        self.email = email
        self.password = password
        self.client_id = client_id
        self.client_secret = client_secret
        self.redirect_uri = redirect_uri
        self.use_password_flow = use_password_flow

        # Token management
        self.access_token: Optional[str] = None
        self.refresh_token: Optional[str] = None
        self.token_expires_at: float = 0
        self.refresh_token_expires_at: float = 0
        self.logged_in: bool = False

        # Perform initial authentication
        _ = self.login()

    def _mask_secret(self, secret: str, identifier: str) -> str:
        """
        Mask a secret (client_secret or password) using iRacing's masking algorithm.

        Args:
            secret: The secret to mask
            identifier: client_id for client_secret, username for password

        Returns:
            Base64 encoded SHA-256 hash of secret + normalized_identifier
        """
        # Normalize the identifier (trim and lowercase)
        normalized_id = identifier.strip().lower()

        # Concatenate secret with normalized identifier
        combined = f"{secret}{normalized_id}"

        # Hash with SHA-256 and encode with base64
        hasher = hashlib.sha256()
        hasher.update(combined.encode("utf-8"))

        return base64.b64encode(hasher.digest()).decode("utf-8")

    def _generate_pkce_pair(self) -> tuple[str, str]:
        """
        Generate PKCE code verifier and challenge.

        Returns:
            Tuple of (code_verifier, code_challenge)
        """
        # Generate random code verifier (43-128 characters)
        code_verifier = (
            base64.urlsafe_b64encode(secrets.token_bytes(32))
            .decode("utf-8")
            .rstrip("=")
        )

        # Create SHA-256 hash of verifier
        challenge_bytes = hashlib.sha256(code_verifier.encode("utf-8")).digest()
        code_challenge = (
            base64.urlsafe_b64encode(challenge_bytes).decode("utf-8").rstrip("=")
        )

        return code_verifier, code_challenge

    def _login_authorization_code_flow(self) -> bool:
        """
        Authenticate using Authorization Code Flow with PKCE.

        Returns:
            True if login is successful

        Raises:
            UnauthorizedException: If authentication fails
        """

        # Generate PKCE pair
        code_verifier, code_challenge = self._generate_pkce_pair()

        # Generate random state for CSRF protection
        state = secrets.token_urlsafe(32)

        # Build authorization URL
        auth_params = {
            "client_id": self.client_id,
            "redirect_uri": self.redirect_uri,
            "response_type": "code",
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
            "state": state,
            "scope": "iracing.auth",
            "audience": "data-server",
        }
        auth_url = f"{self.OAUTH_AUTHORIZE_URL}?{urllib.parse.urlencode(auth_params)}"

        # Set up callback server
        authorization_code = None
        received_state = None

        class CallbackHandler(BaseHTTPRequestHandler):
            def do_GET(self):
                nonlocal authorization_code, received_state

                # Parse query parameters
                query = urllib.parse.urlparse(self.path).query
                params = urllib.parse.parse_qs(query)

                if "code" in params:
                    authorization_code = params["code"][0]
                    received_state = params.get("state", [None])[0]

                    # Send success response
                    self.send_response(200)
                    self.send_header("Content-type", "text/html")
                    self.end_headers()
                    self.wfile.write(
                        b"<html><body><h1>Authentication successful!</h1><p>You can close this window.</p></body></html>"
                    )
                else:
                    # Send error response
                    self.send_response(400)
                    self.send_header("Content-type", "text/html")
                    self.end_headers()
                    error = params.get("error", ["unknown"])[0]
                    self.wfile.write(
                        f"<html><body><h1>Authentication failed</h1><p>Error: {error}</p></body></html>".encode()
                    )

            def log_message(self, format, *args):
                # Suppress log messages
                pass

        # Start local server on a random available port
        parsed_uri = urllib.parse.urlparse(self.redirect_uri)
        port = int(parsed_uri.port) if parsed_uri.port else 0
        server = HTTPServer(("127.0.0.1", port), CallbackHandler)
        server_thread = Thread(target=lambda: server.handle_request())
        server_thread.daemon = True
        server_thread.start()

        # Get the actual port that was bound (important when port=0)
        actual_port = server.server_port

        # Update redirect_uri with actual port if needed
        if port == 0:
            actual_redirect_uri = f"http://127.0.0.1:{actual_port}/callback"
            auth_params["redirect_uri"] = actual_redirect_uri
            auth_url = (
                f"{self.OAUTH_AUTHORIZE_URL}?{urllib.parse.urlencode(auth_params)}"
            )

        # Open browser for user authentication
        print(f"Opening browser for authentication at: {auth_url}")
        webbrowser.open(auth_url)

        # Wait for callback (timeout after 5 minutes)
        server_thread.join(timeout=300)
        server.server_close()

        if not authorization_code:
            raise UnauthorizedException("Failed to receive authorization code")

        if received_state != state:
            raise UnauthorizedException("State mismatch - possible CSRF attack")

        # Exchange authorization code for tokens
        # Use actual redirect URI if port was dynamically allocated
        exchange_redirect_uri = self.redirect_uri
        if port == 0:
            exchange_redirect_uri = f"http://127.0.0.1:{actual_port}/callback"

        token_data = {
            "grant_type": "authorization_code",
            "client_id": self.client_id,
            "code": authorization_code,
            "redirect_uri": exchange_redirect_uri,
            "code_verifier": code_verifier,
        }

        if self.client_secret:
            token_data["client_secret"] = self._mask_secret(
                self.client_secret, self.client_id
            )

        response = requests.post(
            self.OAUTH_TOKEN_URL,
            data=token_data,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )

        if response.status_code != 200:
            raise UnauthorizedException(
                f"Failed to exchange authorization code: {response.text}"
            )

        return self._process_token_response(response.json())

    def _login_password_limited_flow(self) -> bool:
        """
        Authenticate using Password Limited Flow.

        Returns:
            True if login is successful

        Raises:
            UnauthorizedException: If authentication fails
        """
        if not self.client_id or not self.client_secret:
            raise UnauthorizedException(
                "client_id and client_secret are required for Password Limited Flow"
            )

        if not self.email or not self.password:
            raise UnauthorizedException(
                "email and password are required for Password Limited Flow"
            )

        # Mask the client secret and password
        masked_secret = self._mask_secret(self.client_secret, self.client_id)
        masked_password = self._mask_secret(self.password, self.email)

        # Request tokens
        token_data = {
            "grant_type": "password_limited",
            "client_id": self.client_id,
            "client_secret": masked_secret,
            "username": self.email,
            "password": masked_password,
            "scope": "iracing.auth",
        }

        response = requests.post(
            self.OAUTH_TOKEN_URL,
            data=token_data,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )

        if response.status_code != 200:
            raise UnauthorizedException(
                f"Password Limited authentication failed: {response.text}"
            )

        return self._process_token_response(response.json())

    def _process_token_response(self, token_response: dict[str, Any]) -> bool:
        """
        Process token response and store tokens.

        Args:
            token_response: Response from token endpoint

        Returns:
            True if successful
        """
        self.access_token = token_response.get("access_token")
        self.refresh_token = token_response.get("refresh_token")

        # Calculate expiry times
        expires_in = token_response.get("expires_in", 600)
        self.token_expires_at = time() + expires_in

        refresh_expires_in = token_response.get("refresh_token_expires_in", 604800)
        self.refresh_token_expires_at = time() + refresh_expires_in

        self.logged_in = True
        return True

    def _refresh_access_token(self) -> bool:
        """
        Refresh the access token using the refresh token.

        Returns:
            True if refresh is successful

        Raises:
            UnauthorizedException: If refresh fails
        """
        if not self.refresh_token:
            raise UnauthorizedException("No refresh token available")

        if time() >= self.refresh_token_expires_at:
            raise UnauthorizedException("Refresh token has expired")

        token_data = {
            "grant_type": "refresh_token",
            "client_id": self.client_id,
            "refresh_token": self.refresh_token,
        }

        if self.client_secret and self.client_id:
            token_data["client_secret"] = self._mask_secret(
                self.client_secret, self.client_id
            )

        response = requests.post(
            self.OAUTH_TOKEN_URL,
            data=token_data,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )

        if response.status_code != 200:
            raise UnauthorizedException(f"Failed to refresh token: {response.text}")

        return self._process_token_response(response.json())

    def login(self) -> bool:
        """
        Log in to the iRacing API using the appropriate OAuth flow.

        Returns:
            True if login is successful

        Raises:
            UnauthorizedException: If authentication fails
        """
        if self.use_password_flow:
            return self._login_password_limited_flow()
        else:
            return self._login_authorization_code_flow()

    def request(
        self, method: str, url: str, *args: Any, **kwargs: Any
    ) -> requests.Response:
        """
        Override request method to add Bearer token authentication.

        Args:
            method: HTTP method
            url: URL to request
            *args: Additional arguments
            **kwargs: Additional keyword arguments

        Returns:
            Response object
        """
        # Check if token needs refresh (with 30 second buffer)
        if self.logged_in and time() >= (self.token_expires_at - 30):
            try:
                self._refresh_access_token()
            except UnauthorizedException:
                # If refresh fails, try to re-authenticate
                self.logged_in = False
                self.login()

        # Add Bearer token to headers only for iRacing API URLs
        # S3 presigned URLs (from "link" field) already have authentication in query params
        if self.access_token and (
            "members-ng.iracing.com" in url or "oauth.iracing.com" in url
        ):
            if "headers" not in kwargs:
                kwargs["headers"] = {}
            kwargs["headers"]["Authorization"] = f"Bearer {self.access_token}"

        return super().request(method, url, *args, **kwargs)

    def _get_paged_data(self, url: str) -> dict[str, Any]:  # pyright: ignore[reportExplicitAny]
        """
        Get paginated data from the API.

        Args:
            url: URL to fetch data from

        Returns:
            dictionary containing the fetched data
        """
        if not self.logged_in:
            _ = self.login()
            if not self.logged_in:
                raise UnauthorizedException("Not logged in to iRacing API")

        response = self.get(url)

        if response.status_code == 200:
            response_json = response.json()
            if "link" in response_json:
                data = self.get(response_json["link"])
                return data.json() if data.status_code == 200 else {}
            else:
                return cast(
                    dict[str, Any],  # pyright: ignore[reportExplicitAny]
                    response_json,
                )
        elif response.status_code == 401:
            # Token expired or invalid, try to refresh
            self.logged_in = False
            try:
                self._refresh_access_token()
                self.logged_in = True
                return self._get_paged_data(url)
            except UnauthorizedException:
                # Refresh failed, try full re-authentication
                self.login()
                return self._get_paged_data(url)
        else:
            response.raise_for_status()
            return {}

    def get_joinable_sessions_for_league(
        self, league_id: int
    ) -> list[SessionDefinition]:
        """
        Get a list of joinable sessions for a league.

        Args:
            league_id: ID of the league

        Returns:
            List of session dictionaries
        """
        url = "https://members-ng.iracing.com/data/league/cust_league_sessions"
        r = self._get_paged_data(url)
        if "sessions" in r:
            return [
                s
                for s in r["sessions"]
                if (
                    int(s.get("league_id")) == league_id
                    and (
                        datetime.strptime(
                            s.get("launch_at"),
                            "%Y-%m-%dT%H:%M:%SZ",
                        )
                        > datetime.now().replace(tzinfo=None)
                    )
                )
            ]
        else:
            return []

    def session_hash(self, session: SessionDefinition) -> str:
        """
        Compute a hash of the session's relevant fields for change detection.

        This improved version normalizes lists to ensure that reordering
        list elements doesn't affect the hash.

        Args:
            session: Session definition to hash

        Returns:
            SHA-256 hash of the normalized session data
        """
        import copy
        import hashlib

        s: SessionDefinition = copy.deepcopy(session)

        # Remove fields that change frequently but don't represent meaningful changes
        try:
            assert isinstance(s["weather"], dict)
            del s["weather"][
                "weather_url"
            ]  # Remove weather_url as it changes frequently
        except KeyError:
            pass
        try:
            assert isinstance(s["weather"], dict)
            assert isinstance(s["weather"]["forecast_options"], dict)
            del s["weather"]["forecast_options"]["weather_seed"]
        except KeyError:
            pass

        # Remove fields that don't represent the session definition
        for key in [
            "elig",
            "can_spot",
            "can_watch",
            "can_broadcast",
            "can_join",
        ]:
            try:
                del s[key]  # pyright: ignore[reportIndexIssue]
            except KeyError:
                pass

        # Normalize lists in the session to make order irrelevant
        normalized_session = normalize_lists_in_dict(s)

        # Generate hash using normalized data
        return hashlib.sha256(
            json.dumps(normalized_session, sort_keys=True).encode()
        ).hexdigest()
