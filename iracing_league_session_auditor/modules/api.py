"""
iRacing API Handler for accessing the iRacing API.

This module provides classes and functions to interact with the iRacing API,
authenticate, retrieve session data, and validate sessions against expectations.
"""

import copy
import hashlib
import json

from . import types
import requests
from datetime import datetime
import base64
from typing import Any, cast

from ..exceptions import (
    VerificationRequiredException,
    UnauthorizedException,
)


SessionDefinition = types.SessionDefinition


class iRacingAPIHandler(requests.Session):
    """
    Handler for interacting with the iRacing API.

    This class extends requests.Session to manage authentication and
    provide methods for retrieving and validating session data.
    """

    # Constants already imported from validation module

    def __init__(self, email: str, password: str):
        """
        Initialize the API handler.

        Args:
            email: iRacing account email
            password: iRacing account password
        """
        self.email: str = email
        self.password: str = str(
            base64.b64encode(
                hashlib.sha256(f"{password}{str(email).lower()}".encode()).digest()
            )
        )
        # remove b' and ' from the ends of the string
        self.password = self.password[2:-1]
        self.logged_in: bool = False
        super().__init__()
        _ = self.login()

    def login(self) -> bool:
        """
        Log in to the iRacing API.

        Returns:
            True if login is successful, False otherwise

        Raises:
            VerificationRequiredException: If verification is required
            UnauthorizedException: If authentication fails
        """
        url = "https://members-ng.iracing.com/auth"
        login_headers = {"Content-Type": "application/json"}
        data = {"email": self.email, "password": self.password}

        response = self.post(url, json=data, headers=login_headers)
        response_data = cast(
            dict[str, Any], response.json()  # pyright: ignore[reportExplicitAny]
        )

        if response.status_code == 200 and response_data.get("authcode"):
            # save the returned cookie
            if response.cookies:
                self.cookies.update(  # pyright: ignore[reportUnknownMemberType]
                    response.cookies
                )
            self.logged_in = True
            return True
        elif (
            "verificationRequired" in response.json()
            and response.json()["verificationRequired"]
        ):
            raise VerificationRequiredException(
                f"Please log in to the iRacing member site. {response_data}"
            )
        else:
            raise UnauthorizedException(f"Error from iRacing: {response_data}")

    def _get_paged_data(
        self, url: str
    ) -> dict[str, Any]:  # pyright: ignore[reportExplicitAny]
        """
        Get paginated data from the API.

        Args:
            url: URL to fetch data from

        Returns:
            Dictionary containing the fetched data
        """
        if not self.logged_in:
            _ = self.login()
            if not self.logged_in:
                raise UnauthorizedException("Not logged in to iRacing API")
        response = self.get(url)
        if response.status_code == 200:
            if "link" in response.json():
                data = self.get(response.json()["link"])  # pyright: ignore[reportAny]
                return data.json() if data.status_code == 200 else {}
            else:
                return cast(
                    dict[str, Any],  # pyright: ignore[reportExplicitAny]
                    response.json(),
                )
        elif response.status_code == 401:
            self.logged_in = False
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
                for s in r["sessions"]  # pyright: ignore[reportAny]
                if (
                    int(s.get("league_id")) == league_id  # pyright: ignore[reportAny]
                    and (
                        datetime.strptime(
                            s.get("launch_at"),  # pyright: ignore[reportAny]
                            "%Y-%m-%dT%H:%M:%SZ",
                        )
                        > datetime.now().replace(tzinfo=None)
                    )
                )
            ]
        else:
            return []

    def session_hash(self, session: SessionDefinition) -> str:
        """Compute a hash of the session's relevant fields for change detection."""
        s: SessionDefinition = copy.deepcopy(session)
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
        for key in [
            "elig",
            "can_spot",
            "can_watch",
            "can_broadcast",
            "can_join",
        ]:
            try:
                del s[key]
            except KeyError:
                pass

        return hashlib.sha256(json.dumps(s, sort_keys=True).encode()).hexdigest()
