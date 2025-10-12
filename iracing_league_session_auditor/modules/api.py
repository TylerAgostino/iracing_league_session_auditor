"""
iRacing API Handler for accessing the iRacing API.

This module provides classes and functions to interact with the iRacing API,
authenticate, retrieve session data, and validate sessions against expectations.
"""

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
                self.cookies.update(response.cookies)
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
            dictionary containing the fetched data
        """
        if not self.logged_in:
            _ = self.login()
            if not self.logged_in:
                raise UnauthorizedException("Not logged in to iRacing API")
        response = self.get(url)
        if response.status_code == 200:
            if "link" in response.json():
                data = self.get(response.json()["link"])
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
        import hashlib
        import copy

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
