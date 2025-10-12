"""
iRacing API Handler for accessing the iRacing API.

This module provides classes and functions to interact with the iRacing API,
authenticate, retrieve session data, and validate sessions against expectations.
"""

import copy
import hashlib
import json
import os
import requests
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional, Union, Tuple

from iracing_league_session_auditor.utils.validation import (
    compare_expectations, count_mismatches,
    format_validation_results, session_hash, validate_session,
    PASS_ICON, FAIL_ICON, UNKNOWN_ICON,
)

from iracing_league_session_auditor.exceptions import (
    VerificationRequiredException,
    UnauthorizedException,
)
from iracing_league_session_auditor.modules.cron_matcher import CronMatcher
from iracing_league_session_auditor.utils.validation import (
    compare_expectations,
    count_mismatches,
    format_validation_results,
    validate_session,
    session_hash,
)

class iRacingAPIHandler(requests.Session):
    """
    Handler for interacting with the iRacing API.

    This class extends requests.Session to manage authentication and
    provide methods for retrieving and validating session data.
    """

    # Constants already imported from validation module

    def __init__(
        self,
        email: str,
        password: str,
        state_file_path: str = "state/state.json",
        expectations_path: str = "expectations.json",
    ):
        """
        Initialize the API handler.

        Args:
            email: iRacing account email
            password: iRacing account password
            state_file_path: Path to the state file for storing session summaries
            expectations_path: Path to the JSON file containing session expectations
        """
        self.email = email
        self.password = password
        self.state_file_path = state_file_path
        self.expectations = self._load_expectations(expectations_path)
        self.logged_in = False
        super().__init__()
        self.login()

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
        response_data = response.json()

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

    def _get_paged_data(self, url: str) -> Dict:
        """
        Get paginated data from the API.

        Args:
            url: URL to fetch data from

        Returns:
            Dictionary containing the fetched data
        """
        if not self.logged_in:
            self.login()
            if not self.logged_in:
                raise UnauthorizedException("Not logged in to iRacing API")
        response = self.get(url)
        if response.status_code == 200:
            if "link" in response.json():
                data = self.get(response.json()["link"])
                return data.json() if data.status_code == 200 else {}
            else:
                return response.json()
        elif response.status_code == 401:
            self.logged_in = False
            return self._get_paged_data(url)
        else:
            response.raise_for_status()
            return {}

    def get_joinable_sessions_for_league(self, league_id: int) -> List[Dict]:
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
                    s.get("league_id") == league_id
                    and (
                        datetime.strptime(s.get("launch_at"), "%Y-%m-%dT%H:%M:%SZ")
                        > datetime.now().replace(tzinfo=None)
                    )
                )
            ]
        else:
            return []

    def _session_hash(self, session):
        """Compute a hash of the session's relevant fields for change detection."""
        s = copy.deepcopy(session)
        try:
            del s["weather"]["weather_url"]  # Remove weather_url as it changes frequently
        except KeyError:
            pass
        try:
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

    def _compute_expectations_revision(self, path=None):
        """Compute a checksum of the expectations file for change detection."""
        path = path or self.expectations_path
        with open(path, "rb") as f:
            return hashlib.sha256(f.read()).hexdigest()

    def _session_hash(self, session):
        """Compute a hash of the session's relevant fields for change detection."""
        return session_hash(session)

    def validate_session(self, session):
        """
        Validate a single session against expectations.

        Args:
            session: Session data to validate

        Returns:
            Dictionary containing validation results
        """
        return validate_session(session, self.expectations)

    def validate_sessions(
        self, league_id: int, summaries_path: Optional[str] = None, force: bool = False
    ) -> Union[List[Dict], bool]:
        """
        Validate sessions for a league against expectations.

        Args:
            league_id: ID of the league
            summaries_path: Path to save session summaries
            force: Whether to force validation regardless of changes

        Returns:
            List of validation results or False if no sessions found
        """
        sessions = self.get_joinable_sessions_for_league(league_id)
        if not sessions:
            return False

        summaries_path = summaries_path or self.state_file_path
        prev_summaries = self._load_previous_summaries(summaries_path)
        new_summaries = {}
        results = []

        # Compute the current expectations revision
        current_revision = self._compute_expectations_revision(self.expectations_path)
        prev_revision = prev_summaries.get("revision")

        # If the revision has changed, force revalidation
        if current_revision != prev_revision:
            force = True

        for session in sessions:
            session_id = str(session.get("launch_at"))
            session_hash = self._session_hash(session)
            new_summaries[session_id] = session_hash

            if (
                session_id not in prev_summaries
                or prev_summaries[session_id] != session_hash
                or force
            ):
                print(f"Session changed or force validation: {session.get('session_name')}")
                results.append(self.validate_session(session))

        # Save the new revision and summaries
        new_summaries["revision"] = current_revision
        self._save_summaries(new_summaries, summaries_path)

        return results

    def format_validation_results(self, results):
        """Format validation results for display."""
        return format_validation_results(results)

        """
        Recursively compare expected and actual values.

        Args:
            expected: Expected value or structure
            actual: Actual value or structure
            path: Current path in the structure (for reporting)

        Returns:
            List of validation results
        """
        results = []
        if isinstance(expected,mat_validation_results(self, results: List[Dict]) -> str:
        """
        Format validation results for display.

        Args:
            results: List of validation results

        Returns:
            Formatted string with validation results
        """
        sessions = self.get_joinable_sessions_for_league(league_id)
        if not sessions:
            return False

        summaries_path = summaries_path or self.state_file_path
        prev_summaries = self._load_previous_summaries(summaries_path)
        new_summaries = {}
        results = []

        # Compute the current expectations revision
        current_revision = self._compute_expectations_revision()
        prev_revision = prev_summaries.get("revision")

        # If the revision has changed, force revalidation
        if current_revision != prev_revision:
            force = True

        for session in sessions:
            session_id = str(session.get("launch_at"))
            session_hash = self._session_hash(session)
            new_summaries[session_id] = session_hash

            if (
                session_id not in prev_summaries
                or prev_summaries[session_id] != session_hash
                or force
            ):
                results.append(self.validate_session(session))

        # Save the new revision and summaries
        new_summaries["revision"] = current_revision
        self._save_summaries(new_summaries, summaries_path)

        return results

    def _load_previous_summaries(self, path: Optional[str] = None) -> Dict:
        """
        Load previous session summaries from file.

        Args:
            path: Path to the summaries file

        Returns:
            Dictionary containing previous session summaries
        """
        path = path or self.state_file_path
        if os.path.exists(path):
            with open(path, "r") as f:
                return json.load(f)
        return {}

    def _save_summaries(self, summaries: Dict, path: Optional[str] = None) -> None:
        """
        Save session summaries to file.

        Args:
            summaries: Dictionary of session summaries
            path: Path to save the summaries file
        """
        path = path or self.state_file_path
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as f:
            json.dump(summaries, f, indent=2)

    def _load_expectations(self, path: str) -> List[Dict]:
        """
        Load session expectations from file.

        Args:
            path: Path to the expectations JSON file

        Returns:
            List of session expectations
        """
        with open(path, "r") as f:
            expectations = json.load(f)
        # Replace any 'launch_at' with a matcher callable
        for exp in expectations:
            if "expectation" in exp and isinstance(exp["expectation"], dict):
                launch_at = exp["expectation"].get("launch_at")
                if (
                    isinstance(launch_at, dict)
                    and "cron" in launch_at
                    and "margin" in launch_at
                ):
                    exp["expectation"]["launch_at"] = CronMatcher(
                        launch_at["cron"], launch_at["margin"]
                    )
                elif launch_at == "CronMatcher":
                    exp["expectation"]["launch_at"] = CronMatcher()
        return expectations

    @staticmethod
    def _compute_expectations_revision(path: str) -> str:
        """
        Compute a checksum of the expectations file for change detection.

        Args:
            path: Path to the expectations file

        Returns:
            SHA-256 hash of the file contents
        """
        with open(path, "rb") as f:
            return hashlib.sha256(f.read()).hexdigest()
