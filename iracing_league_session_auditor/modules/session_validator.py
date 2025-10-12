from pathlib import Path
from iracing_league_session_auditor.modules.cron_matcher import CronMatcher
import hashlib
import json
import os

# Constants
PASS_ICON = "✅"
FAIL_ICON = "❌"
UNKNOWN_ICON = "❓"

# Default paths
script_dir = Path(os.path.dirname(os.path.abspath(__file__)))
default_state_file = script_dir / ".." / ".state" / "summaries.json"
default_expectations_file = "expectations.json"


class SessionValidator:
    """
    Handles validation of iRacing sessions against defined expectations.
    This class is responsible for:
    - Loading and parsing expectations
    - Comparing session data against expectations
    - Tracking changes in sessions over time
    - Formatting validation results
    """

    def __init__(
            self,
            expectations_path: str = default_expectations_file,
            session_definition: dict = None
    ):
        """
        Initialize the SessionValidator with expectations.

        Args:
            expectations_path: Path to the JSON file containing expectations
        """
        with open(expectations_path, "r") as f:
            expectations = json.load(f)
        # Replace any 'launch_at' with a matcher callable
        for exp in expectations:
            if "expectation" in exp and isinstance(exp["expectation"], dict):
                for key, val in exp["expectation"].items():
                    if isinstance(val, dict) and "cron" in val and "margin" in val:
                        exp["expectation"][key] = CronMatcher(
                            val["cron"], val["margin"]
                        )
        self.expectations = expectations
        self.expectations_revision = hashlib.sha256(expectations).hexdigest()
        self.session_definition = session_definition

    def exact_match(self):
        """
        Check if the session definition exactly matches any expectation.

        Returns:
            The name of the matching expectation or None if no match is found.
        """
        for exp in self.expectations:
            if "expectation" in exp and self.matches_expectation(exp):
                return exp["name"]
        return None

    def get_valid_invalid_tuple_for_expectation(self, expectation: dict) -> tuple[list[tuple[str, str]], list[tuple[str, str]]]:
        """
        Check if the session definition matches a given expectation.

        Args:
            expectation: The expectation to match against.
        Returns:
            True if the session matches the expectation, False otherwise.
        """
        if not self.session_definition:
            return False
        for key, val in expectation["expectation"].items():
            if key not in self.session_definition:
                return False
            if callable(val):
                if not val(self.session_definition[key]):
                    return False
            elif self.session_definition[key] != val:
                return False
        return True