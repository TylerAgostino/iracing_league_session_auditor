import unittest
from auditor import iRacingAPIHandler, LaunchAtMatcher
import os
import json

class TestiRacingAPIHandler(unittest.TestCase):
    def setUp(self):
        self.email = os.environ.get('IRACING_API_EMAIL', "tyleragostino@gmail.com")
        self.password = os.environ.get('IRACING_API_PASSWORD', "password")
        self.handler = iRacingAPIHandler(self.email, self.password)

    def test_login(self):
        try:
            response = self.handler.login()
            self.assertIsNotNone(response, "Login failed, response is None")
            self.assertIn('authcode', response, "Login response does not contain 'authcode'")
        except Exception as e:
            self.fail(f"Login raised an exception: {e}")


    def test_get_joinable_sessions_for_league(self):
        league_id = 8579
        try:
            response = self.handler.get_joinable_sessions_for_league(league_id)
            self.assertIsNotNone(response, "Get joinable sessions failed, response is None")
            self.assertIsInstance(response, list, "Response is not a list")
        except Exception as e:
            self.fail(f"Get joinable sessions raised an exception: {e}")

    def test_validate_sessions(self):
        league_id = 8579
        try:
            results = self.handler.validate_sessions(league_id)
            self.assertIsInstance(results, list, "Validation results are not a list")
            for result in results:
                self.assertIn("✅", result) or self.assertIn("❌", result, "Validation result does not contain expected markers")
        except Exception as e:
            self.fail(f"Validate sessions raised an exception: {e}")

    def test_formatted_results(self):
        league_id = 8579
        try:
            self.handler.login()
            results = self.handler.validate_sessions(league_id)
            formatted_results = self.handler.format_validation_results(results)
            self.assertIsInstance(formatted_results, list, "Formatted results are not a list")
            for result in formatted_results:
                self.assertIn("✅", result) or self.assertIn("❌", result, "Formatted result does not contain expected markers")
        except Exception as e:
            self.fail(f"Formatted results raised an exception: {e}")

    def test_get_historical_sessions(self):
        league_id = 8579
        season_id = 0#123052
        response = self.handler._get_paged_data(f"https://members-ng.iracing.com/data/league/season_sessions?league_id={league_id}&season_id={season_id}")
        print(json.dumps(response, indent=2))


class TestLaunchAtMatcher(unittest.TestCase):
    def test_passing_cases(self):
        cases = [
            # (cron, tolerance in minutes, passing timestamp)
            ("30 0 * * 4", 15, "2025-08-21T00:30:00Z"),  # Wednesday at 00:30 UTC
        ]
        for cron, tolerance, timestamp in cases:
            matcher = LaunchAtMatcher(cron, tolerance)
            valid, message = matcher(timestamp)
            self.assertTrue(valid, message)

    def test_failing_cases(self):
        cases = [
            # (cron, tolerance in minutes, failing timestamp)
            ("30 0 * * 4", 10, "2025-08-21T00:45:00Z"),  # Wednesday at 00:45 UTC, outside tolerance
            ("30 0 * * 4", 15, "2025-08-21T01:00:00Z"),  # Wednesday at 01:00 UTC, outside tolerance
            ("30 0 * * 4", 5, "2025-08-20T12:30:00Z"),  # Tuesday at 12:30 UTC, outside tolerance
        ]
        for cron, tolerance, timestamp in cases:
            matcher = LaunchAtMatcher(cron, tolerance)
            valid, message = matcher(timestamp)
            self.assertFalse(valid, message)