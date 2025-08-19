import unittest
from auditor import iRacingAPIHandler
import os

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

