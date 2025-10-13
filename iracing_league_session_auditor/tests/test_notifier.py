# pyright: basic
"""
Tests for the Notifier class.

This test module verifies the functionality of the Notifier class
which is responsible for sending notifications via webhooks.

The tests include both unit tests with mocked responses and
integration tests that make real HTTP requests.

Integration Test Usage:
----------------------
To run the integration tests with a real webhook:

1. Set the TEST_WEBHOOK_URL environment variable to a valid webhook URL:

   # Linux/Mac
   export TEST_WEBHOOK_URL="https://discord.com/api/webhooks/your_webhook_url"

   # Windows
   set TEST_WEBHOOK_URL=https://discord.com/api/webhooks/your_webhook_url

2. Run the tests:

   pytest iracing_league_session_auditor/tests/test_notifier.py -v

   or

   python -m unittest iracing_league_session_auditor/tests/test_notifier.py

If the TEST_WEBHOOK_URL environment variable is not set, the integration
tests will be skipped automatically.

The integration tests include:
1. A simple test with a basic webhook message
2. A comprehensive test with realistic validation result payloads that
   simulate both successful and failed validations
"""

import unittest
import os
from unittest.mock import patch, MagicMock
import json
import logging
import requests
from ..modules.notifier import Notifier

# Set up logging to avoid actual log outputs during tests
logging.disable(logging.CRITICAL)

# Environment variable name for real webhook URL for integration tests
WEBHOOK_URL_ENV = "TEST_WEBHOOK_URL"


class TestNotifier(unittest.TestCase):
    """Test the Notifier class functionality."""

    def setUp(self) -> None:
        """Set up test environment."""
        self.webhook_url = "https://discord.com/api/webhooks/test_webhook"
        self.notifier = Notifier(self.webhook_url)

        # Sample payload to be sent in notifications
        self.sample_payload = {
            "session_id": 12345,
            "validation_results": [
                {
                    "field": "track_name",
                    "status": "mismatch",
                    "expected": "Spa",
                    "actual": "Monza",
                },
                {"field": "car_count", "status": "match", "expected": 20, "actual": 20},
            ],
            "validation_passed": False,
        }

        # String version of the payload for direct comparison
        self.sample_payload_str = json.dumps(self.sample_payload)

    def test_init(self) -> None:
        """Test that Notifier initializes with the correct webhook URL."""
        self.assertEqual(
            self.webhook_url,
            self.notifier.webhook_url,
            "Webhook URL should be stored correctly",
        )

    @patch("requests.post")
    def test_send_notification_success(self, mock_post) -> None:
        """Test successful notification sending."""
        # Set up the mock to return a 204 status code for successful Discord webhook
        mock_response = MagicMock()
        mock_response.status_code = 204
        mock_post.return_value = mock_response

        # Send a notification with our sample payload
        response = self.notifier.send_notification(self.sample_payload)

        # Verify that requests.post was called with the correct arguments
        mock_post.assert_called_once_with(
            self.webhook_url,
            json=self.sample_payload,
            headers={"Content-Type": "application/json"},
        )

        # Check that the response is correctly returned
        self.assertEqual(
            response,
            mock_response,
            "send_notification should return the response from requests.post",
        )

    @patch("requests.post")
    def test_send_notification_failure(self, mock_post) -> None:
        """Test handling of failed notification sending."""
        # Set up the mock to return an error status code
        mock_response = MagicMock()
        mock_response.status_code = 400
        mock_response.text = "Bad Request"
        mock_post.return_value = mock_response

        # Send a notification with our sample payload
        response = self.notifier.send_notification(self.sample_payload)

        # Verify that requests.post was called with the correct arguments
        mock_post.assert_called_once_with(
            self.webhook_url,
            json=self.sample_payload,
            headers={"Content-Type": "application/json"},
        )

        # Check that the response is correctly returned even on failure
        self.assertEqual(
            response,
            mock_response,
            "send_notification should return the response from requests.post even on failure",
        )

    @patch("requests.post")
    def test_send_notification_network_error(self, mock_post) -> None:
        """Test handling of network errors during notification sending."""
        # Set up the mock to raise a network error
        mock_post.side_effect = requests.exceptions.RequestException("Network error")

        # The method should handle the exception gracefully
        with self.assertRaises(requests.exceptions.RequestException):
            self.notifier.send_notification(self.sample_payload)

        # Verify that requests.post was called with the correct arguments
        mock_post.assert_called_once_with(
            self.webhook_url,
            json=self.sample_payload,
            headers={"Content-Type": "application/json"},
        )

    @patch("logging.Logger.info")
    @patch("requests.post")
    def test_logging_on_success(self, mock_post, mock_log_info) -> None:
        """Test that successful notifications are logged."""
        # Set up the mock to return a successful response
        mock_response = MagicMock()
        mock_response.status_code = 204
        mock_post.return_value = mock_response

        # Send a notification
        self.notifier.send_notification(self.sample_payload)

        # Verify that logging.info was called for both the sending attempt and success
        self.assertEqual(mock_log_info.call_count, 2)
        # First call should be about sending
        mock_log_info.assert_any_call(
            f"Sending notification to {self.webhook_url}: {self.sample_payload}"
        )
        # Second call should be about success
        mock_log_info.assert_any_call("Results sent to Discord successfully.")

    @patch("logging.Logger.error")
    @patch("requests.post")
    def test_logging_on_failure(self, mock_post, mock_log_error) -> None:
        """Test that failed notifications are logged as errors."""
        # Set up the mock to return an error response
        mock_response = MagicMock()
        mock_response.status_code = 400
        mock_response.text = "Bad Request"
        mock_post.return_value = mock_response

        # Send a notification
        self.notifier.send_notification(self.sample_payload)

        # Verify that logging.error was called for the failure
        mock_log_error.assert_called_once_with(
            f"Failed to send results to Discord: {mock_response.status_code} - {mock_response.text}"
        )

    def test_integration_real_webhook(self) -> None:
        """
        Integration test that makes an actual webhook call.

        This test only runs if the TEST_WEBHOOK_URL environment variable is set.
        It sends a real HTTP request to the specified webhook URL and verifies the response.

        To run this test:
        1. Set the TEST_WEBHOOK_URL environment variable to a valid Discord webhook URL
        2. Run the tests normally
        """
        # Skip this test if no real webhook URL is provided in environment variables
        webhook_url = os.environ.get(WEBHOOK_URL_ENV)
        if not webhook_url:
            self.skipTest(
                f"Skipping integration test: {WEBHOOK_URL_ENV} environment variable not set"
            )

        # Create a test payload that won't cause problems with the real webhook
        test_payload = {
            "content": "This is a test notification from the iRacing League Session Auditor test suite",
            "test_data": {
                "session_id": 99999,
                "validation_results": [
                    {
                        "field": "test_field",
                        "status": "match",
                        "expected": "test",
                        "actual": "test",
                    }
                ],
                "validation_passed": True,
            },
        }

        # Create a new notifier with the real webhook URL
        real_notifier = Notifier(webhook_url)

        # Send an actual notification
        response = real_notifier.send_notification(test_payload)

        # Verify that the request was successful (Discord returns 204 No Content on success)
        self.assertEqual(
            response.status_code,
            204,
            f"Expected 204 status code, got {response.status_code} with content: {response.text}",
        )

    def test_integration_with_validation_results(self) -> None:
        """
        Integration test that sends a realistic validation result payload to a real webhook.

        This test simulates the exact format of validation results that would be sent
        by the validator in the actual application flow.

        This test only runs if the TEST_WEBHOOK_URL environment variable is set.
        """
        # Skip this test if no real webhook URL is provided in environment variables
        webhook_url = os.environ.get(WEBHOOK_URL_ENV)
        if not webhook_url:
            self.skipTest(
                f"Skipping integration test: {WEBHOOK_URL_ENV} environment variable not set"
            )

        # Create a realistic validation results payload similar to what would be
        # produced by SessionValidator.format_validation_results()
        PASS_ICON = "✅"
        FAIL_ICON = "❌"

        # Scenario 1: Failed validation
        failed_validation_payload = "\n".join(
            [
                f"{FAIL_ICON} No exact match found for any expectation.",
                "Expectation: Weekly Series Race",
                "Invalid fields:",
                f"  {FAIL_ICON} Field 'track_name' expected 'Spa', got 'Monza'",
                f"  {FAIL_ICON} Field 'car_count' expected 20, got 18",
                f"  {FAIL_ICON} Field 'session_name' expected 'Weekly GT3 Series', got 'GT3 Special Event'",
            ]
        )

        # Scenario 2: Passed validation
        passed_validation_payload = "\n".join(
            [
                f"{PASS_ICON} Exact match found for expectation.",
                "Expectation details: "
                + json.dumps(
                    {
                        "name": "Weekly Series Race",
                        "track_name": "Spa",
                        "car_count": 20,
                        "session_name": "Weekly GT3 Series",
                    },
                    indent=2,
                ),
            ]
        )

        # Create Discord-friendly payloads with the validation results
        failed_payload = {
            "content": "**VALIDATION FAILED**",
            "embeds": [
                {
                    "title": "Session Validation Results",
                    "description": failed_validation_payload,
                    "color": 16711680,  # Red color for failure
                }
            ],
        }

        passed_payload = {
            "content": "**VALIDATION PASSED**",
            "embeds": [
                {
                    "title": "Session Validation Results",
                    "description": passed_validation_payload,
                    "color": 65280,  # Green color for success
                }
            ],
        }

        # Create a new notifier with the real webhook URL
        real_notifier = Notifier(webhook_url)

        # Send both notifications and verify responses
        for payload, scenario in [
            (failed_payload, "Failed validation"),
            (passed_payload, "Passed validation"),
        ]:
            # Add test identifier to avoid confusion with real alerts
            payload["content"] = f"[TEST] {payload['content']}"

            # Send the notification
            response = real_notifier.send_notification(payload)

            # Verify that the request was successful
            self.assertEqual(
                response.status_code,
                204,
                f"Expected 204 status code for {scenario}, got {response.status_code} with content: {response.text}",
            )


if __name__ == "__main__":
    unittest.main()
