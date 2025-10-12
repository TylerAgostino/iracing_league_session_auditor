import os
import tempfile
import unittest
from unittest.mock import patch

from ..modules.api import iRacingAPIHandler
from ..modules.state_manager import StateManager
from ..modules.types import SessionDefinition

# pyright: basic
# pyright: reportAttributeAccessIssue=false


class TestApiStateManagerInteraction(unittest.TestCase):
    """Test interaction between API and StateManager classes."""

    def setUp(self) -> None:
        """Set up test environment."""
        # Create a temporary state file
        self.temp_file = tempfile.NamedTemporaryFile(delete=False)
        self.temp_file.write(b"[]")
        self.temp_file.close()

        # Create a sample session with a list that will be reordered
        self.sample_session: SessionDefinition = {
            "session_id": 12345,
            "cars": [
                {"id": 1, "name": "Ferrari"},
                {"id": 2, "name": "McLaren"},
                {"id": 3, "name": "Red Bull"},
            ],
            "drivers": [
                {"driver_id": 101, "name": "Driver A"},
                {"driver_id": 102, "name": "Driver B"},
                {"driver_id": 103, "name": "Driver C"},
            ],
            "weather": {
                "type": "dynamic",
                "temperature": 75,
                "forecast_options": {"weather_seed": 123456},
            },
            "launch_at": "2023-01-01T12:00:00Z",
            "can_join": True,
            "can_watch": True,
        }

        # Create a reordered version of the same session
        self.reordered_session = self.sample_session.copy()
        # Reorder the cars list without changing contents
        self.reordered_session["cars"] = [
            {"id": 2, "name": "McLaren"},
            {"id": 3, "name": "Red Bull"},
            {"id": 1, "name": "Ferrari"},
        ]
        # Reorder the drivers list without changing contents
        self.reordered_session["drivers"] = [
            {"driver_id": 103, "name": "Driver C"},
            {"driver_id": 101, "name": "Driver A"},
            {"driver_id": 102, "name": "Driver B"},
        ]

        # Create a state manager with our temporary file
        self.state_manager = StateManager(self.temp_file.name)

    def tearDown(self) -> None:
        """Clean up test environment."""
        # Remove the temporary state file
        os.unlink(self.temp_file.name)

    def test_reordered_list_produces_same_hash(self) -> None:
        """
        Test that reordering a list in a session produces the same hash.
        """
        # Create API handler instance for hashing
        api_handler = iRacingAPIHandler.__new__(iRacingAPIHandler)

        # Get hash of original session
        original_hash = api_handler.session_hash(self.sample_session)

        # Get hash of reordered session
        reordered_hash = api_handler.session_hash(self.reordered_session)

        # With the current implementation, list order does not affect the hash
        self.assertEqual(
            original_hash,
            reordered_hash,
            "Reordered lists should produce the same hash",
        )

    def test_state_manager_change_detection_with_reordered_lists(self) -> None:
        """
        Test that state manager does not detect changes when list order changes.
        """
        session_id = str(self.sample_session["session_id"])

        # Create API handler instance for hashing
        api_handler = iRacingAPIHandler.__new__(iRacingAPIHandler)

        # First, add the original session to the state
        original_hash = api_handler.session_hash(self.sample_session)
        initial_change = self.state_manager.item_changed(session_id, original_hash)

        # Since this is the first time we've seen this session, it should register as changed
        self.assertTrue(initial_change, "Initial session should be marked as changed")

        # Now get the hash of the reordered session
        reordered_hash = api_handler.session_hash(self.reordered_session)

        # Check if state manager detects a change with the reordered session
        change_detected = self.state_manager.item_changed(session_id, reordered_hash)

        # With the current implementation, it will not detect this as a change
        self.assertFalse(
            change_detected,
            "Reordered lists should not be detected as a change",
        )

    def test_actual_content_change_is_detected(self) -> None:
        """Test that actual content changes are still detected properly."""
        session_id = str(self.sample_session["session_id"])

        # Create API handler instance for hashing
        api_handler = iRacingAPIHandler.__new__(iRacingAPIHandler)

        # First, add the original session to the state
        original_hash = api_handler.session_hash(self.sample_session)
        self.state_manager.item_changed(session_id, original_hash)

        # Modify session content (not just order)
        modified_session = self.sample_session.copy()
        modified_session["cars"] = [
            {"id": 1, "name": "Ferrari"},
            {"id": 2, "name": "McLaren"},
            {"id": 4, "name": "Mercedes"},  # Changed from Red Bull to Mercedes
        ]

        # Get hash of modified session
        modified_hash = api_handler.session_hash(modified_session)

        # Check if state manager detects the actual content change
        change_detected = self.state_manager.item_changed(session_id, modified_hash)

        # It SHOULD detect this as a change
        self.assertTrue(change_detected, "Actual content changes should be detected")

    @patch("iracing_league_session_auditor.modules.api.json.dumps")
    def test_json_serialization_uses_sort_keys(self, mock_dumps) -> None:
        """Test that json.dumps is called with sort_keys=True when creating the hash."""
        # Setup the mock to return a string that can be encoded
        mock_dumps.return_value = "{}"

        # Create API handler instance for hashing
        api_handler = iRacingAPIHandler.__new__(iRacingAPIHandler)

        # Call session_hash method
        api_handler.session_hash(self.sample_session)

        # Verify that json.dumps was called with sort_keys=True
        mock_dumps.assert_called_with(
            unittest.mock.ANY,  # We don't care about the exact dict passed
            sort_keys=True,
        )
