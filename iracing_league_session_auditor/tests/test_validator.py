"""
Test suite for SessionValidator component.

This test suite validates the session validator component's ability to compare
various field types against expectations, including:
- String fields
- Integer fields
- Boolean fields
- Dictionary fields (nested structures)
- List fields
- List of dictionaries
- Cron expressions
"""

import unittest
import json
import tempfile
from pathlib import Path
from typing import Any, Dict, List, cast, override
from unittest.mock import patch

from iracing_league_session_auditor.modules.session_validator import (
    SessionValidator,
    PASS_ICON,
    FAIL_ICON,
    WARN_ICON,
    UNKNOWN_ICON,
    SessionTopLevelField,
    SessionDefinition,
    ExpectationDefinition,
)
from iracing_league_session_auditor.modules.cron_matcher import CronMatcher

# pyright: basic


class TestSessionValidator(unittest.TestCase):
    """
    Test cases for the SessionValidator class.

    Tests the validator's ability to compare different field types and structures
    against expected values, ensuring proper validation of iRacing session configurations.
    """

    @override
    def setUp(self) -> None:
        """
        Set up test fixtures.

        Creates a temporary expectations file and initializes test data structures
        with various field types to test validation logic against:
        - Simple scalar types (string, int, boolean)
        - Nested dictionaries
        - Lists of values
        - Lists of dictionaries
        - Cron schedule specifications
        """
        self.temp_dir: tempfile.TemporaryDirectory[str] = tempfile.TemporaryDirectory()

        self.expectations_path = str(
            Path(self.temp_dir.name) / "test_expectations.json"
        )

        # Basic test expectations
        self.test_expectations: List[Dict[str, Any]] = [
            {
                "name": "Simple Test",
                "expectation": {
                    "string_field": "expected_value",
                    "int_field": 42,
                    "boolean_field": True,
                    "dict_field": {"nested_string": "nested_value", "nested_int": 100},
                    "list_field": ["item1", "item2", "item3"],
                    "list_of_dicts": [
                        {"id": 1, "name": "first"},
                        {"id": 2, "name": "second"},
                    ],
                    "launch_at": {"cron": "30 0 * * 2", "margin": 15},
                },
            }
        ]

        with open(self.expectations_path, "w") as f:
            json.dump(self.test_expectations, f)

        # Basic test session
        self.test_session: Dict[str, Any] = {
            "string_field": "expected_value",
            "int_field": 42,
            "boolean_field": True,
            "dict_field": {
                "nested_string": "nested_value",
                "nested_int": 100,
                "extra_field": "this is extra",  # Extra field that shouldn't cause failure
            },
            "list_field": ["item1", "item2", "item3"],
            "list_of_dicts": [{"id": 1, "name": "first"}, {"id": 2, "name": "second"}],
            "launch_at": "2023-11-14T00:30:00Z",  # A Tuesday at 00:30 UTC
        }

    @override
    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def test_exact_match(self) -> None:
        """
        Test that an exact match is found when all fields match.

        This verifies the validator can correctly identify when a session
        definition completely matches an expectation definition.
        """
        validator = SessionValidator(
            cast(SessionDefinition, self.test_session), self.expectations_path
        )
        match = validator.exact_match()
        assert match is not None
        self.assertIsNotNone(match)
        self.assertEqual(match["name"], "Simple Test")

    def test_string_field_match(self) -> None:
        """
        Test matching string field.

        Verifies that string comparison works correctly when values match.
        """
        validator = SessionValidator(
            cast(SessionDefinition, self.test_session), self.expectations_path
        )
        severity, _ = validator.compare_single_field(
            "string_field",
            cast(SessionTopLevelField, self.test_session["string_field"]),
            cast(SessionTopLevelField, "expected_value"),
        )
        self.assertEqual(severity, PASS_ICON)

    def test_string_field_mismatch(self) -> None:
        """
        Test mismatched string field.

        Verifies that string comparison correctly identifies when values don't match.
        """
        validator = SessionValidator(
            cast(SessionDefinition, self.test_session), self.expectations_path
        )
        severity, _ = validator.compare_single_field(
            "string_field",
            cast(SessionTopLevelField, self.test_session["string_field"]),
            cast(SessionTopLevelField, "wrong_value"),
        )
        self.assertEqual(severity, FAIL_ICON)

    def test_int_field_match(self) -> None:
        """
        Test matching integer field.

        Verifies that integer comparison works correctly when values match.
        """
        validator = SessionValidator(
            cast(SessionDefinition, self.test_session), self.expectations_path
        )
        severity, _ = validator.compare_single_field(
            "int_field",
            cast(SessionTopLevelField, self.test_session["int_field"]),
            cast(SessionTopLevelField, 42),
        )
        self.assertEqual(severity, PASS_ICON)

    def test_int_field_mismatch(self) -> None:
        """
        Test mismatched integer field.

        Verifies that integer comparison correctly identifies when values don't match.
        """
        validator = SessionValidator(
            cast(SessionDefinition, self.test_session), self.expectations_path
        )
        severity, _ = validator.compare_single_field(
            "int_field",
            cast(SessionTopLevelField, self.test_session["int_field"]),
            cast(SessionTopLevelField, 43),
        )
        self.assertEqual(severity, FAIL_ICON)

    def test_boolean_field_match(self) -> None:
        """
        Test matching boolean field.

        Verifies that boolean comparison works correctly when values match.
        """
        validator = SessionValidator(
            cast(SessionDefinition, self.test_session), self.expectations_path
        )
        severity, _ = validator.compare_single_field(
            "boolean_field",
            cast(SessionTopLevelField, self.test_session["boolean_field"]),
            cast(SessionTopLevelField, True),
        )
        self.assertEqual(severity, PASS_ICON)

    def test_boolean_field_mismatch(self) -> None:
        """
        Test mismatched boolean field.

        Verifies that boolean comparison correctly identifies when values don't match.
        """
        validator = SessionValidator(
            cast(SessionDefinition, self.test_session), self.expectations_path
        )
        severity, _ = validator.compare_single_field(
            "boolean_field",
            cast(SessionTopLevelField, self.test_session["boolean_field"]),
            cast(SessionTopLevelField, False),
        )
        self.assertEqual(severity, FAIL_ICON)

    def test_dict_field_match(self) -> None:
        """
        Test matching dictionary field.

        Verifies that dictionary comparison works correctly when all keys and values match.
        """
        validator = SessionValidator(
            cast(SessionDefinition, self.test_session), self.expectations_path
        )
        expected_dict = {"nested_string": "nested_value", "nested_int": 100}
        severity, _ = validator.compare_single_field(
            "dict_field",
            cast(SessionTopLevelField, self.test_session["dict_field"]),
            cast(SessionTopLevelField, expected_dict),
        )
        self.assertEqual(severity, PASS_ICON)

    def test_dict_field_mismatch(self) -> None:
        """
        Test matching dictionary field.

        Verifies that dictionary comparison works correctly when all keys and values match.
        """
        validator = SessionValidator(
            cast(SessionDefinition, self.test_session), self.expectations_path
        )
        expected_dict = {"nested_string": "wrong_value", "nested_int": 999}
        severity, _ = validator.compare_single_field(
            "dict_field",
            cast(SessionTopLevelField, self.test_session["dict_field"]),
            cast(SessionTopLevelField, expected_dict),
        )
        self.assertEqual(severity, FAIL_ICON)

    def test_dict_field_with_extra_fields(self) -> None:
        """
        Test dictionary with extra fields in actual value.

        Verifies that dictionary comparison passes when the actual dictionary
        contains all required fields plus additional fields not in the expected dictionary.
        This is important for API responses that might contain more fields than required.
        """
        validator = SessionValidator(
            cast(SessionDefinition, self.test_session), self.expectations_path
        )
        expected_dict = {"nested_string": "nested_value"}
        # Only checking a subset of fields should pass
        severity, _ = validator.compare_single_field(
            "dict_field",
            cast(SessionTopLevelField, self.test_session["dict_field"]),
            cast(SessionTopLevelField, expected_dict),
        )
        self.assertEqual(severity, PASS_ICON)

    def test_dict_field_missing_key(self) -> None:
        """
        Test dictionary with missing key in actual value.

        Verifies that dictionary comparison fails when the actual dictionary
        is missing keys that are present in the expected dictionary.
        """
        validator = SessionValidator(
            cast(SessionDefinition, self.test_session), self.expectations_path
        )
        expected_dict = {"nested_string": "nested_value", "missing_key": "should fail"}
        severity, _ = validator.compare_single_field(
            "dict_field",
            cast(SessionTopLevelField, self.test_session["dict_field"]),
            cast(SessionTopLevelField, expected_dict),
        )
        self.assertEqual(severity, FAIL_ICON)

    def test_dict_field_wrong_type(self) -> None:
        """
        Test dictionary field with wrong type in actual value.

        Verifies that validation fails when comparing a dictionary against a non-dictionary value.
        Tests type checking functionality of the validator.
        """
        validator = SessionValidator(
            cast(SessionDefinition, self.test_session), self.expectations_path
        )
        severity, _ = validator.compare_single_field(
            "string_field",  # string_field is a string, not a dict
            cast(SessionTopLevelField, self.test_session["string_field"]),
            cast(SessionTopLevelField, {"key": "value"}),  # Expecting a dict
        )
        self.assertEqual(severity, FAIL_ICON)

    def test_list_field_match(self) -> None:
        """
        Test matching list field.

        Verifies that list comparison works correctly when all elements match exactly.
        """
        validator = SessionValidator(
            cast(SessionDefinition, self.test_session), self.expectations_path
        )
        expected_list = ["item1", "item2", "item3"]
        severity, _ = validator.compare_single_field(
            "list_field",
            cast(SessionTopLevelField, self.test_session["list_field"]),
            cast(SessionTopLevelField, expected_list),
        )
        self.assertEqual(severity, PASS_ICON)

    def test_list_field_subset(self) -> None:
        """
        Test list with expected being a subset of actual.

        Verifies that when the expected list is a subset of the actual list,
        the comparison returns a warning (not a pass or fail). This allows for
        additional items in the actual value while ensuring all required items exist.
        """
        validator = SessionValidator(
            cast(SessionDefinition, self.test_session), self.expectations_path
        )
        expected_list = ["item1", "item3"]
        severity, _ = validator.compare_single_field(
            "list_field",
            cast(SessionTopLevelField, self.test_session["list_field"]),
            cast(SessionTopLevelField, expected_list),
        )
        # When expected list is a subset of actual, it should return a warning, not pass
        self.assertEqual(severity, WARN_ICON)

    def test_list_field_extra_items(self) -> None:
        """
        Test list with extra items in actual list.

        Verifies that when the actual list contains all expected items plus additional ones,
        the comparison returns a warning. This is different from a failure, allowing for
        flexibility in list contents while still indicating a difference.
        """
        validator = SessionValidator(
            cast(SessionDefinition, self.test_session), self.expectations_path
        )
        test_session_with_extra = self.test_session.copy()
        test_session_with_extra["list_field"] = [
            "item1",
            "item2",
            "item3",
            "extra_item",
        ]

        severity, _ = validator.compare_single_field(
            "list_field",
            cast(SessionTopLevelField, test_session_with_extra["list_field"]),
            cast(SessionTopLevelField, ["item1", "item2", "item3"]),
        )
        # This should be a warning, not a failure
        self.assertEqual(severity, WARN_ICON)

    def test_list_field_missing_item(self) -> None:
        """
        Test list with missing item in actual list.

        Verifies that list comparison fails when the actual list is missing items
        that are present in the expected list. This ensures all required elements exist.
        """
        validator = SessionValidator(
            cast(SessionDefinition, self.test_session), self.expectations_path
        )
        expected_list = ["item1", "item2", "item3", "missing_item"]
        severity, _ = validator.compare_single_field(
            "list_field",
            cast(SessionTopLevelField, self.test_session["list_field"]),
            cast(SessionTopLevelField, expected_list),
        )
        self.assertEqual(severity, FAIL_ICON)

    def test_list_field_wrong_type(self) -> None:
        """
        Test list field with wrong type in actual value.

        Verifies that validation fails when comparing a list against a non-list value.
        Tests type checking functionality of the validator.
        """
        validator = SessionValidator(
            cast(SessionDefinition, self.test_session), self.expectations_path
        )
        severity, _ = validator.compare_single_field(
            "string_field",  # string_field is a string, not a list
            cast(SessionTopLevelField, self.test_session["string_field"]),
            cast(SessionTopLevelField, ["item1", "item2"]),  # Expecting a list
        )
        self.assertEqual(severity, FAIL_ICON)

    def test_list_of_dicts_match(self) -> None:
        """
        Test matching list of dictionaries.

        Verifies that comparison works correctly for complex nested structures,
        specifically lists containing dictionaries, when all elements match.
        """
        validator = SessionValidator(
            cast(SessionDefinition, self.test_session), self.expectations_path
        )
        expected_list = [{"id": 1, "name": "first"}, {"id": 2, "name": "second"}]
        severity, _ = validator.compare_single_field(
            "list_of_dicts",
            cast(SessionTopLevelField, self.test_session["list_of_dicts"]),
            cast(SessionTopLevelField, expected_list),
        )
        self.assertEqual(severity, PASS_ICON)

    def test_list_of_dicts_mismatch(self) -> None:
        """
        Test matching list of dictionaries.

        Verifies that comparison works correctly for complex nested structures,
        specifically lists containing dictionaries, when all elements match.
        """
        validator = SessionValidator(
            cast(SessionDefinition, self.test_session), self.expectations_path
        )
        expected_list = [{"id": 1, "name": "WRONG"}, {"id": 2, "name": "WRONG"}]
        severity, _ = validator.compare_single_field(
            "list_of_dicts",
            cast(SessionTopLevelField, self.test_session["list_of_dicts"]),
            cast(SessionTopLevelField, expected_list),
        )
        self.assertEqual(severity, FAIL_ICON)

    def test_list_of_dicts_order_irrelevant(self) -> None:
        """
        Test that list order doesn't matter for comparison.

        Verifies that the validator considers lists equivalent regardless of element order.
        This is important for lists of dictionaries where order typically isn't significant.
        """
        validator = SessionValidator(
            cast(SessionDefinition, self.test_session), self.expectations_path
        )
        # Reverse the order of the expected list
        expected_list = [{"id": 2, "name": "second"}, {"id": 1, "name": "first"}]
        severity, _ = validator.compare_single_field(
            "list_of_dicts",
            cast(SessionTopLevelField, self.test_session["list_of_dicts"]),
            cast(SessionTopLevelField, expected_list),
        )
        self.assertEqual(severity, PASS_ICON)

    @patch("iracing_league_session_auditor.modules.cron_matcher.CronMatcher.__call__")
    def test_cron_matcher_match(self, mock_cron_call: Any) -> None:
        """
        Test CronMatcher field that matches.

        Verifies that the validator correctly handles CronMatcher objects for time-based validation.
        Tests the integration with the CronMatcher component when a match is found.
        """
        mock_cron_call.return_value = (True, "")

        validator = SessionValidator(
            cast(SessionDefinition, self.test_session), self.expectations_path
        )

        # Create a CronMatcher manually for testing
        cron_matcher = CronMatcher("30 0 * * 2", 15)

        severity, _ = validator.compare_single_field(
            "launch_at",
            cast(SessionTopLevelField, "2023-11-14T00:30:00Z"),
            cast(SessionTopLevelField, cron_matcher),
        )
        self.assertEqual(severity, PASS_ICON)

    @patch("iracing_league_session_auditor.modules.cron_matcher.CronMatcher.__call__")
    def test_cron_matcher_mismatch(self, mock_cron_call: Any) -> None:
        """
        Test CronMatcher field that doesn't match.

        Verifies that the validator correctly handles CronMatcher objects for time-based validation.
        Tests the integration with the CronMatcher component when no match is found.
        """
        mock_cron_call.return_value = (False, "")

        validator = SessionValidator(
            cast(SessionDefinition, self.test_session), self.expectations_path
        )

        # Create a CronMatcher manually for testing
        cron_matcher = CronMatcher("30 0 * * 2", 15)

        severity, _ = validator.compare_single_field(
            "launch_at",
            cast(
                SessionTopLevelField, "2023-11-15T00:30:00Z"
            ),  # This is a Wednesday, not a Tuesday
            cast(SessionTopLevelField, cron_matcher),
        )
        self.assertEqual(severity, FAIL_ICON)

    def test_field_not_in_session(self) -> None:
        """
        Test field not present in session.

        Verifies that the validator correctly handles the case where an expected field
        is completely missing from the session definition. This should result in an
        UNKNOWN_ICON status.
        """
        validator = SessionValidator(
            cast(SessionDefinition, self.test_session), self.expectations_path
        )

        # Modify session to remove a field
        test_session = self.test_session.copy()
        test_session.pop("string_field")
        validator.session_definition = cast(SessionDefinition, test_session)

        severity, _ = validator.compare_single_field(
            "string_field",
            cast(SessionTopLevelField, None),
            cast(SessionTopLevelField, "expected_value"),
        )
        self.assertEqual(severity, UNKNOWN_ICON)

    def test_format_validation_results_match(self) -> None:
        """
        Test formatting validation results with a matching session.

        Verifies that the validator correctly formats the output string
        when a matching expectation is found, including the appropriate success icon.
        """
        validator = SessionValidator(
            cast(SessionDefinition, self.test_session), self.expectations_path
        )

        # Mock the exact_match function to avoid JSON serialization issues with CronMatcher
        with patch.object(validator, "exact_match") as mock_exact_match:
            mock_exact_match.return_value = {"name": "Simple Test"}
            results = validator.format_validation_results()

            self.assertIn(PASS_ICON, results)
            self.assertIn("Exact match found", results)

    def test_format_validation_results_no_match(self) -> None:
        """
        Test formatting validation results with no matching session.

        Verifies that the validator correctly formats the output string when
        no matching expectations are found, including appropriate failure icon
        and details about mismatched fields.
        """
        # Create a session that won't match
        bad_session = {"string_field": "wrong_value", "int_field": 99}

        validator = SessionValidator(
            cast(SessionDefinition, bad_session), self.expectations_path
        )
        results = validator.format_validation_results()

        self.assertIn(FAIL_ICON, results)
        self.assertIn("No exact match found", results)

    def test_validation_with_modified_session(self) -> None:
        """
        Test validation with a modified session that has some matching and some failing fields.

        Verifies that the validator correctly segregates valid and invalid fields when
        a session partially matches an expectation. This tests the partial matching logic
        and reporting capabilities of the validator.
        """
        modified_session = self.test_session.copy()
        modified_session["string_field"] = "wrong_value"
        modified_session["launch_at"] = "2023-11-15T00:30:00Z"  # Wrong day

        validator = SessionValidator(
            cast(SessionDefinition, modified_session), self.expectations_path
        )
        valid, invalid = validator.get_valid_invalid_tuple_for_expectation(
            cast(ExpectationDefinition, self.test_expectations[0])
        )

        # We should have several valid fields and two invalid ones
        self.assertTrue(len(valid) > 0)
        self.assertEqual(len(invalid), 2)

        # Check that the right fields failed
        invalid_fields = [desc for _, desc in invalid]
        self.assertTrue(any("string_field" in field for field in invalid_fields))
        self.assertTrue(any("launch_at" in field for field in invalid_fields))


if __name__ == "__main__":
    unittest.main()
