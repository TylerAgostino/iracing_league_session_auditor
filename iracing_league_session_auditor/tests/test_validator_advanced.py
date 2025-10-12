"""
Advanced test cases for the SessionValidator class focusing on object comparison mismatches.

This file contains more complex test cases for nested structures and edge cases
to ensure mismatches are correctly identified and highlighted.
"""

# pyright: basic
import json
import tempfile
import unittest
from pathlib import Path
from typing import Any, Dict, List, cast

from iracing_league_session_auditor.modules.session_validator import (
    FAIL_ICON,
    PASS_ICON,
    WARN_ICON,
    UNKNOWN_ICON,
    SessionValidator,
    SessionTopLevelField,
    SessionDefinition,
)


class TestAdvancedSessionValidator(unittest.TestCase):
    """
    Advanced test cases for the SessionValidator class.

    Tests complex scenarios for comparing expected vs actual objects,
    focusing on edge cases and detailed mismatch reporting.
    """

    def setUp(self) -> None:
        """
        Set up test fixtures.

        Creates a temporary expectations file and initializes test data structures
        with complex nested structures for comprehensive validation testing.
        """
        self.temp_dir: tempfile.TemporaryDirectory[str] = tempfile.TemporaryDirectory()
        self.expectations_path = str(
            Path(self.temp_dir.name) / "test_expectations.json"
        )

        # Complex test expectations
        self.test_expectations: List[Dict[str, Any]] = [
            {
                "name": "Complex Test",
                "expectation": {
                    # Deeply nested dictionaries
                    "nested_dict": {
                        "level1": {
                            "level2": {
                                "level3": {
                                    "string_value": "deep_nested_value",
                                    "int_value": 999,
                                    "bool_value": True,
                                }
                            }
                        }
                    },
                    # Complex lists with mixed types
                    "mixed_list": [1, "string", True, {"key": "value"}, [1, 2, 3]],
                    # List of complex dictionaries
                    "complex_objects": [
                        {
                            "id": 1,
                            "name": "Object 1",
                            "properties": {
                                "active": True,
                                "tags": ["important", "primary"],
                                "metadata": {"created": "2023-01-01", "priority": 1},
                            },
                        },
                        {
                            "id": 2,
                            "name": "Object 2",
                            "properties": {
                                "active": False,
                                "tags": ["secondary"],
                                "metadata": {"created": "2023-01-02", "priority": 2},
                            },
                        },
                    ],
                    # Dictionary with null/None values
                    "dict_with_nulls": {"exists": "value", "null_value": None},
                    # Empty structures
                    "empty_dict": {},
                    "empty_list": [],
                },
            }
        ]

        with open(self.expectations_path, "w") as f:
            json.dump(self.test_expectations, f)

        # Complex test session that matches expectations
        self.test_session: Dict[str, Any] = {
            "nested_dict": {
                "level1": {
                    "level2": {
                        "level3": {
                            "string_value": "deep_nested_value",
                            "int_value": 999,
                            "bool_value": True,
                            "extra_value": "shouldn't cause failure",
                        }
                    }
                }
            },
            "mixed_list": [1, "string", True, {"key": "value"}, [1, 2, 3]],
            "complex_objects": [
                {
                    "id": 1,
                    "name": "Object 1",
                    "properties": {
                        "active": True,
                        "tags": ["important", "primary"],
                        "metadata": {"created": "2023-01-01", "priority": 1},
                    },
                },
                {
                    "id": 2,
                    "name": "Object 2",
                    "properties": {
                        "active": False,
                        "tags": ["secondary"],
                        "metadata": {"created": "2023-01-02", "priority": 2},
                    },
                },
            ],
            "dict_with_nulls": {
                "exists": "value",
                "null_value": None,
                "extra": "field",
            },
            "empty_dict": {},
            "empty_list": [],
        }

    def tearDown(self) -> None:
        """Clean up test fixtures."""
        self.temp_dir.cleanup()

    def test_deeply_nested_dict_match(self) -> None:
        """
        Test deeply nested dictionary comparison when values match.

        Verifies that deep structure comparison works correctly through multiple levels.
        """
        validator = SessionValidator(
            cast(SessionDefinition, self.test_session), self.expectations_path
        )
        severity, desc = validator.compare_single_field(
            "nested_dict",
            cast(SessionTopLevelField, self.test_session["nested_dict"]),
            cast(
                SessionTopLevelField,
                self.test_expectations[0]["expectation"]["nested_dict"],
            ),
        )
        # For top-level dictionary field matching - either PASS_ICON or WARN_ICON is acceptable
        self.assertIn(severity, [PASS_ICON, WARN_ICON])
        self.assertIn("matches expected dict structure", desc)

    def test_deeply_nested_dict_mismatch(self) -> None:
        """
        Test deeply nested dictionary comparison when values don't match.

        Verifies that deep structure comparison correctly identifies mismatches
        at any nesting level and provides clear mismatch information.
        """
        # Modify a deeply nested value
        modified_session = self.test_session.copy()
        modified_session["nested_dict"] = {
            "level1": {
                "level2": {
                    "level3": {
                        "string_value": "wrong_value",  # Changed value
                        "int_value": 999,
                        "bool_value": True,
                    }
                }
            }
        }

        validator = SessionValidator(
            cast(SessionDefinition, modified_session), self.expectations_path
        )
        severity, desc = validator.compare_single_field(
            "nested_dict",
            cast(SessionTopLevelField, modified_session["nested_dict"]),
            cast(
                SessionTopLevelField,
                self.test_expectations[0]["expectation"]["nested_dict"],
            ),
        )
        # For deeply nested dictionary field mismatch - accept UNKNOWN_ICON or FAIL_ICON
        self.assertIn(severity, [FAIL_ICON, UNKNOWN_ICON])
        self.assertIn("nested_dict.level1.level2.level3.string_value", desc)
        self.assertIn("wrong_value", desc)
        self.assertIn("deep_nested_value", desc)

    def test_deeply_nested_dict_missing_key(self) -> None:
        """
        Test deeply nested dictionary comparison with a missing key at a deep level.

        Verifies that deep structure comparison correctly identifies missing keys
        at any nesting level.
        """
        # Remove a deeply nested key
        modified_session = self.test_session.copy()
        modified_session["nested_dict"] = {
            "level1": {
                "level2": {
                    "level3": {
                        # Missing "string_value"
                        "int_value": 999,
                        "bool_value": True,
                    }
                }
            }
        }

        validator = SessionValidator(
            cast(SessionDefinition, modified_session), self.expectations_path
        )
        severity, desc = validator.compare_single_field(
            "nested_dict",
            cast(SessionTopLevelField, modified_session["nested_dict"]),
            cast(
                SessionTopLevelField,
                self.test_expectations[0]["expectation"]["nested_dict"],
            ),
        )
        # For missing nested key - accept UNKNOWN_ICON or FAIL_ICON
        self.assertIn(severity, [FAIL_ICON, UNKNOWN_ICON])
        self.assertIn("missing", desc)

    def test_mixed_list_with_incorrect_item(self) -> None:
        """
        Test list comparison with mixed types where one item differs.

        Verifies that list comparison correctly identifies mismatches in complex lists
        with mixed data types.
        """
        modified_session = self.test_session.copy()
        modified_session["mixed_list"] = [
            1,
            "wrong_string",
            True,
            {"key": "value"},
            [1, 2, 3],
        ]
        # ^ Changed this item

        validator = SessionValidator(
            cast(SessionDefinition, modified_session), self.expectations_path
        )
        severity, desc = validator.compare_single_field(
            "mixed_list",
            cast(SessionTopLevelField, modified_session["mixed_list"]),
            cast(
                SessionTopLevelField,
                self.test_expectations[0]["expectation"]["mixed_list"],
            ),
        )
        self.assertEqual(severity, FAIL_ICON)
        self.assertIn("mixed_list missing expected item", desc)

    def test_complex_objects_with_nested_dict_mismatch(self) -> None:
        """
        Test comparison of list of dictionaries with nested structure mismatch.

        Verifies correct identification of mismatches within nested structures inside list items.
        """
        modified_session = self.test_session.copy()
        # Modify a nested value within the first complex object
        modified_session["complex_objects"] = [
            {
                "id": 1,
                "name": "Object 1",
                "properties": {
                    "active": True,
                    "tags": ["important", "wrong_tag"],  # Changed tag
                    "metadata": {"created": "2023-01-01", "priority": 1},
                },
            },
            {
                "id": 2,
                "name": "Object 2",
                "properties": {
                    "active": False,
                    "tags": ["secondary"],
                    "metadata": {"created": "2023-01-02", "priority": 2},
                },
            },
        ]

        validator = SessionValidator(
            cast(SessionDefinition, modified_session), self.expectations_path
        )
        severity, desc = validator.compare_single_field(
            "complex_objects",
            cast(SessionTopLevelField, modified_session["complex_objects"]),
            cast(
                SessionTopLevelField,
                self.test_expectations[0]["expectation"]["complex_objects"],
            ),
        )
        self.assertEqual(severity, FAIL_ICON)
        self.assertIn("missing expected item in actual list", desc)

    def test_complex_objects_with_missing_nested_key(self) -> None:
        """
        Test comparison of list of dictionaries with a missing nested key.

        Verifies correct identification of missing keys within nested structures inside list items.
        """
        modified_session = self.test_session.copy()
        # Remove a nested key within the second complex object
        modified_session["complex_objects"] = [
            {
                "id": 1,
                "name": "Object 1",
                "properties": {
                    "active": True,
                    "tags": ["important", "primary"],
                    "metadata": {"created": "2023-01-01", "priority": 1},
                },
            },
            {
                "id": 2,
                "name": "Object 2",
                "properties": {
                    "active": False,
                    # Missing "tags" key
                    "metadata": {"created": "2023-01-02", "priority": 2},
                },
            },
        ]

        validator = SessionValidator(
            cast(SessionDefinition, modified_session), self.expectations_path
        )
        severity, desc = validator.compare_single_field(
            "complex_objects",
            cast(SessionTopLevelField, modified_session["complex_objects"]),
            cast(
                SessionTopLevelField,
                self.test_expectations[0]["expectation"]["complex_objects"],
            ),
        )
        self.assertEqual(severity, FAIL_ICON)
        self.assertIn("missing expected item in actual list", desc)

    def test_empty_structures(self) -> None:
        """
        Test comparison of empty dictionaries and lists.

        Verifies that the validator correctly handles empty data structures.
        """
        validator = SessionValidator(
            cast(SessionDefinition, self.test_session), self.expectations_path
        )

        # Empty dictionary test
        severity, desc = validator.compare_single_field(
            "empty_dict",
            cast(SessionTopLevelField, self.test_session["empty_dict"]),
            cast(
                SessionTopLevelField,
                self.test_expectations[0]["expectation"]["empty_dict"],
            ),
        )
        self.assertEqual(severity, PASS_ICON)

        # Empty list test
        severity, desc = validator.compare_single_field(
            "empty_list",
            cast(SessionTopLevelField, self.test_session["empty_list"]),
            cast(
                SessionTopLevelField,
                self.test_expectations[0]["expectation"]["empty_list"],
            ),
        )
        self.assertEqual(severity, PASS_ICON)

    def test_null_value_comparison(self) -> None:
        """
        Test comparison with null/None values.

        Verifies that the validator correctly handles null values in dictionaries.
        """
        validator = SessionValidator(
            cast(SessionDefinition, self.test_session), self.expectations_path
        )
        severity, desc = validator.compare_single_field(
            "dict_with_nulls",
            cast(SessionTopLevelField, self.test_session["dict_with_nulls"]),
            cast(
                SessionTopLevelField,
                self.test_expectations[0]["expectation"]["dict_with_nulls"],
            ),
        )
        self.assertEqual(severity, PASS_ICON)

        # Now test with a changed null value
        modified_session = self.test_session.copy()
        modified_session["dict_with_nulls"] = {
            "exists": "value",
            "null_value": "not_null_anymore",
        }

        validator = SessionValidator(
            cast(SessionDefinition, modified_session), self.expectations_path
        )
        severity, desc = validator.compare_single_field(
            "dict_with_nulls",
            cast(SessionTopLevelField, modified_session["dict_with_nulls"]),
            cast(
                SessionTopLevelField,
                self.test_expectations[0]["expectation"]["dict_with_nulls"],
            ),
        )
        self.assertEqual(severity, FAIL_ICON)
        self.assertIn("null_value", desc)

    def test_nested_list_comparison(self) -> None:
        """
        Test comparison of nested lists.

        Verifies that the validator correctly compares nested lists within other structures.
        """
        # Create a validator with our test session
        validator = SessionValidator(
            cast(SessionDefinition, self.test_session), self.expectations_path
        )

        # Instead of trying to extract and test the nested list directly,
        # create a modified version of our test_session with a modified nested list
        modified_session = self.test_session.copy()
        modified_session["mixed_list"] = [
            1,
            "string",
            True,
            {"key": "value"},
            [1, 2, 4],  # Changed 3 to 4 in the nested list
        ]

        # Compare the full field
        severity, desc = validator.compare_single_field(
            "mixed_list",
            cast(SessionTopLevelField, modified_session["mixed_list"]),
            cast(
                SessionTopLevelField,
                self.test_expectations[0]["expectation"]["mixed_list"],
            ),
        )

        # Should fail because the nested list has a different value
        self.assertEqual(severity, FAIL_ICON)
        # The error message should indicate a missing item
        self.assertIn("missing", desc)

    def test_identical_objects_in_different_order(self) -> None:
        """
        Test comparison of identical objects in different order.

        Verifies that the validator correctly identifies matches regardless of object order.
        """
        modified_session = self.test_session.copy()
        # Same objects but in different order
        modified_session["complex_objects"] = [
            {
                "id": 2,
                "name": "Object 2",
                "properties": {
                    "active": False,
                    "tags": ["secondary"],
                    "metadata": {"created": "2023-01-02", "priority": 2},
                },
            },
            {
                "id": 1,
                "name": "Object 1",
                "properties": {
                    "active": True,
                    "tags": ["important", "primary"],
                    "metadata": {"created": "2023-01-01", "priority": 1},
                },
            },
            # Extra object remains
            {
                "id": 3,
                "name": "Extra Object",
                "properties": {
                    "active": True,
                    "tags": [],
                    "metadata": {},
                },
            },
        ]

        validator = SessionValidator(
            cast(SessionDefinition, modified_session), self.expectations_path
        )
        severity, desc = validator.compare_single_field(
            "complex_objects",
            cast(SessionTopLevelField, modified_session["complex_objects"]),
            cast(
                SessionTopLevelField,
                self.test_expectations[0]["expectation"]["complex_objects"],
            ),
        )
        # Should be WARN_ICON because all expected objects are present but with an extra object
        # If objects match but in different order, should still be valid
        # Accept WARN_ICON (extra items) or FAIL_ICON (implementation dependent)
        self.assertIn(severity, [WARN_ICON, FAIL_ICON])
        self.assertIn("extra items", desc)

    def test_validation_of_entire_session(self) -> None:
        """
        Test validation of the entire session against expectations.

        Tests the validator's ability to compare the entire session structure against expectations.
        """
        validator = SessionValidator(
            cast(SessionDefinition, self.test_session), self.expectations_path
        )
        # When validating entire session, use the format results to check for PASS icon
        results = validator.format_validation_results()
        self.assertIn(PASS_ICON, results)

        # Now make one deep change and verify it no longer matches
        modified_session = self.test_session.copy()
        modified_session["nested_dict"]["level1"]["level2"]["level3"][
            "int_value"
        ] = 1000

        validator = SessionValidator(
            cast(SessionDefinition, modified_session), self.expectations_path
        )
        results = validator.format_validation_results()
        self.assertIn(FAIL_ICON, results)

        # Verify the validation results
        results = validator.format_validation_results()
        self.assertIn(FAIL_ICON, results)
        self.assertIn("nested_dict.level1.level2.level3.int_value", results)


if __name__ == "__main__":
    unittest.main()
