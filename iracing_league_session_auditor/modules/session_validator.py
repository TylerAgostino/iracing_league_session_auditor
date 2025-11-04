import hashlib
import json
import os
from pathlib import Path
from typing import cast

from . import types
from .cron_matcher import CronMatcher

# Constants
PASS_ICON = "✅"
FAIL_ICON = "❌"
UNKNOWN_ICON = "❓"
WARN_ICON = "⚠️"

# Default paths
script_dir = Path(os.path.dirname(os.path.abspath(__file__)))
default_state_file = script_dir / ".." / ".state" / "summaries.json"
default_expectations_file = "expectations.json"


SessionTopLevelField = types.SessionTopLevelField
SessionDefinition = types.SessionDefinition
ExpectationDefinition = types.ExpectationDefinition


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
        session_definition: SessionDefinition,
        expectations_path: str = default_expectations_file,
    ):
        """
        Initialize the SessionValidator with expectations.

        Args:
            expectations_path: Path to the JSON file containing expectations
        """
        try:
            with open(expectations_path, "r") as f:
                expectations_file_content: str = f.read()
        except FileNotFoundError:
            # Create expectations based on current session

            # Get all sessions being validated from the session_definition
            name = session_definition.get("launch_at", "")

            # Create the expectations list with the current session
            expectations_list = [{"name": name, "expectation": session_definition}]

            expectations_json = json.dumps(expectations_list, indent=2)
            with open(expectations_path, "w") as f:
                _ = f.write(expectations_json)
            expectations_file_content = expectations_json
        self.expectations_revision: str = hashlib.sha256(
            expectations_file_content.encode()
        ).hexdigest()
        try:
            expectations = cast(
                list[ExpectationDefinition], json.loads(expectations_file_content)
            )
        except json.JSONDecodeError:
            print(f"Error: Invalid JSON in expectations file: {expectations_path}")
            raise
        # Replace any 'launch_at' with a matcher callable
        for exp in expectations:
            if "expectation" in exp and isinstance(exp["expectation"], dict):
                for key, val in exp["expectation"].items():
                    if isinstance(val, dict) and "cron" in val and "margin" in val:
                        assert isinstance(val["cron"], str)
                        assert isinstance(val["margin"], int)
                        # Optional timezone support: allow callers to provide an IANA timezone
                        # (e.g. "America/New_York"). If missing, default to UTC.
                        tz = val.get("timezone", "UTC")
                        assert isinstance(tz, str)
                        exp["expectation"][key] = CronMatcher(
                            val["cron"], val["margin"], tz
                        )
        self.expectations: list[ExpectationDefinition] = expectations
        self.session_definition: SessionDefinition = session_definition

    def exact_match(self):
        """
        Check if the session definition has no errors for an expectation.
        Returns:
            The first expectation that matches exactly, or None if none match.
        """
        for expectation in self.expectations:
            _, invalid = self.get_valid_invalid_tuple_for_expectation(expectation)
            if len(invalid) == 0:
                return expectation
        return None

    def get_valid_invalid_tuple_for_expectation(
        self, expectation: ExpectationDefinition
    ) -> tuple[list[tuple[str, str]], list[tuple[str, str]]]:
        """
        Validate the session definition against a specific expectation.

        Args:
            expectation: The expectation dictionary to validate against.

        Returns:
            A tuple containing two lists:
            - List of (severity_icon, description) tuples for valid fields
            - List of (severity_icon, description) tuples for invalid fields
        """
        valid: list[tuple[str, str]] = []
        invalid: list[tuple[str, str]] = []
        if "expectation" not in expectation:
            return valid, invalid
        assert isinstance(expectation["expectation"], dict)  # make linter happy
        for field, expected_value in expectation["expectation"].items():
            actual_value = self.session_definition.get(field)
            if actual_value is None:
                invalid.append((FAIL_ICON, f"{field} missing in actual value"))
                continue
            severity, desc = self.compare_single_field(
                field, actual_value, expected_value
            )
            if severity == PASS_ICON:
                valid.append((severity, desc))
            else:
                invalid.append((severity, desc))
        return valid, invalid

    def compare_single_field(
        self,
        field_name: str,
        actual_value: SessionTopLevelField,
        expected_value: SessionTopLevelField,
    ) -> tuple[str, str]:
        """
        Compare a single field's actual value against the expected value.

        Args:
            field_name: The name of the field being compared.
            actual_value: The actual value from the session definition.
            expected_value: The expected value from the expectation.

        Returns:
            A tuple containing:
            - Severity icon (PASS_ICON, FAIL_ICON, or UNKNOWN_ICON)
            - Description of the comparison result
        """
        # Skip this check for nested fields - they've been checked by their parent
        if (
            "." not in field_name
            and "[" not in field_name
            and field_name not in self.session_definition
        ):
            return (UNKNOWN_ICON, f"{field_name} not present in session definition")

        if isinstance(expected_value, CronMatcher):
            """CronMatcher provides its own matching logic"""

            if isinstance(actual_value, str):
                cron_match = expected_value(actual_value)
                if cron_match[0]:
                    return (PASS_ICON, f"{field_name} matches cron pattern")

                try:
                    fail_string = cron_match[1]
                except UnboundLocalError:
                    fail_string = f"{field_name} does not match cron pattern: '{actual_value}' does not match '{expected_value.cron_expr}' (margin: {expected_value.minute_tolerance} min)"

                return (FAIL_ICON, fail_string)
            else:
                return (
                    FAIL_ICON,
                    f"{field_name} is not a string as expected - got {type(actual_value).__name__} with value: {actual_value}",
                )
        elif isinstance(expected_value, dict):
            """Handle dictionaries, checking first if it's a comparison operator config"""
            if (
                len(expected_value) == 2
                and "operator" in expected_value
                and "value" in expected_value
            ):
                exp_value = expected_value["value"]
                operator = expected_value["operator"]

                # Validate operator
                valid_operators = {"=", ">", "<", "!="}
                if operator not in valid_operators:
                    return (
                        FAIL_ICON,
                        f"{field_name} has invalid operator '{operator}'. Must be one of: {', '.join(valid_operators)}",
                    )

                # Convert values to numbers if both are numeric
                if isinstance(actual_value, (int, float)) and isinstance(
                    exp_value, (int, float)
                ):
                    actual_num = float(actual_value)
                    expected_num = float(exp_value)

                    if operator == ">" and actual_num > expected_num:
                        return (PASS_ICON, f"{field_name} is greater than {exp_value}")
                    elif operator == "<" and actual_num < expected_num:
                        return (PASS_ICON, f"{field_name} is less than {exp_value}")
                    elif operator == "!=" and actual_num != expected_num:
                        return (PASS_ICON, f"{field_name} is not equal to {exp_value}")
                    elif operator == "=" and actual_num == expected_num:
                        return (PASS_ICON, f"{field_name} equals {exp_value}")
                    else:
                        return (
                            FAIL_ICON,
                            f"{field_name} fails comparison - expected {operator} {exp_value}, got {actual_value}",
                        )

                # Handle string comparisons - only allow = and != operators
                elif isinstance(actual_value, str) and isinstance(exp_value, str):
                    if operator in {">", "<"}:
                        return (
                            FAIL_ICON,
                            f"{field_name} - {operator} operator cannot be used with strings",
                        )
                    elif operator == "!=" and actual_value != exp_value:
                        return (PASS_ICON, f"{field_name} is not equal to {exp_value}")
                    elif operator == "=" and actual_value == exp_value:
                        return (PASS_ICON, f"{field_name} equals {exp_value}")
                    else:
                        return (
                            FAIL_ICON,
                            f"{field_name} fails comparison - expected {operator} {exp_value}, got {actual_value}",
                        )

                return (
                    FAIL_ICON,
                    f"{field_name} comparison failed - incompatible types for comparison: {type(actual_value).__name__} vs {type(exp_value).__name__}",
                )

            # Handle regular dictionary comparison
            if not isinstance(actual_value, dict):
                return (
                    FAIL_ICON,
                    f"{field_name} is not a dict as expected - got {type(actual_value).__name__} with value: {actual_value}",
                )

            # Check for direct value comparison first
            for key, val in expected_value.items():
                if key not in actual_value:
                    return (
                        FAIL_ICON,
                        f"{field_name}.{key} missing in actual value - expected: {val}",
                    )

                # For primitive types, do direct comparison
                if not isinstance(val, (dict, list)):
                    if actual_value[key] != val:
                        return (
                            FAIL_ICON,
                            f"{field_name}.{key} has incorrect value: expected {val}, got {actual_value[key]}",
                        )
                else:
                    # For complex types, recurse
                    severity, desc = self.compare_single_field(
                        f"{field_name}.{key}", actual_value[key], val
                    )
                    if severity == FAIL_ICON:
                        # Return failure with path information preserved in desc
                        return (FAIL_ICON, desc)
                    elif severity == UNKNOWN_ICON:
                        return (UNKNOWN_ICON, desc)
                    elif severity == WARN_ICON:
                        # If we get a warning from nested comparison, propagate it up
                        return (WARN_ICON, desc)

            return (PASS_ICON, f"{field_name} matches expected dict structure")
        elif isinstance(expected_value, list):
            """
            For lists, each individual element present in expected must be in actual and match.
            If Actual has extra elements not in expected, use the Warning icon
            Order does not matter
            """
            if not isinstance(actual_value, list):
                return (
                    FAIL_ICON,
                    f"{field_name} is not a list as expected - got {type(actual_value).__name__} with value: {actual_value}",
                )
            for i, exp_item in enumerate(expected_value):
                match_found = False
                for act_item in actual_value:
                    # For dictionaries in lists, we need deeper comparison
                    if isinstance(exp_item, dict) and isinstance(act_item, dict):
                        # Check if this could be a match by comparing common keys
                        common_keys = set(exp_item.keys()) & set(act_item.keys())
                        if not common_keys:
                            continue

                        # Do a deeper comparison for dictionary items
                        all_keys_match = True
                        for k, v in exp_item.items():
                            if k not in act_item:
                                all_keys_match = False
                                break

                            # For primitive values do direct comparison
                            if not isinstance(v, (dict, list)):
                                if act_item[k] != v:
                                    all_keys_match = False
                                    break
                            else:
                                # For nested structures use recursion
                                nested_field = f"{field_name}[{i}].{k}"
                                sub_severity, _ = self.compare_single_field(
                                    nested_field, act_item[k], v
                                )
                                if sub_severity not in (PASS_ICON, WARN_ICON):
                                    all_keys_match = False
                                    break

                        if all_keys_match:
                            match_found = True
                            break

                    # For lists in lists, we need deeper comparison
                    elif isinstance(exp_item, list) and isinstance(act_item, list):
                        # Only check if lengths are same or if expected is a subset
                        if len(exp_item) > len(act_item):
                            continue

                        # For simple lists, check if all expected items are in actual
                        if all(
                            simple_item in act_item
                            for simple_item in exp_item  # pyright: ignore[reportUnknownVariableType]
                            if not isinstance(simple_item, (dict, list))
                        ):
                            # Now check complex items
                            complex_items_match = True
                            for (
                                j,
                                complex_item,  # pyright: ignore[reportUnknownVariableType]
                            ) in enumerate(
                                [  # pyright: ignore[reportUnknownArgumentType]
                                    item
                                    for item in exp_item  # pyright: ignore[reportUnknownVariableType]
                                    if isinstance(item, (dict, list))
                                ]
                            ):
                                nested_found = False
                                for (
                                    act_complex
                                ) in [  # pyright: ignore[reportUnknownVariableType]
                                    item
                                    for item in act_item  # pyright: ignore[reportUnknownVariableType]
                                    if isinstance(item, (dict, list))
                                ]:
                                    nested_field = f"{field_name}[{i}][{j}]"
                                    sub_severity, _ = self.compare_single_field(
                                        nested_field,
                                        act_complex,  # pyright: ignore[reportUnknownArgumentType]
                                        complex_item,  # pyright: ignore[reportUnknownArgumentType]
                                    )
                                    if sub_severity in (PASS_ICON, WARN_ICON):
                                        nested_found = True
                                        break
                                if not nested_found:
                                    complex_items_match = False
                                    break

                            if complex_items_match:
                                match_found = True
                                break
                    else:
                        # For primitive types
                        if act_item == exp_item:
                            match_found = True
                            break
                if not match_found:
                    # Format the error message differently based on the type of expected item
                    if isinstance(exp_item, dict):
                        return (
                            FAIL_ICON,
                            f"{field_name} missing expected item in actual list. Expected object {exp_item.get('car_name', '')} not found.",
                        )
                    elif isinstance(exp_item, list):
                        return (
                            FAIL_ICON,
                            f"{field_name} missing expected list item in actual list.",
                        )
                    else:
                        return (
                            FAIL_ICON,
                            f"{field_name} missing expected item {exp_item} in actual list.",
                        )
            if len(actual_value) > len(expected_value):
                return (
                    WARN_ICON,
                    f"{field_name} has extra items beyond expectation",
                )
            return (PASS_ICON, f"{field_name} matches expected list items")

        else:
            """For basic types, do a direct comparison"""
            if actual_value == expected_value:
                return (
                    PASS_ICON,
                    f"{field_name} matches expected value: {expected_value}",
                )
            else:
                return (
                    FAIL_ICON,
                    f"{field_name} does not match expected value - expected: {expected_value}, actual: {actual_value}",
                )

    def format_validation_results(self) -> str:
        """
        Format the validation results for the session definition.

        Returns:
            A formatted string summarizing the validation results.
        """
        results: list[str] = []
        exact = self.exact_match()
        if exact:
            results.append(f"{PASS_ICON} Exact match found for expectation.")
            results.append(f"Matched Expectation: {exact.get('name', 'Unnamed')}")
        else:
            results.append(f"{FAIL_ICON} No exact match found for any expectation.")
            for expectation in self.expectations:
                _, invalid = self.get_valid_invalid_tuple_for_expectation(expectation)
                results.append(
                    f"\n\n**Expectation: {expectation.get('name', 'Unnamed')}**"
                )
                if invalid:
                    results.append("Invalid fields:")
                    for severity, desc in invalid:
                        results.append(f"  {severity} {desc}")
        return "\n".join(results)
