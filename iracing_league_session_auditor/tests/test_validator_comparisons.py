import unittest
from ..modules.session_validator import SessionValidator, PASS_ICON, FAIL_ICON
from ..modules.types import ComparisonOperator


class TestSessionValidatorComparisons(unittest.TestCase):
    def setUp(self):
        self.base_session = {
            "drivers": 25,
            "temperature": 85,
            "weather_type": 2,
            "fuel": 100,
            "track_state": "clean",
            "weather": "sunny",
            "name": "Test Series",
        }
        self.validator = SessionValidator(self.base_session)

    def test_greater_than_numeric_pass(self):
        """Test greater than comparison with numeric values that should pass"""
        field_name = "drivers"
        expected = {"operator": ">", "value": 20}
        severity, message = self.validator.compare_single_field(
            field_name, self.base_session[field_name], expected
        )
        self.assertEqual(severity, PASS_ICON)
        self.assertTrue("greater than" in message.lower())

    def test_greater_than_numeric_fail(self):
        """Test greater than comparison with numeric values that should fail"""
        self.base_session["drivers"] = 15
        field_name = "drivers"
        expected = {"operator": ">", "value": 20}
        severity, message = self.validator.compare_single_field(
            field_name, self.base_session[field_name], expected
        )
        self.assertEqual(severity, FAIL_ICON)
        self.assertTrue("fails comparison" in message.lower())

    def test_less_than_numeric_pass(self):
        """Test less than comparison with numeric values that should pass"""
        field_name = "temperature"
        expected = {"operator": "<", "value": 95}
        severity, message = self.validator.compare_single_field(
            field_name, self.base_session[field_name], expected
        )
        self.assertEqual(severity, PASS_ICON)
        self.assertTrue("less than" in message.lower())

    def test_less_than_numeric_fail(self):
        """Test less than comparison with numeric values that should fail"""
        self.base_session["temperature"] = 100
        field_name = "temperature"
        expected = {"operator": "<", "value": 95}
        severity, message = self.validator.compare_single_field(
            field_name, self.base_session[field_name], expected
        )
        self.assertEqual(severity, FAIL_ICON)
        self.assertTrue("fails comparison" in message.lower())

    def test_not_equals_numeric_pass(self):
        """Test not equals comparison with numeric values that should pass"""
        field_name = "weather_type"
        expected = {"operator": "!=", "value": 3}
        severity, message = self.validator.compare_single_field(
            field_name, self.base_session[field_name], expected
        )
        self.assertEqual(severity, PASS_ICON)
        self.assertTrue("not equal" in message.lower())

    def test_not_equals_numeric_fail(self):
        """Test not equals comparison with numeric values that should fail"""
        self.base_session["weather_type"] = 3
        field_name = "weather_type"
        expected = {"operator": "!=", "value": 3}
        severity, message = self.validator.compare_single_field(
            field_name, self.base_session[field_name], expected
        )
        self.assertEqual(severity, FAIL_ICON)
        self.assertTrue("fails comparison" in message.lower())

    def test_equals_numeric_pass(self):
        """Test equals comparison with numeric values that should pass"""
        field_name = "fuel"
        expected = {"operator": "=", "value": 100}
        severity, message = self.validator.compare_single_field(
            field_name, self.base_session[field_name], expected
        )
        self.assertEqual(severity, PASS_ICON)
        self.assertTrue("equals" in message.lower())

    def test_equals_numeric_fail(self):
        """Test equals comparison with numeric values that should fail"""
        self.base_session["fuel"] = 90
        field_name = "fuel"
        expected = {"operator": "=", "value": 100}
        severity, message = self.validator.compare_single_field(
            field_name, self.base_session[field_name], expected
        )
        self.assertEqual(severity, FAIL_ICON)
        self.assertTrue("fails comparison" in message.lower())

    def test_not_equals_string_pass(self):
        """Test not equals comparison with string values that should pass"""
        field_name = "track_state"
        expected = {"operator": "!=", "value": "dusty"}
        severity, message = self.validator.compare_single_field(
            field_name, self.base_session[field_name], expected
        )
        self.assertEqual(severity, PASS_ICON)
        self.assertTrue("not equal" in message.lower())

    def test_not_equals_string_fail(self):
        """Test not equals comparison with string values that should fail"""
        self.base_session["track_state"] = "dusty"
        field_name = "track_state"
        expected = {"operator": "!=", "value": "dusty"}
        severity, message = self.validator.compare_single_field(
            field_name, self.base_session[field_name], expected
        )
        self.assertEqual(severity, FAIL_ICON)
        self.assertTrue("fails comparison" in message.lower())

    def test_equals_string_pass(self):
        """Test equals comparison with string values that should pass"""
        field_name = "weather"
        expected = {"operator": "=", "value": "sunny"}
        severity, message = self.validator.compare_single_field(
            field_name, self.base_session[field_name], expected
        )
        self.assertEqual(severity, PASS_ICON)
        self.assertTrue("equals" in message.lower())

    def test_equals_string_fail(self):
        """Test equals comparison with string values that should fail"""
        self.base_session["weather"] = "cloudy"
        field_name = "weather"
        expected = {"operator": "=", "value": "sunny"}
        severity, message = self.validator.compare_single_field(
            field_name, self.base_session[field_name], expected
        )
        self.assertEqual(severity, FAIL_ICON)
        self.assertTrue("fails comparison" in message.lower())

    def test_invalid_string_comparison(self):
        """Test that string comparisons with > or < operators are rejected"""
        field_name = "name"
        expected = {"operator": ">", "value": "Some Series"}
        severity, message = self.validator.compare_single_field(
            field_name, self.base_session[field_name], expected
        )
        self.assertEqual(severity, FAIL_ICON)
        self.assertTrue("operator cannot be used with" in message.lower())

    def test_invalid_operator(self):
        """Test that invalid operators are rejected"""
        field_name = "drivers"
        expected = {"operator": "invalid", "value": 20}
        severity, message = self.validator.compare_single_field(
            field_name, self.base_session[field_name], expected
        )
        self.assertEqual(severity, FAIL_ICON)
        self.assertTrue("invalid operator" in message.lower())

    def test_type_mismatch(self):
        """Test comparison between different types"""
        self.base_session["value"] = "25"
        field_name = "value"
        expected = {"operator": ">", "value": 20}
        severity, message = self.validator.compare_single_field(
            field_name, self.base_session[field_name], expected
        )
        self.assertEqual(severity, FAIL_ICON)
        self.assertTrue("incompatible types" in message.lower())


if __name__ == "__main__":
    unittest.main()
