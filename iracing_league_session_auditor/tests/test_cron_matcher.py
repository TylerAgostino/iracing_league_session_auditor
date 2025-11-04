"""
Tests for the CronMatcher class.

This test module verifies the functionality of the CronMatcher class
which is responsible for matching timestamps against cron expressions
with a tolerance window.
"""

# pyright: basic

import datetime
import unittest

from ..modules.cron_matcher import CronMatcher


class TestCronMatcher(unittest.TestCase):
    """Test the CronMatcher class functionality."""

    def test_init_default_values(self) -> None:
        """Test initialization with default values."""
        matcher = CronMatcher()
        self.assertEqual(matcher.cron_expr, "30 20 * * 2")
        self.assertEqual(matcher.minute_tolerance, 15)
        self.assertEqual(matcher.cron_minute, "30")
        self.assertEqual(matcher.cron_hour, "20")
        self.assertEqual(matcher.cron_dom, "*")
        self.assertEqual(matcher.cron_month, "*")
        self.assertEqual(matcher.cron_wday, "2")

    def test_init_custom_values(self) -> None:
        """Test initialization with custom values."""
        matcher = CronMatcher("15 8 * * 1,3,5", 10)
        self.assertEqual(matcher.cron_expr, "15 8 * * 1,3,5")
        self.assertEqual(matcher.minute_tolerance, 10)
        self.assertEqual(matcher.cron_minute, "15")
        self.assertEqual(matcher.cron_hour, "8")
        self.assertEqual(matcher.cron_dom, "*")
        self.assertEqual(matcher.cron_month, "*")
        self.assertEqual(matcher.cron_wday, "1,3,5")

    def test_init_invalid_cron(self) -> None:
        """Test initialization with invalid cron expression."""
        with self.assertRaises(ValueError):
            CronMatcher("15 8 * *")  # Missing field
        with self.assertRaises(ValueError):
            CronMatcher("15 8 * * 1 0")  # Extra field

    def test_parse_field_asterisk(self) -> None:
        """Test parsing a wildcard field."""
        result = CronMatcher._parse_field("*", 0, 59)
        self.assertEqual(result, set(range(0, 60)))

    def test_parse_field_single_value(self) -> None:
        """Test parsing a field with a single value."""
        result = CronMatcher._parse_field("15", 0, 59)
        self.assertEqual(result, {15})

    def test_parse_field_multiple_values(self) -> None:
        """Test parsing a field with multiple comma-separated values."""
        result = CronMatcher._parse_field("15,30,45", 0, 59)
        self.assertEqual(result, {15, 30, 45})

    def test_parse_field_range(self) -> None:
        """Test parsing a field with a range of values."""
        result = CronMatcher._parse_field("15-20", 0, 59)
        self.assertEqual(result, {15, 16, 17, 18, 19, 20})

    def test_parse_field_mixed(self) -> None:
        """Test parsing a field with a mix of ranges and individual values."""
        result = CronMatcher._parse_field("5,10-12,15", 0, 59)
        self.assertEqual(result, {5, 10, 11, 12, 15})

    def test_parse_cron_weekdays_asterisk(self) -> None:
        """Test parsing a weekday field with wildcard."""
        result = CronMatcher._parse_cron_weekdays("*")
        self.assertEqual(result, set(range(0, 7)))  # 0=Monday to 6=Sunday in Python

    def test_parse_cron_weekdays_single_value(self) -> None:
        """Test parsing a weekday field with a single value."""
        # Cron: 1=Monday, Python: 0=Monday
        result = CronMatcher._parse_cron_weekdays("1")
        self.assertEqual(result, {0})  # Monday in Python format

        # Cron: 7=Sunday (alternate notation), Python: 6=Sunday
        result = CronMatcher._parse_cron_weekdays("7")
        self.assertEqual(result, {6})  # Sunday in Python format

        # Cron: 0=Sunday, Python: 6=Sunday
        result = CronMatcher._parse_cron_weekdays("0")
        self.assertEqual(result, {6})  # Sunday in Python format

    def test_parse_cron_weekdays_multiple_values(self) -> None:
        """Test parsing a weekday field with multiple comma-separated values."""
        # Cron: 1=Monday, 3=Wednesday, 5=Friday
        # Python: 0=Monday, 2=Wednesday, 4=Friday
        result = CronMatcher._parse_cron_weekdays("1,3,5")
        self.assertEqual(
            result, {0, 2, 4}
        )  # Monday, Wednesday, Friday in Python format

    def test_parse_cron_weekdays_range(self) -> None:
        """Test parsing a weekday field with a range of values."""
        # Cron: 1=Monday through 5=Friday
        # Python: 0=Monday through 4=Friday
        result = CronMatcher._parse_cron_weekdays("1-5")
        self.assertEqual(result, {0, 1, 2, 3, 4})  # Monday to Friday in Python format

    def test_parse_cron_weekdays_mixed(self) -> None:
        """Test parsing a weekday field with a mix of ranges and individual values."""
        # Cron: 1=Monday, 3-5=Wednesday-Friday, 0=Sunday
        # Python: 0=Monday, 2-4=Wednesday-Friday, 6=Sunday
        result = CronMatcher._parse_cron_weekdays("1,3-5,0")
        self.assertEqual(
            result, {0, 2, 3, 4, 6}
        )  # Monday, Wed-Fri, Sunday in Python format

    def test_nearest_cron_time_exact_match(self) -> None:
        """Test finding the nearest cron time with an exact match."""
        # Tuesday (weekday 1 in Python) at 20:30
        matcher = CronMatcher("30 20 * * 2")  # Tuesdays at 8:30pm
        dt = datetime.datetime(
            2023, 11, 14, 20, 30, tzinfo=datetime.timezone.utc
        )  # Tue, 2023-11-14 20:30 UTC

        nearest, delta = matcher._nearest_cron_time(dt)

        self.assertEqual(nearest, dt)  # Should match exactly
        self.assertEqual(delta, 0)  # Zero minutes difference

    def test_nearest_cron_time_near_match(self) -> None:
        """Test finding the nearest cron time with a near match."""
        matcher = CronMatcher("30 20 * * 2")  # Tuesdays at 8:30pm
        dt = datetime.datetime(
            2023, 11, 14, 20, 35, tzinfo=datetime.timezone.utc
        )  # Tue, 2023-11-14 20:35 UTC (5 min after)

        nearest, delta = matcher._nearest_cron_time(dt)

        expected_nearest = datetime.datetime(
            2023, 11, 14, 20, 30, tzinfo=datetime.timezone.utc
        )  # 5 minutes earlier
        self.assertEqual(nearest, expected_nearest)
        self.assertEqual(delta, 5)  # 5 minutes difference

    def test_nearest_cron_time_different_weekday(self) -> None:
        """Test finding the nearest cron time on a different weekday."""
        matcher = CronMatcher("30 20 * * 2")  # Tuesdays at 8:30pm
        dt = datetime.datetime(
            2023, 11, 15, 20, 30, tzinfo=datetime.timezone.utc
        )  # Wed, 2023-11-15 20:30 UTC

        nearest, delta = matcher._nearest_cron_time(dt)

        # Should find either the previous Tuesday or the next Tuesday
        expected_prev = datetime.datetime(
            2023, 11, 14, 20, 30, tzinfo=datetime.timezone.utc
        )  # Previous Tue, 2023-11-14 20:30 UTC

        # It should choose the closest one (previous Tuesday)
        self.assertEqual(nearest, expected_prev)
        self.assertEqual(delta, 24 * 60)  # 24 hours = 1440 minutes

    def test_nearest_cron_time_multiple_options(self) -> None:
        """Test finding the nearest cron time with multiple weekday options."""
        matcher = CronMatcher("30 20 * * 1,3,5")  # Mon,Wed,Fri at 8:30pm
        dt = datetime.datetime(
            2023, 11, 14, 20, 30, tzinfo=datetime.timezone.utc
        )  # Tue, 2023-11-14 20:30 UTC

        nearest, delta = matcher._nearest_cron_time(dt)

        # Should find the closest among Mon,Wed,Fri
        expected_mon = datetime.datetime(
            2023, 11, 13, 20, 30, tzinfo=datetime.timezone.utc
        )  # Mon, 2023-11-13 20:30 UTC (1 day before)

        # It should choose one of the closest options (both Monday and Wednesday are 1 day away)
        # The implementation chooses the earlier date when distances are equal
        self.assertEqual(
            nearest, expected_mon
        )  # Algorithm finds Monday as it's earlier
        self.assertEqual(delta, 24 * 60)  # 24 hours = 1440 minutes

    def test_to_json(self) -> None:
        """Test the to_json method."""
        matcher = CronMatcher("15 8 * * 1,3,5", 10)
        json_data = matcher.to_json()

        self.assertEqual(
            json_data, {"cron": "15 8 * * 1,3,5", "margin": 10, "timezone": "UTC"}
        )

    def test_call_exact_match(self) -> None:
        """Test the __call__ method with an exact match."""
        matcher = CronMatcher("30 20 * * 2")  # Tuesdays at 8:30pm

        # Tuesday, 2023-11-14 20:30:00 UTC
        result, message = matcher("2023-11-14T20:30:00Z")

        self.assertTrue(result)
        self.assertIn("Launch time OK", message)
        self.assertIn("delta 0.0 min", message)

    def test_call_within_tolerance(self) -> None:
        """Test the __call__ method with a time within tolerance."""
        matcher = CronMatcher(
            "30 20 * * 2", minute_tolerance=15
        )  # Tuesdays at 8:30pm, 15 min tolerance

        # Tuesday, 2023-11-14 20:42:00 UTC (12 minutes after scheduled time)
        result, message = matcher("2023-11-14T20:42:00Z")

        self.assertTrue(result)
        self.assertIn("Launch time OK", message)
        self.assertIn("delta 12.0 min", message)

    def test_call_outside_tolerance(self) -> None:
        """Test the __call__ method with a time outside tolerance."""
        matcher = CronMatcher(
            "30 20 * * 2", minute_tolerance=15
        )  # Tuesdays at 8:30pm, 15 min tolerance

        # Tuesday, 2023-11-14 20:47:00 UTC (17 minutes after scheduled time)
        result, message = matcher("2023-11-14T20:47:00Z")

        self.assertFalse(result)
        self.assertIn("Time not within 15 min of cron", message)
        self.assertIn("delta 17.0 min", message)

    def test_call_wrong_weekday(self) -> None:
        """Test the __call__ method with the wrong weekday."""
        matcher = CronMatcher(
            "30 20 * * 2", minute_tolerance=15
        )  # Tuesdays at 8:30pm, 15 min tolerance

        # Wednesday, 2023-11-15 20:30:00 UTC (correct time, wrong day)
        result, message = matcher("2023-11-15T20:30:00Z")

        self.assertFalse(result)
        self.assertIn("Time not within 15 min of cron", message)

    def test_call_invalid_date_format(self) -> None:
        """Test the __call__ method with an invalid date format."""
        matcher = CronMatcher("30 20 * * 2")

        result, message = matcher("not-a-valid-date")

        self.assertFalse(result)
        self.assertIn("Invalid date format", message)

    def test_call_handles_different_timezone_formats(self) -> None:
        """Test that __call__ can handle different timezone formats."""
        matcher = CronMatcher("30 20 * * 2")  # Tuesdays at 8:30pm UTC

        # Same time in different timezone formats
        result1, _ = matcher("2023-11-14T20:30:00Z")  # UTC with Z
        result2, _ = matcher("2023-11-14T20:30:00+00:00")  # UTC with +00:00

        self.assertTrue(result1)
        self.assertTrue(result2)

    def test_timezone_matching(self) -> None:
        """Test that cron patterns match in the configured timezone."""
        # Configure matcher for US Eastern time, expecting 8:30pm local time
        matcher = CronMatcher(
            "30 20 * * 2", time_zone="America/New_York"
        )  # Tuesday 8:30pm ET

        # Winter time (EST = UTC-5)
        # Local: Tuesday 2024-01-09 20:30 EST
        # UTC: Wednesday 2024-01-10 01:30 UTC
        result, message = matcher("2024-01-10T01:30:00Z")
        self.assertTrue(result)
        self.assertIn("Launch time OK", message)
        self.assertIn("EST", message)  # Should show local time in messages

        # A time that's 8:30pm UTC but not 8:30pm Eastern should fail
        # UTC: Tuesday 2024-01-09 20:30 UTC
        # Local: Tuesday 2024-01-09 15:30 EST (wrong local time)
        result, message = matcher("2024-01-09T20:30:00Z")
        self.assertFalse(result)
        self.assertIn("Time not within", message)

    def test_dst_transition_handling(self) -> None:
        """Test cron matching across DST transitions."""
        # Configure for US Eastern, 8:30pm Tuesday sessions
        matcher = CronMatcher("30 20 * * 2", time_zone="America/New_York")

        # Before DST starts - Tuesday March 5, 2024 8:30pm Eastern
        # EST (UTC-5) is in effect
        result, message = matcher("2024-03-06T01:30:00Z")  # 8:30pm EST = 1:30am UTC
        self.assertTrue(result)
        self.assertIn("EST", message)

        # After DST starts (March 10, 2024) - Tuesday March 19, 2024 8:30pm Eastern
        # EDT (UTC-4) is in effect
        result, message = matcher("2024-03-20T00:30:00Z")  # 8:30pm EDT = 12:30am UTC
        self.assertTrue(result)
        self.assertIn("EDT", message)

        # Before DST ends - Tuesday Oct 29, 2024 8:30pm Eastern
        # EDT (UTC-4) is in effect
        result, message = matcher("2024-10-30T00:30:00Z")  # 8:30pm EDT = 12:30am UTC
        self.assertTrue(result)
        self.assertIn("EDT", message)

        # After DST ends (Nov 3, 2024) - Tuesday Nov 5, 2024 8:30pm Eastern
        # EST (UTC-5) is in effect
        result, message = matcher("2024-11-06T01:30:00Z")  # 8:30pm EST = 1:30am UTC
        self.assertTrue(result)
        self.assertIn("EST", message)


if __name__ == "__main__":
    unittest.main()
