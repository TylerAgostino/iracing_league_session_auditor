import unittest
from auditor import iRacingAPIHandler, LaunchAtMatcher
import os
import json
from pandas import DataFrame


class TestiRacingAPIHandler(unittest.TestCase):
    def setUp(self):
        self.email = os.environ.get("IRACING_API_EMAIL", "tyleragostino@gmail.com")
        self.password = os.environ.get("IRACING_API_PASSWORD", "password")
        self.handler = iRacingAPIHandler(self.email, self.password)

    def test_login(self):
        try:
            response = self.handler.login()
            self.assertIsNotNone(response, "Login failed, response is None")
            self.assertIn(
                "authcode", response, "Login response does not contain 'authcode'"
            )
        except Exception as e:
            self.fail(f"Login raised an exception: {e}")

    def test_get_joinable_sessions_for_league(self):
        league_id = 7198
        try:
            response = self.handler.get_joinable_sessions_for_league(league_id)
            self.assertIsNotNone(
                response, "Get joinable sessions failed, response is None"
            )
            self.assertIsInstance(response, list, "Response is not a list")
        except Exception as e:
            self.fail(f"Get joinable sessions raised an exception: {e}")

    def test_validate_sessions(self):
        league_id = 8579
        try:
            results = self.handler.validate_sessions(league_id)
            self.assertIsInstance(results, list, "Validation results are not a list")
            for result in results:
                self.assertIn("✅", result) or self.assertIn(
                    "❌", result, "Validation result does not contain expected markers"
                )
        except Exception as e:
            self.fail(f"Validate sessions raised an exception: {e}")

    def test_formatted_results(self):
        league_id = 8579
        try:
            self.handler.login()
            results = self.handler.validate_sessions(league_id)
            formatted_results = self.handler.format_validation_results(results)
            self.assertIsInstance(
                formatted_results, list, "Formatted results are not a list"
            )
            for result in formatted_results:
                self.assertIn("✅", result) or self.assertIn(
                    "❌", result, "Formatted result does not contain expected markers"
                )
        except Exception as e:
            self.fail(f"Formatted results raised an exception: {e}")

    def test_get_historical_sessions(self):
        league_id = 7198#8579
        season_id = 0  # 123052
        response = self.handler._get_paged_data(
            f"https://members-ng.iracing.com/data/league/season_sessions?league_id={league_id}&season_id={season_id}"
        )
        print(json.dumps(response, indent=2))

    def test_weather(self):
        league_id = 8579  # 7198
        sessions = self.handler.get_joinable_sessions_for_league(league_id)
        sessions.reverse()
        for session in sessions:
            weather_url = session["weather"]["weather_url"]
            import requests
            from pandas import DataFrame

            weather_response = requests.get(weather_url)
            weather = weather_response.json()
            weather_df = DataFrame(weather)
            self.weather_graph(weather_df)
            print(json.dumps(weather, indent=2))

    @staticmethod
    def weather_graph(weather):
        weather_df = DataFrame(weather)
        # Generate a line chart of temp, precip, wind, and humidity over time
        import matplotlib.pyplot as plt
        import matplotlib.dates as mdates
        from pandas import to_datetime
        from matplotlib.ticker import MaxNLocator
        from io import BytesIO
        from PIL import Image
        fig, ax1 = plt.subplots(figsize=(10, 6))
        ax1.xaxis.set_major_formatter(mdates.DateFormatter("%H:%M"))
        ax1.xaxis.set_major_locator(MaxNLocator(nbins=10))
        ax1.plot(
            to_datetime(weather_df["timestamp"]),
            weather_df["air_temp"],
            "r-",
            label="Temperature (°F)",
        )
        ax1.set_xlabel("Time")
        ax1.set_ylabel("Temperature (°F)", color="r")
        ax1.tick_params(axis="y", labelcolor="r")
        ax2 = ax1.twinx()
        ax2.plot(
            to_datetime(weather_df["timestamp"]),
            weather_df["precip_chance"],
            "b-",
            label="Precipitation Chance (%)",
        )
        ax2.set_ylabel("Precipitation Chance (%)", color="b")
        ax2.tick_params(axis="y", labelcolor="b")
        ax3 = ax1.twinx()
        ax3.spines["right"].set_position(("outward", 60))
        ax3.plot(
            to_datetime(weather_df["timestamp"]),
            weather_df["rel_humidity"],
            "g-",
            label="Humidity (%)",
        )
        ax3.set_ylabel("Humidity (%)", color="g")
        ax3.tick_params(axis="y", labelcolor="g")
        ax4 = ax1.twinx()
        ax4.spines["right"].set_position(("outward", 120))
        ax4.plot(
            to_datetime(weather_df["timestamp"]),
            weather_df["wind_speed"],
            "m-",
            label="Wind Speed (mph)",
        )
        ax4.set_ylabel("Wind Speed (mph)", color="m")
        ax4.tick_params(axis="y", labelcolor="m")
        ax5 = ax1.twinx()
        ax5.spines["right"].set_position(("outward", 180))
        ax5.plot(
            to_datetime(weather_df["timestamp"]),
            weather_df["cloud_cover"],
            "m-",
            label="Cloud Cover (%)",
        )
        ax5.set_ylabel("Cloud Cover (%)", color="g")
        ax5.tick_params(axis="y", labelcolor="m")
        fig.tight_layout()
        plt.title("Weather Forecast")
        plt.legend(loc="upper left")
        buf = BytesIO()
        plt.savefig(buf, format="png")
        buf.seek(0)
        image = Image.open(buf)
        image.show()
        buf.close()


    def test_tracks(self):
        tracks = self.handler._get_paged_data("https://members-ng.iracing.com/data/track/get")
        df = DataFrame(tracks)
        spreadsheet_cols = df[['track_name', 'ai_enabled', 'allow_rolling_start', 'allow_pitlane_collisions', 'allow_standing_start', 'award_exempt', 'banking', 'category', 'category_id', 'closes', 'config_name', 'corners_per_lap', 'created', 'first_sale', 'free_with_subscription', 'fully_lit', 'grid_stalls', 'has_opt_path', 'has_short_parade_lap', 'has_start_zone', 'has_svg_map', 'is_dirt', 'is_oval', 'is_ps_purchasable', 'lap_scoring', 'latitude', 'location', 'longitude', 'max_cars', 'night_lighting', 'nominal_lap_time', 'number_pitstalls', 'opens', 'package_id', 'pit_road_speed_limit', 'price', 'price_display', 'priority', 'purchasable', 'qualify_laps', 'restart_on_left', 'retired', 'search_filters', 'site_url', 'sku', 'solo_laps', 'start_on_left', 'supports_grip_compound', 'tech_track', 'time_zone', 'track_config_length', 'track_dirpath', 'track_id']]
        with open("tracks.csv", "w") as f:
            f.write(spreadsheet_cols.to_csv(index=False, lineterminator='\n'))
        print(json.dumps(tracks, indent=2))


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
            (
                "30 0 * * 4",
                10,
                "2025-08-21T00:45:00Z",
            ),  # Wednesday at 00:45 UTC, outside tolerance
            (
                "30 0 * * 4",
                15,
                "2025-08-21T01:00:00Z",
            ),  # Wednesday at 01:00 UTC, outside tolerance
            (
                "30 0 * * 4",
                5,
                "2025-08-20T12:30:00Z",
            ),  # Tuesday at 12:30 UTC, outside tolerance
        ]
        for cron, tolerance, timestamp in cases:
            matcher = LaunchAtMatcher(cron, tolerance)
            valid, message = matcher(timestamp)
            self.assertFalse(valid, message)
