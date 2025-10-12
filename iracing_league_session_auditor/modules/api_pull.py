import os
from .api import iRacingAPIHandler
import requests
from pandas import DataFrame  # pyright: ignore[reportMissingTypeStubs]
from typing import cast
import json

if __name__ == "__main__":
    runtime_email = os.environ.get("IRACING_API_EMAIL", "tyleragostino@gmail.com")
    runtime_password = os.environ.get("IRACING_API_PASSWORD")
    if not runtime_email or not runtime_password:
        print(
            "Please set IRACING_API_EMAIL and IRACING_API_PASSWORD environment variables."
        )
    else:
        handler = iRacingAPIHandler(runtime_email, runtime_password)
        last_auth_failed = False
        tracks = handler._get_paged_data(  # pyright: ignore[reportPrivateUsage]
            "https://members-ng.iracing.com/data/track/get"
        )
        df: DataFrame = cast(
            DataFrame,
            DataFrame(tracks)[
                [
                    "track_name",
                    "ai_enabled",
                    "allow_rolling_start",
                    "allow_pitlane_collisions",
                    "allow_standing_start",
                    "award_exempt",
                    "banking",
                    "category",
                    "category_id",
                    "closes",
                    "config_name",
                    "corners_per_lap",
                    "created",
                    "first_sale",
                    "free_with_subscription",
                    "fully_lit",
                    "grid_stalls",
                    "has_opt_path",
                    "has_short_parade_lap",
                    "has_start_zone",
                    "has_svg_map",
                    "is_dirt",
                    "is_oval",
                    "is_ps_purchasable",
                    "lap_scoring",
                    "latitude",
                    "location",
                    "longitude",
                    "max_cars",
                    "night_lighting",
                    "nominal_lap_time",
                    "number_pitstalls",
                    "opens",
                    "package_id",
                    "pit_road_speed_limit",
                    "price",
                    "price_display",
                    "priority",
                    "purchasable",
                    "qualify_laps",
                    "restart_on_left",
                    "retired",
                    "search_filters",
                    "site_url",
                    "sku",
                    "solo_laps",
                    "start_on_left",
                    "supports_grip_compound",
                    "tech_track",
                    "time_zone",
                    "track_config_length",
                    "track_dirpath",
                    "track_id",
                ]
            ],
        )
        headers = {
            "Content-Type": "multipart/form-data",
            "Content-Disposition": 'form-data; name="files[0]"; filename="tracks.csv"',
        }

        webhook_url = os.environ.get("DISCORD_WEBHOOK_URL", "")
        with open("tracks.csv", "w", newline="", encoding="utf-8") as f:
            _ = f.write(
                df.to_csv(  # pyright: ignore[reportUnknownMemberType]
                    index=False, lineterminator="\n"
                )
            )
        with open("tracks.csv", "rb") as f:
            wh_response = requests.post(
                webhook_url,
                data={
                    "payload_json": json.dumps(
                        {
                            "content": "test",
                            "username": "Session Auditor",
                            "avatar_url": "https://cdn.discordapp.com/icons/981935710514839572/6d1658b24a272ad3e0efa97d9480fef5.png?size=320&quality=lossless",
                            "attachments": [
                                {
                                    "id": 0,
                                    "filename": "tracks.csv",
                                    "description": "Tracks",
                                }
                            ],
                        }
                    )
                },
                verify=False,
                files={"filetag": ("tracks.csv", f, "text/csv")},
            )
        if wh_response.status_code == 204:
            print("Results sent to Discord successfully.")
        else:
            print(
                f"Failed to send results to Discord: {wh_response.status_code} - {wh_response.text}"
            )
