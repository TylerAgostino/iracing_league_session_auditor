#!/usr/bin/env python3
"""
CLI entry point for iRacing League Session Auditor
"""

import argparse
import datetime
import json
import os
import requests
import time
from pathlib import Path

from iracing_league_session_auditor.api import iRacingAPIHandler
from iracing_league_session_auditor.exceptions import (
    VerificationRequiredException,
    UnauthorizedException,
)


def main():
    """
    Main entry point for the CLI application
    """
    # Set up command line argument parsing
    parser = argparse.ArgumentParser(description="iRacing League Session Auditor")
    parser.add_argument(
        "--email", default="tyleragostino@gmail.com", help="iRacing API email"
    )
    parser.add_argument("--password", required=True, help="iRacing API password")
    parser.add_argument(
        "--state-path",
        default="state/state.json",
        help="Path to state file (default: state/state.json)",
    )
    parser.add_argument(
        "--league-id",
        type=int,
        default=8579,
        help="iRacing league ID to audit (default: 8579)",
    )
    parser.add_argument(
        "--discord-webhook", default="", help="Discord webhook URL for notifications"
    )
    parser.add_argument(
        "--single-run",
        action="store_true",
        help="Run once and exit (default: run continuously)",
    )
    parser.add_argument(
        "--wait",
        type=int,
        default=3600,
        help="Wait time in seconds between runs (default: 3600)",
    )

    args = parser.parse_args()

    # Initialize the API handler with the provided credentials and paths
    handler = iRacingAPIHandler(
        email=args.email, password=args.password, state_file_path=args.state_path
    )
    last_auth_failed = False

    while True:
        try:
            print(f"Validating sessions for league ID {args.league_id}...")
            league_sessions = handler.validate_sessions(args.league_id)
            message_content = (
                handler.format_validation_results(league_sessions)
                if league_sessions
                else False
            )
        except VerificationRequiredException as e:
            print(f"Verification required: {e}")
            if last_auth_failed:
                message_content = False
            else:
                message_content = "iRacing authentication expired. Please log in to the iRacing member site."
                last_auth_failed = True
        except UnauthorizedException as e:
            print(f"Unauthorized, re-authenticating: {e}")
            try:
                handler.login()
            except Exception as inner_e:
                print(inner_e)
                time.sleep(
                    60 * 60 * 24
                )  # Wait a day before retrying after login failure
            finally:
                message_content = False
        except Exception as e:
            print(f"Error during validation: {e}")
            message_content = False
        else:
            last_auth_failed = False

        try:
            if message_content:
                headers = {"Content-Type": "application/json"}
                print(message_content)

                # Only send to Discord if webhook provided
                if args.discord_webhook:
                    # Prepare Discord webhook payload, truncating message if needed
                    payload = {
                        "content": message_content[
                            :2000
                        ],  # Discord message limit is 2000 characters
                        "username": "iRacing Session Auditor",
                        "avatar_url": "https://cdn.discordapp.com/icons/981935710514839572/6d1658b24a272ad3e0efa97d9480fef5.png?size=320&quality=lossless",
                    }
                    wh_response = requests.post(
                        args.discord_webhook, json=payload, headers=headers
                    )
                    if wh_response.status_code == 204:
                        print("Results sent to Discord successfully.")
                    else:
                        print(
                            f"Failed to send results to Discord: {wh_response.status_code} - {wh_response.text}"
                        )
        except Exception as e:
            print(f"Error sending to Discord: {e}")

        # Exit after one run if single_run flag is set
        if args.single_run:
            print("Single run complete, exiting.")
            break

        # Schedule next run
        next_run = datetime.datetime.now() + datetime.timedelta(seconds=args.wait)
        print(f"Next check scheduled at: {next_run.strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"Waiting {args.wait} seconds...")
        time.sleep(args.wait)


if __name__ == "__main__":
    main()
