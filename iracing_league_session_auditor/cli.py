#!/usr/bin/env python3
# pyright: basic
"""
CLI entry point for iRacing League Session Auditor
"""
from . import (
    iRacingAPIHandler,
    SessionValidator,
    StateManager,
    SessionDefinition,
    Notifier,
)
import logging
import argparse
import time

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def run_validation(
    username: str,
    password: str,
    league_id: int,
    expectations_path: str | None = None,
    state_path: str = "state.json",
    webhook_url: str | None = None,
    force: bool = False,
) -> None:
    """
    Run the session validation process.

    Args:
        username: iRacing account email
        password: iRacing account password
        expectations_path: Path to the JSON file containing expectations
        state_path: Path to the JSON file for storing state
        webhook_url: URL of the webhook to send results to
        force: If True, force re-validation of all sessions
    """
    api_handler = iRacingAPIHandler(username, password)
    sessions: list[SessionDefinition] = api_handler.get_joinable_sessions_for_league(
        league_id
    )
    logger.info(f"Found {len(sessions)} sessions for league ID {league_id}")
    with StateManager(state_path) as state_manager:
        for session in sessions:
            assert isinstance(session, dict)
            assert isinstance(session["launch_at"], str)
            id: str = session["launch_at"]
            hash = api_handler.session_hash(session)
            if state_manager.item_changed(id, hash) or force:
                if expectations_path:
                    validator = SessionValidator(
                        session, expectations_path=expectations_path
                    )
                else:
                    validator = SessionValidator(session)

                output = validator.format_validation_results()
                logger.info(
                    f"\n\n\n\nValidation results for session {session.get('session_desc', id)}:\n{output}"
                )
                if webhook_url:
                    webhook_content = {
                        "content": "",
                        "embeds": [
                            {
                                "title": f"Validation results for session {session.get('session_desc', id)}",
                                "description": output,
                                "color": 65280 if validator.exact_match() else 16711680,
                            }
                        ],
                    }
                    notifier = Notifier(webhook_url)
                    _ = notifier.send_notification(webhook_content)


def main():
    """
    Main entry point for the CLI application.

    Returns:
        int: Exit code (0 for success, non-zero for errors)
    """
    arg_parser = argparse.ArgumentParser(
        description="iRacing League Session Auditor CLI"
    )
    _ = arg_parser.add_argument(
        "--username", type=str, required=True, help="iRacing account email"
    )
    _ = arg_parser.add_argument(
        "--password", type=str, required=True, help="iRacing account password"
    )
    _ = arg_parser.add_argument(
        "--league-id", type=int, required=True, help="iRacing league ID", default=0
    )
    _ = arg_parser.add_argument(
        "--expectations-path",
        type=str,
        default=None,
        help="Path to the JSON file containing expectations",
    )
    _ = arg_parser.add_argument(
        "--state-path",
        type=str,
        default="state.json",
        help="Path to the JSON file for storing state",
    )
    _ = arg_parser.add_argument(
        "--webhook-url",
        type=str,
        default=None,
        help="URL of the webhook to send results to",
    )
    _ = arg_parser.add_argument(
        "--keep-alive",
        action="store_true",
        default=False,
        help="Keep the application running and validate periodically",
    )
    _ = arg_parser.add_argument(
        "--force",
        action="store_true",
        default=False,
        help="Force re-validation of all sessions",
    )
    _ = arg_parser.add_argument(
        "--interval",
        type=int,
        default=3600,
        help="Interval in seconds between validation runs (if not running once)",
    )
    args = arg_parser.parse_args()

    try:
        while True:
            run_validation(
                username=args.username,
                password=args.password,
                league_id=args.league_id,
                expectations_path=args.expectations_path,
                state_path=args.state_path,
                webhook_url=args.webhook_url,
                force=args.force,
            )
            if not args.keep_alive:
                break
            logger.info(f"Waiting for {args.interval} seconds before next run...")
            time.sleep(args.interval)
        return 0
    except Exception as e:
        logger.error(f"Error during execution: {e}")
        import traceback

        traceback.print_exc()
        return 1


if __name__ == "__main__":
    exit(main())
