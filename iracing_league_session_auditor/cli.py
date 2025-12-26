#!/usr/bin/env python3
# pyright: basic
"""
CLI entry point for iRacing League Session Auditor
"""

import argparse
import logging
import os
import time

from . import (
    Notifier,
    SessionDefinition,
    SessionValidator,
    StateManager,
    iRacingAPIHandler,
)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def run_validation(
    league_id: int,
    expectations_path: str | None = None,
    state_path: str = "state.json",
    webhook_url: str | None = None,
    force: bool = False,
    username: str | None = None,
    password: str | None = None,
    client_id: str = "session-auditor",
    client_secret: str | None = None,
    redirect_uri: str = "http://127.0.0.1:0/callback",
    use_password_flow: bool = False,
) -> None:
    """
    Run the session validation process.

    Args:
        league_id: iRacing league ID
        expectations_path: Path to the JSON file containing expectations
        state_path: Path to the JSON file for storing state
        webhook_url: URL of the webhook to send results to
        force: If True, force re-validation of all sessions
        username: iRacing account email (required for password flow)
        password: iRacing account password (required for password flow)
        client_id: OAuth client ID (required for OAuth flows)
        client_secret: OAuth client secret (required for OAuth flows)
        redirect_uri: OAuth redirect URI
        use_password_flow: If True, use Password Limited Flow; otherwise use Authorization Code Flow
    """
    api_handler = iRacingAPIHandler(
        email=username,
        password=password,
        client_id=client_id,
        client_secret=client_secret,
        redirect_uri=redirect_uri,
        use_password_flow=use_password_flow,
    )
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
        "--league-id", type=int, required=True, help="iRacing league ID", default=0
    )

    # OAuth credentials
    _ = arg_parser.add_argument(
        "--client-id",
        type=str,
        default="session-auditor",
        help="OAuth client ID (env: IRACING_CLIENT_ID, default: session-auditor)",
    )
    _ = arg_parser.add_argument(
        "--client-secret",
        type=str,
        help="OAuth client secret (env: IRACING_CLIENT_SECRET) - optional for auth code flow",
    )
    _ = arg_parser.add_argument(
        "--redirect-uri",
        type=str,
        default="http://127.0.0.1:0/callback",
        help="OAuth redirect URI (env: IRACING_REDIRECT_URI, default: http://127.0.0.1:0/callback)",
    )

    # Password Limited Flow uses environment variables only for security
    # IRACING_USERNAME and IRACING_PASSWORD should be set via environment
    _ = arg_parser.add_argument(
        "--use-password-flow",
        action="store_true",
        default=False,
        help="Use Password Limited Flow instead of Authorization Code Flow (env: IRACING_USE_PASSWORD_FLOW)",
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

    # Determine if using password flow first
    use_password_flow = args.use_password_flow or os.environ.get(
        "IRACING_USE_PASSWORD_FLOW", ""
    ).lower() in ("true", "1", "yes")

    # Get credentials from environment variables if not provided as arguments
    # For password flow, client_id should come from args/env without default
    # For auth code flow, use 'session-auditor' as default
    if use_password_flow:
        # Password flow requires explicit client_id (no default)
        client_id = (
            args.client_id
            if args.client_id != "session-auditor"
            else os.environ.get("IRACING_CLIENT_ID")
        )
        if not client_id:
            logger.error(
                "Password Limited Flow requires explicit client_id (via --client-id or IRACING_CLIENT_ID)"
            )
            return 1
    else:
        # Auth code flow can use default
        client_id = args.client_id or os.environ.get(
            "IRACING_CLIENT_ID", "session-auditor"
        )

    client_secret = args.client_secret or os.environ.get("IRACING_CLIENT_SECRET")
    redirect_uri = args.redirect_uri or os.environ.get(
        "IRACING_REDIRECT_URI", "http://127.0.0.1:0/callback"
    )
    username = os.environ.get("IRACING_USERNAME")
    password = os.environ.get("IRACING_PASSWORD")

    # Validate credentials based on flow
    if use_password_flow:
        if not all([client_id, client_secret, username, password]):
            logger.error(
                "Password Limited Flow requires: client_id, client_secret, username, and password"
            )
            return 1

    try:
        while True:
            run_validation(
                league_id=args.league_id,
                expectations_path=args.expectations_path,
                state_path=args.state_path,
                webhook_url=args.webhook_url,
                force=args.force,
                username=username,
                password=password,
                client_id=client_id,
                client_secret=client_secret,
                redirect_uri=redirect_uri,
                use_password_flow=use_password_flow,
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
