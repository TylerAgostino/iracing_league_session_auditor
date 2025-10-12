"""
iRacing League Session Auditor

A tool to validate and audit iRacing league sessions against expected parameters.
"""

from .modules.cron_matcher import CronMatcher
from .modules.session_validator import SessionValidator
from .exceptions import (
    VerificationRequiredException,
    UnauthorizedException,
)
from .modules.api import iRacingAPIHandler
from .modules.state_manager import StateManager
from .modules.types import SessionDefinition, ExpectationDefinition
from .modules.notifier import Notifier


__all__ = [
    "iRacingAPIHandler",
    "CronMatcher",
    "SessionValidator",
    "VerificationRequiredException",
    "UnauthorizedException",
    "StateManager",
    "SessionDefinition",
    "ExpectationDefinition",
    "Notifier",
]

__version__ = "0.1.0"
