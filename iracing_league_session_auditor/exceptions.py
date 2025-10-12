"""
Custom exceptions for the iRacing League Session Auditor.
"""


class VerificationRequiredException(Exception):
    """
    Exception raised when verification is required for iRacing login.

    This typically happens when the API requires additional authentication steps
    or when the session has expired and needs to be re-established.
    """

    pass


class UnauthorizedException(Exception):
    """
    Exception raised when API requests are unauthorized.

    This typically indicates that the credentials are invalid or the session
    has expired and needs to be refreshed.
    """

    pass


class ValidationError(Exception):
    """
    Exception raised when a session fails validation.

    This is used to indicate that a session doesn't meet the expected criteria.
    """

    pass


class ConfigurationError(Exception):
    """
    Exception raised when there's an issue with the configuration.

    This could be due to missing or invalid configuration files or options.
    """

    pass
