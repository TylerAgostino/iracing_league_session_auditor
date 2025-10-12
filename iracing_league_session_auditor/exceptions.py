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
