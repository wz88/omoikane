class BaseError(Exception):
    """Base error class."""


class NoRouteFound(BaseError):
    """Raised when no route is found."""