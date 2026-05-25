class DomainException(Exception):
    """Base exception for all domain logic."""

    pass


class InvalidEndpointException(DomainException):
    """Exception thrown when an API endpoint has an invalid format or URL."""

    pass


class ReaderException(DomainException):
    """Exception thrown when reading endpoints from inputs fails."""

    pass


class ExporterException(DomainException):
    """Exception thrown when exporting reports fails."""

    pass
