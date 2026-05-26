class DomainError(Exception):
    pass


class ApiKeyInvalidaError(DomainError):
    pass


class ApiKeyExpiradaError(DomainError):
    pass


class ApiKeyDesactivadaError(DomainError):
    pass


class AfirmacionBloqueadaError(DomainError):
    pass


class AnalisisError(DomainError):
    pass
