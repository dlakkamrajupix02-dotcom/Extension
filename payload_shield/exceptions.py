"""
Custom Exceptions for Payload Shield.
"""

class PayloadShieldException(Exception):
    """Base exception for Payload Shield errors."""
    pass

class HandshakeError(PayloadShieldException):
    """Raised when key exchange/handshake fails."""
    pass

class KeyExpiredError(PayloadShieldException):
    """Raised when session key has expired or is invalid."""
    pass

class PayloadDecryptionError(PayloadShieldException):
    """Raised when incoming payload decryption fails or fails integrity check."""
    pass
