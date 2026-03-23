"""
noncey — user provisioning helpers.

Postfix alias acceptance for the nonce domain is handled at install time via a
dedicated MySQL map file (nonce_accept.cf) that returns the recipient address for
any @nonces.yourdomain.com address without per-user rows.  User create/delete is
therefore pure SQLite — no MySQL operations required here.
"""

import re

# Lowercase alphanumeric, plus hyphens, underscores, dots.
# Must start and end with a letter or digit; no consecutive dots; max 64 chars.
_USERNAME_RE = re.compile(r'^[a-z0-9]([a-z0-9._-]{0,62}[a-z0-9])?$')


class ProvisionError(Exception):
    pass


def validate_username(username: str) -> None:
    """Raise ProvisionError if username is not a safe email local-part component."""
    if not username:
        raise ProvisionError("Username must not be empty.")
    if len(username) > 64:
        raise ProvisionError("Username must be 64 characters or fewer.")
    if '..' in username:
        raise ProvisionError("Username must not contain consecutive dots.")
    if not _USERNAME_RE.match(username):
        raise ProvisionError(
            "Username may only contain lowercase letters, digits, hyphens, "
            "underscores, and dots, and must start and end with a letter or digit."
        )
