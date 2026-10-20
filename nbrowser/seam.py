from typing import Any

from .egress_guard import is_public_safe
from .errors import AuthorityRequired
from .types import EffectOperation, HostTarget


class AuthoritySeam:
    """Pre-broker effect gate."""

    def __init__(self, activation: Any) -> None:
        self.activation = activation

    def authorize_host_activation(
        self, operation: EffectOperation, url: str, interaction: Any
    ) -> HostTarget:
        from .interact import is_local_activation

        if (
            self.activation.allows_local_activation()
            and is_local_activation(interaction)
            and is_public_safe(url)
        ):
            return HostTarget(url=url)
        raise AuthorityRequired(operation, url)

    def authorize_host(self, operation: EffectOperation, url: str) -> HostTarget:
        if is_public_safe(url):
            return HostTarget(url=url)
        raise AuthorityRequired(operation, url)
