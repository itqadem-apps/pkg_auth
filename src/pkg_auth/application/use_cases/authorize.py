from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

from ...domain.constants import ClaimSet
from ...domain.entities import AccessContext, AccessRights
from ...domain.exceptions import AuthorizationError
from ...domain.value_objects import AccessRequirement


def _claim_set_label(claim_set: ClaimSet) -> str:
    """Human-friendly names for error messages."""
    if claim_set is ClaimSet.PERMISSION:
        return "permission"
    if claim_set is ClaimSet.REALM_ROLE:
        return "realm role"
    if claim_set is ClaimSet.CLIENT_ROLE:
        return "client role"
    if claim_set is ClaimSet.SCOPE:
        return "scope"
    if claim_set is ClaimSet.AUDIENCE:
        return "audience"
    return "claim"


@dataclass(slots=True)
class AuthorizeAccessUseCase:
    """
    Application use case for authorization using declarative AccessRequirement
    objects.

    Takes:
      - an AccessContext (already authenticated)
      - an iterable of AccessRequirement objects

    and raises AuthorizationError if any requirement is not satisfied.
    """

    def _check_requirement(self, rights: AccessRights, requirement: AccessRequirement) -> None:
        claim_set = requirement.claim_set
        any_of = list(requirement.any_of)
        all_of = list(requirement.all_of)
        claim_name = _claim_set_label(claim_set)

        if any_of and not rights.contains_any(any_of, claim_set):
            raise AuthorizationError(
                f"Missing at least one required {claim_name} from: {any_of}"
            )

        if all_of and not rights.contains_all(all_of, claim_set):
            raise AuthorizationError(
                f"Missing required {claim_name}(s): {all_of}"
            )

    def execute(
            self,
            context: AccessContext,
            requirements: Iterable[AccessRequirement],
    ) -> AccessContext:
        """
        Raises:
            AuthorizationError if any of the requirements are not satisfied.

        Returns:
            The same AccessContext if authorization succeeds (for chaining).
        """
        rights = context.rights

        for requirement in requirements:
            self._check_requirement(rights, requirement)

        return context
