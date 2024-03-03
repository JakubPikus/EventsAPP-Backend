from rest_framework_simplejwt.tokens import RefreshToken, BlacklistMixin, Token, AccessToken
from rest_framework_simplejwt.settings import api_settings
from rest_framework_simplejwt.utils import datetime_from_epoch
from rest_framework_simplejwt.exceptions import TokenError


from .models import CustomOutstandingToken, CustomBlacklistedToken


class CustomBlacklistMixin(BlacklistMixin):

    def check_blacklist(self):
        """
        Checks if this token is present in the token blacklist.  Raises
        `TokenError` if so.
        """
        jti = self.payload[api_settings.JTI_CLAIM]

        if CustomBlacklistedToken.objects.filter(token__jti=jti).exists():
            raise TokenError(_("Token is blacklisted"))

    def blacklist(self):
        """
        Ensures this token is included in the outstanding token list and
        adds it to the blacklist.
        """

        jti = self.payload[api_settings.JTI_CLAIM]
        exp = self.payload["exp"]

        # Ensure outstanding token exists with given jti
        token, _ = CustomOutstandingToken.objects.get_or_create(
            jti=jti,
            defaults={
                "token": str(self),
                "expires_at": datetime_from_epoch(exp),
            },
        )

        return CustomBlacklistedToken.objects.get_or_create(token=token)

    """
    Adds this token to the outstanding token list.
    """

    @classmethod
    def for_user(cls, user, ip_validator):
        token = super().for_user(user)

        jti = token[api_settings.JTI_CLAIM]
        exp = token["exp"]

        CustomOutstandingToken.objects.create(
            user=user,
            jti=jti,
            token=str(token),
            created_at=token.current_time,
            expires_at=datetime_from_epoch(exp),
            ip_validator=ip_validator,
        )

        return token


class CustomRefreshToken(CustomBlacklistMixin, Token):
    token_type = "refresh"
    lifetime = api_settings.REFRESH_TOKEN_LIFETIME
    no_copy_claims = (
        api_settings.TOKEN_TYPE_CLAIM,
        "exp",
        # Both of these claims are included even though they may be the same.
        # It seems possible that a third party token might have a custom or
        # namespaced JTI claim as well as a default "jti" claim.  In that case,
        # we wouldn't want to copy either one.
        api_settings.JTI_CLAIM,
        "jti",
    )
    access_token_class = AccessToken

    @property
    def access_token(self):
        """
        Returns an access token created from this refresh token.  Copies all
        claims present in this refresh token to the new access token except
        those claims listed in the `no_copy_claims` attribute.
        """
        access = self.access_token_class()

        # Use instantiation time of refresh token as relative timestamp for
        # access token "exp" claim.  This ensures that both a refresh and
        # access token expire relative to the same time if they are created as
        # a pair.
        access.set_exp(from_time=self.current_time)

        no_copy = self.no_copy_claims
        for claim, value in self.payload.items():
            if claim in no_copy:
                continue
            access[claim] = value
        return access
