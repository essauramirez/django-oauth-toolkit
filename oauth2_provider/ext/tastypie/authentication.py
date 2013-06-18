from tastypie.authentication import Authentication

from ...backends import get_oauthlib_core


class OAuth2Authentication(Authentication):

    def is_authenticated(self, request, **kwargs):
        """
        Check that the access_token is valid. We don't perform any
        scope checks yet.
        """
        core = get_oauthlib_core()
        valid, req = core.verify_request(request, scopes=[])
        request.client = req.application
        request.user = req.user
        request.scopes = req.scopes

        # this is needed by django rest framework
        request.access_token = req.access_token

        return valid
