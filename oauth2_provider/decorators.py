from functools import wraps

from django.http import HttpResponseForbidden

from oauthlib.oauth2 import Server

from .oauth2_validators import OAuth2Validator
from .backends import OAuthLibCore


def protected_resource(f, scopes=None, validator_cls=OAuth2Validator, server_cls=Server):
    """
    OAuth resource decorator

    :param f: The view we are decorating
    """
    @wraps(f)
    def wrapper(request, *args, **kwargs):
        """
        Verify the resource is valid
        """
        validator = validator_cls()
        core = OAuthLibCore(server_cls(validator))

        # todo get scopes method
        valid, req = core.verify_request(request, scopes)
        if valid:
            return f(request, *args, **kwargs)
        return HttpResponseForbidden()

    return wrapper
