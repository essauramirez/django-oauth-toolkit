from tastypie.authorization import Authorization
from tastypie.exceptions import Unauthorized


class OAuth2Authorization(Authorization):
    """
    The oauth2 authorization class relies on the oauth2 authentication
    passing. If the authentication passes we know the access_token and user
    objects will be stored in the request.
    """
    scopes = []

    def __init__(self, scopes, *args, **kwargs):
        self.scopes = scopes
        super(OAuth2Authorization, self).__init__(*args, **kwargs)

    def has_permission(self, request):
        token_valid = request.access_token.is_valid(self.get_scopes())

        if not token_valid:
            return False

        return True

    def get_scopes(self):
        return self.scopes

    def read_detail(self, object_list, bundle):
        if self.has_permission(bundle.request):
            return True

        raise Unauthorized("You don't have access to this resource.")

    def read_list(self, object_list, bundle):
        if self.has_permission(bundle.request):
            return object_list

        raise Unauthorized("You don't have access to this resource.")

    def create_list(self, object_list, bundle):
        if self.has_permission(bundle.request):
            return object_list

        raise Unauthorized("You don't have access to this resource.")

    def update_list(self, object_list, bundle):
        if self.has_permission(bundle.request):
            return object_list

        raise Unauthorized("You don't have access to this resource.")

    def update_detail(self, object_list, bundle):
        if self.has_permission(bundle.request):
            return True

        raise Unauthorized("You don't have access to this resource.")

    def delete_list(self, object_list, bundle):
        if self.has_permission(bundle.request):
            return object_list

        raise Unauthorized("You don't have access to this resource.")

    def delete_detail(self, object_list, bundle):
        if self.has_permission(bundle.request):
            return True

        raise Unauthorized("You don't have access to this resource.")
