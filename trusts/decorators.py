from functools import wraps
from urllib.parse import urlparse
from operator import and_, or_

from django.conf import settings
from django.contrib.auth import REDIRECT_FIELD_NAME
from django.contrib.auth.views import redirect_to_login
from django.core.exceptions import PermissionDenied, ObjectDoesNotExist
from django.shortcuts import resolve_url
from django.contrib.contenttypes.models import ContentType
from django.http import Http404

from trusts import utils


class P(object):
    def __init__(self, perm, **fieldlookups):
        self._perm = perm
        self._fieldlookups = fieldlookups
        self._left_operand = None
        self._right_operand = None
        self._operator = None

    def __and__(self, other):
        if not isinstance(other, self.__class__):
            raise TypeError("unsupported operand type(s) for &: '%s' and '%s'" % (type(self), type(other)))

        p = type(self)('')
        p._left_operand = self
        p._right_operand = other
        p._operator = and_
        return p

    def __or__(self, other):
        if not isinstance(other, self.__class__):
            raise TypeError("unsupported operand type(s) for |: '%s' and '%s'" % (type(self), type(other)))

        p = type(self)('')
        p._left_operand = self
        p._right_operand = other
        p._operator = or_
        return p

    def __repr__(self):
        return self.__str__()

    def __str__(self):
        if not self._operator:
            return self._perm

        return 'P object'

    def get_leaves(self):
        leaves = []
        if not self._operator:
            return [self]

        # Do not use += or leaves.extend here since it changes the original list
        leaves = leaves + self._left_operand.get_leaves()
        leaves = leaves + self._right_operand.get_leaves()

        return leaves

    def solve(self, fn):
        if self._operator:
            # Parent node, return result operation
            if self._operator == and_:
                return self._left_operand.solve(fn) and self._right_operand.solve(fn)
            elif self._operator == or_:
                return self._left_operand.solve(fn) or self._right_operand.solve(fn)
            else:
                raise TypeError('Unsupported Operator: ', self._operator)
        else:
            return fn(self._perm, **self._fieldlookups)


class R(object):
    def __init__(self, key):
        self.key = key


class K(R):
    pass


class G(R):
    pass


class O(R):
    pass


def request_passes_test(test_func, login_url=None, redirect_field_name=REDIRECT_FIELD_NAME, *args, **kwargs):
    '''
    Decorator for views that checks that the user passes the given test,
    redirecting to the log-in page if necessary. The test should be a callable
    that takes the user object and returns True if the user passes.

    Adapted from `django/contrib/auth/decorator.py`
    '''

    def decorator(view_func):
        @wraps(view_func)
        def _wrapped_view(request, *args, **kwargs):
            if test_func(request, *args, **kwargs):
                return view_func(request, *args, **kwargs)

            path = request.build_absolute_uri()
            resolved_login_url = resolve_url(login_url or settings.LOGIN_URL)
            # If the login url is the same scheme and net location then just
            # use the path as the "next" url.
            login_scheme, login_netloc = urlparse(resolved_login_url)[:2]
            current_scheme, current_netloc = urlparse(path)[:2]
            if ((not login_scheme or login_scheme == current_scheme) and
                    (not login_netloc or login_netloc == current_netloc)):
                path = request.get_full_path()
            return redirect_to_login(
                path, resolved_login_url, redirect_field_name)
        return _wrapped_view
    return decorator


def _collect_args(args, fieldlookups):
    results = {}

    if not fieldlookups:
        return results

    for lookup, arg_name in fieldlookups.items():
        if arg_name in args:
            results[lookup] = args[arg_name]
        else:
            results[lookup] = None

    return results


def _get_permissible_items(perm, request, fieldlookups):
    if fieldlookups is None:
        return None

    applabel, modelname, action, cond = utils.parse_perm_code(perm)
    try:
        ctype = ContentType.objects.get_by_natural_key(applabel, modelname)

        return ctype.model_class().objects.filter(**fieldlookups)
    except ObjectDoesNotExist:
        raise ValueError('Permission code must be of the form "app_label.action_modelname". Actual: %s' % perm)


def _resolve_fieldlookups(request, kwargs, fieldlookups_kwargs=None, fieldlookups_getparams=None, fieldlookups_postparams=None, **fieldlookups):
    resolved_fields = {}

    resolved_fields.update(_collect_args(kwargs, fieldlookups_kwargs))
    resolved_fields.update(_collect_args(request.GET, fieldlookups_getparams))
    resolved_fields.update(_collect_args(request.POST, fieldlookups_postparams, ))

    for field, lookup in fieldlookups.items():
        if isinstance(lookup, K):
            source = kwargs
        elif isinstance(lookup, G):
            source = request.GET
        elif isinstance(lookup, O):
            source = request.POST
        else:
            continue
        resolved_fields[field] = source[lookup.key] if lookup.key in source else None

    return resolved_fields or None


def _check(perm, request, kwargs, raise_exception, **fieldlookups):
    if not isinstance(perm, (list, tuple)):
        perms = (perm, )
    else:
        perms = perm

    resolved_items = _resolve_fieldlookups(request, kwargs, **fieldlookups)

    items = None
    if fieldlookups is not None:
        items = _get_permissible_items(perm, request, resolved_items)
        if items is None:
            if raise_exception:
                raise Http404
            return False

    if request.user.has_perms(perms, items):
        return True

    # In case the 403 handler should be called raise the exception
    if raise_exception:
        raise PermissionDenied
    return False


def permission_required(perm, raise_exception=True, login_url=None, **fieldlookups):
    '''
    Decorator for views that checks whether a user has a particular permission
    enabled, redirecting to the log-in page if necessary.
    If the raise_exception parameter is given the PermissionDenied exception
    is raised.

    Adapted from `django/contrib/auth/decorator.py`
    '''

    def _check_perms(request, *args, **kwargs):
        def _wrapped_check(perm, **fieldlookups):
            return _check(perm, request, kwargs, raise_exception, **fieldlookups)

        if isinstance(perm, P):
            return perm.solve(_wrapped_check)

        return _check(perm, request, kwargs, raise_exception, **fieldlookups)

    return request_passes_test(_check_perms, login_url=login_url)
