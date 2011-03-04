import json
import logging
import urlparse
import re

from zope.interface import implements, directlyProvides
from webob import Request, Response
from repoze.who.interfaces import IIdentifier
from repoze.who.interfaces import IChallenger
from repoze.who.plugins.auth_tkt import AuthTktCookiePlugin
from repoze.who.interfaces import IChallengeDecider

from ckan import model
from ckan.model import User, Session, AuthorizationGroup
from ckan.model.authorization_group import add_user_to_authorization_group
from ckan.model.authorization_group import remove_user_from_authorization_group

log = logging.getLogger("ckanext.repoze")
LOGIN_MAGIC_KEY = "oauth_login"


def make_identification_plugin(**kwargs):
    return OAuthIdentifierPlugin(**kwargs)


class OAuthIdentifierPlugin(AuthTktCookiePlugin):
    implements(IIdentifier, IChallenger)

    def __init__(self,
                 consumer_key='',
                 consumer_secret='',
                 request_token_url='',
                 callback_url='',
                 access_token_url='',
                 authorize_url='',
                 user_url=''):
        import oauth2 as oauth
        self.consumer_key = consumer_key
        self.consumer_secret = consumer_secret
        self.request_token_url = request_token_url
        self.callback_url = callback_url
        self.access_token_url = access_token_url
        self.authorize_url = authorize_url
        self.user_url = user_url
        self.consumer = oauth.Consumer(self.consumer_key,
                                       self.consumer_secret)
        self.client = oauth.Client(self.consumer)

    def _get_request_token(self):
        request_plus_callback = "%s?oauth_callback=%s" % \
                                (self.request_token_url,
                                 self.callback_url)
        resp, content = self.client.request(request_plus_callback, "GET")
        if resp['status'] != '200':
            raise Exception("Invalid response %s." % resp['status'])
        tokens = dict(urlparse.parse_qsl(content))
        request_token = tokens.get('oauth_token')
        request_token_secret = tokens.get('oauth_token_secret')
        logging.info("Got request token %s, secret %s from %s" % \
                     (request_token,
                      request_token_secret,
                      self.request_token_url))
        return request_token, request_token_secret

    def challenge(self, environ, status, app_headers, forget_headers):
        if environ.get('ckan.who.oauth.challenge'):
            del(environ['ckan.who.oauth.challenge'])
        request_token, _ = self._get_request_token()
        res = Response()
        res.status = 302
        res.location = "%s?oauth_token=%s" % (self.authorize_url,
                                              request_token)
        logging.info("Challenge: Redirecting challenge to page %s" % \
                     res.location)
        return res

    def identify(self, environ):
        import oauth2 as oauth
        rememberer = self._get_rememberer(environ)
        identity = rememberer and rememberer.identify(environ) or {}
        logging.info("Identify: got remembered identity %r" % dict(identity))
        request = Request(environ)
        if request.params.get(LOGIN_MAGIC_KEY):
            # XXX I believe that in repoze.who 2.x this can be
            # replaced with an IAPI call
            environ['ckan.who.oauth.challenge'] = True
            identity['ckan.who.oauth.challenge'] = True
            return identity
        userdata = identity.get('userdata', '')
        found = 'oauth_token' in userdata
        if not found:
            qstring = environ.get('QUERY_STRING')
            if not qstring:
                return None
            request_token, request_token_secret = self._get_request_token()
            oauth_verifier = dict(urlparse.parse_qsl(qstring))\
                             .get("oauth_token")
            if oauth_verifier:
                token = oauth.Token(oauth_verifier,
                                    request_token_secret)
                client = oauth.Client(self.consumer, token)
                resp, content = client.request(self.access_token_url, "POST")
                tokens = dict(urlparse.parse_qsl(content))
                if 'error' not in tokens:
                    identity = {'userdata': content,
                                'ckan.who.oauth_token': tokens['oauth_token']}
                    logging.info("Identify: Made identity %r" % identity)
                else:
                    logging.warn("Identify: Problem with token %r" % tokens)
        if identity.get('ckan.who.oauth_token')\
               and 'repoze.who.userid' not in identity:
            # this key indicates the user is "pre-authenticated";
            # we set it accordingly.  XXX this is repoze.who 1.x
            # style; in 2.x auth_tkt is an IAuthenticator, instead of
            # relying on this magic value
            if environ.get('ckan.who.oauth.challenge'):
                del(environ['ckan.who.oauth.challenge'])
            identity = self.preauthenticate(environ, identity)
        return identity or None

    def _get_rememberer(self, environ):
        plugins = environ.get('repoze.who.plugins', {})
        return plugins.get('auth_tkt')

    def remember(self, environ, identity):
        rememberer = self._get_rememberer(environ)
        logging.info("Remembering %r" % identity)
        return rememberer and rememberer.remember(environ, identity)

    def forget(self, environ, identity):
        rememberer = self._get_rememberer(environ)
        logging.info("Forgetting %r" % identity)
        return rememberer and rememberer.forget(environ, identity)

    def preauthenticate(self, environ, identity):
        # turn the oauth identity into a CKAN one; set it in our identity
        import oauth2 as oauth
        try:
            access_token = dict(urlparse.parse_qsl(identity['userdata']))
            oauth_token = access_token['oauth_token']
            oauth_token_secret = access_token['oauth_token_secret']
        except KeyError:
            return None
        access_token = oauth.Token(oauth_token,
                                   oauth_token_secret)
        client = oauth.Client(self.consumer, access_token)
        resp, content = client.request(self.user_url, "GET")
        data = json.loads(content)
        user_id = data['id']
        logging.info("Preauth: Got oauth user data for user %s" % user_id)
        user = User.by_openid(user_id)
        if user is None:
            user = User(openid=user_id,
                        name=data['name'],
                        fullname=data['name'],
                        email=data['mail'])
            Session.add(user)
            Session.commit()
            Session.remove()
            logging.info("Preauth: Created new user %s" % user_id)
        # deal with groups
        user_groups = data['groups']
        _sync_auth_groups(user, user_groups)
        logging.info("Preauth: Returning user identifier %s" % user.name)
        identity['repoze.who.userid'] = user.name
        return identity

    def __repr__(self):
        return '<%s %s>' % (self.__class__.__name__, id(self))


def _sync_auth_groups(user, groups):
    group_pattern = re.compile(r"^(org:)?([0-9]+)[/ ](.+)$")
    # remove all user groups that originate from oauth service
    current_groups = Session.query(AuthorizationGroup)\
                     .filter(AuthorizationGroup.users.contains(user))
    for group in current_groups:
        if group_pattern.match(group.name):
            remove_user_from_authorization_group(user, group)
    # and create/add the relevant ones
    for group in groups:
        match = group_pattern.match(group)
        if not match:
            continue
        _, group_id, group_name = match.groups()
        authz_group_name = "%s %s" % (group_id, group_name)
        # create an authzgroup if it doesn't exist
        q = Session.query(AuthorizationGroup)
        q = q.filter_by(name=authz_group_name)
        if q.count() == 0:
            authz_group = AuthorizationGroup(name=authz_group_name)
            model.Session.add(authz_group)
            model.Session.commit()
            model.Session.remove()
            authz_group = Session.query(AuthorizationGroup)\
                          .filter_by(name=authz_group_name)\
                          .all()[0]
            logging.info("Created new auth group %s" % group_name)
        elif q.count() == 1:
            authz_group = q.all()[0]
        else:
            raise AssertionError("More than one matching authz group")
        add_user_to_authorization_group(user,
                                        authz_group,
                                        model.Role.ADMIN)
        model.Session.commit()
        model.Session.remove()
        logging.info("Added user %s to auth group %s" % (user.name,
                                                         authz_group.name))


def oauth_challenge_decider(environ, status, headers):
    # we do the default if it's a 401, probably we show a form then
    if status.startswith('401 '):
        return True
    elif 'ckan.who.oauth.challenge' in environ:
        # in case IIdentification found an oauth path it should be in
        # the environ and we do the challenge
        return True
    elif 'repoze.whoplugins.openid.openid' in environ:
        # handle the openid plugin too
        return True

    return False

directlyProvides(oauth_challenge_decider, IChallengeDecider)
