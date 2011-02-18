import json
import logging
from zope.interface import implements
from repoze.who.interfaces import IIdentifier
from repoze.who.interfaces import IChallenger
from repoze.who.plugins.auth_tkt import AuthTktCookiePlugin
from webob import Response
import urlparse
import oauth2 as oauth

from ckan.model import User, Session

log = logging.getLogger("ckanext.repoze")


def make_identification_plugin(**kwargs):
    return OAuthIdentifierPlugin(**kwargs)


class OAuthIdentifierPlugin(AuthTktCookiePlugin):
    implements(IIdentifier, IChallenger)

    def __init__(self,
                 consumer_key='',
                 consumer_secret='',
                 request_token_url='',
                 access_token_url='',
                 authorize_url='',
                 user_url=''):
        self.consumer_key = consumer_key
        self.consumer_secret = consumer_secret
        self.request_token_url = request_token_url
        self.access_token_url = access_token_url
        self.authorize_url = authorize_url
        self.user_url = user_url

    def _get_request_token(self):
        consumer = oauth.Consumer(self.consumer_key,
                                  self.consumer_secret)
        client = oauth.Client(consumer)
        resp, content = client.request(self.request_token_url, "GET")
        if resp['status'] != '200':
            raise Exception("Invalid response %s." % resp['status'])
        tokens = dict(urlparse.parse_qsl(content))
        request_token = tokens.get('oauth_token')
        request_token_secret = tokens.get('oauth_token_secret')
        # XXX save/cache it somehow
        logging.info("Got request token %s, secret %s from %s" % \
                     (request_token,
                      request_token_secret,
                      self.request_token_url))
        return request_token, request_token_secret

    # challenge
    def challenge(self, environ, status, app_headers, forget_headers):
        request_token, _ = self._get_request_token()
        res = Response()
        res.status = 302
        res.location = "%s?oauth_token=%s" % (self.authorize_url,
                                              request_token)
        logging.info("Challenge: Redirecting challenge to page %s" % \
                     res.location)
        return res

    # identify
    def identify(self, environ):
        # XXX commented out for testing, probably a good idea...
        #if "mi.difi.no" not in environ.get('HTTP_REFERER',''):
        #    return
        rememberer = self._get_rememberer(environ)
        identity = rememberer and rememberer.identify(environ) or {}
        logging.info("Identify: got remembered identity %r" % dict(identity))
        userdata = identity.get('userdata', '')
        found = 'oauth_token' in userdata
        #import pdb; pdb.set_trace()
        if not found:
            qstring = environ.get('QUERY_STRING')
            if not qstring:
                return None
            consumer = oauth.Consumer(self.consumer_key, self.consumer_secret)
            request_token, request_token_secret = self._get_request_token()
            oauth_verifier = dict(urlparse.parse_qsl(qstring))\
                             .get("oauth_token")
            if oauth_verifier:
                token = oauth.Token(oauth_verifier,
                                    request_token_secret)
                client = oauth.Client(consumer, token)
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
            # we set it accordingly
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
        # XXX remember/cache the authentication status for X amount of
        # time
        try:
            access_token = dict(urlparse.parse_qsl(identity['userdata']))
            oauth_token = access_token['oauth_token']
            oauth_token_secret = access_token['oauth_token_secret']
        except KeyError:
            return None
        consumer = oauth.Consumer(self.consumer_key,
                                  self.consumer_secret)
        access_token = oauth.Token(oauth_token,
                                   oauth_token_secret)
        client = oauth.Client(consumer, access_token)
        resp, content = client.request(self.user_url, "GET")
        data = json.loads(content)
        user_id = data['id']
        logging.info("Preauth: Got oauth user data for user %s" % user_id)
        #user_groups = data['groups']
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
        logging.info("Preauth: Returning user identifier %s" % user.name)
        identity['repoze.who.userid'] = user.name
        return identity

    def __repr__(self):
        return '<%s %s>' % (self.__class__.__name__, id(self))
