import unittest
import json
import httplib
import BaseHTTPServer
import threading
import time

from ckanext.repoze.who.oauth.plugin import oauth_challenge_decider
from ckan.model import User, Session, AuthorizationGroup

class MockHandler(BaseHTTPServer.BaseHTTPRequestHandler):
    def do_GET(self):
        if "userinfo" in self.path:
            self.send_response(200)
            self.end_headers()
            content = json.dumps({'id': 'boz',
                                 'name': 'boz',
                                 'mail': 'baz@box.com',
                                 'groups': ['org:1234567/My group',
                                            'invalidgroup']})
        elif "usererror" in self.path:
            self.send_response(200)
            self.end_headers()
            content = json.dumps({'error': 'oops'})
        elif "server404" in self.path:
            self.send_response(404)
            self.end_headers()
            content = ""
        elif "oautherror1" in self.path:
            self.send_response(200)
            self.end_headers()
            content = ("oauth_token=oauth_token&error=oopsy&"
                       "oauth_token_secret=oauth_token_secret")
        elif "oautherror2" in self.path:
            self.send_response(200)
            self.end_headers()
            content = ("oauth_token=oauth_token&asd=123")
        else:
            self.send_response(200)
            self.end_headers()
            content = ("oauth_token=oauth_token&"
                       "oauth_token_secret=oauth_token_secret")
        self.wfile.write(content)

    def do_POST(self):
        self.do_GET()

    def do_QUIT(self):
        self.send_response(200)
        self.end_headers()
        self.server.stop = True


class ReusableServer(BaseHTTPServer.HTTPServer):
    allow_reuse_address = 1

    def serve_til_quit(self):
        self.stop = False
        while not self.stop:
            self.handle_request()


def runmockserver():
    server_address = ('localhost', 6969)
    httpd = ReusableServer(server_address,
                           MockHandler)
    httpd_thread = threading.Thread(target=httpd.serve_til_quit)
    httpd_thread.setDaemon(True)
    httpd_thread.start()
    return httpd_thread


class TestOAuthPlugin(unittest.TestCase):
    def setUp(self):
        self.http_thread = runmockserver()

    def tearDown(self):
        conn = httplib.HTTPConnection("localhost:%d" % 6969)
        conn.request("QUIT", "/")
        conn.getresponse()
        time.sleep(0.5)

    def _makeOne(self, **kwargs):
        defaults = dict(
            consumer_key="a",
            consumer_secret="b",
            request_token_url="http://localhost:6969/a",
            callback_url="http://localhost:6969/callback",
            access_token_url="http://localhost:6969/b",
            authorize_url="http://localhost:6969/c",
            user_url="http://localhost:6969/userinfo")

        from ckanext.repoze.who.oauth.plugin import make_identification_plugin
        defaults.update(**kwargs)
        return make_identification_plugin(**defaults)

    def test_identify_empty_request(self):
        plugin = self._makeOne()
        environ = {'REQUEST_METHOD': 'GET'}
        self.assertEqual(plugin.identify(environ), None)

    def test_challenge(self):
        challenge = oauth_challenge_decider(
            {'ckan.who.oauth.challenge': True},
            "200 OK",
            None)
        self.assertTrue(challenge)

        plugin = self._makeOne()
        environ = {'ckan.who.oauth.challenge': True}
        res = plugin.challenge(environ, None, None, None)
        self.assertEqual(res.status_int, 302)
        self.assert_('oauth_token' in res.location)

    def test_authenticate_step_one(self):
        plugin = self._makeOne()
        environ = {'REQUEST_METHOD': 'GET',
                   'QUERY_STRING': 'oauth_token=foo&oauth_login=1'}
        identity = plugin.identify(environ)
        self.assertTrue(identity['ckan.who.oauth.challenge'])

    def test_authenticate_step_two(self):
        plugin = self._makeOne()
        environ = {'REQUEST_METHOD': 'GET',
                   'QUERY_STRING': 'oauth_token=foo',
                   'ckan.who.oauth.challenge': '1'}
        identity = plugin.identify(environ)
        username = identity.get('repoze.who.userid')
        self.assertEqual(username, "boz")
        user = User.by_name("boz")
        self.assertEqual(user.email, 'baz@box.com')
        groups = Session.query(AuthorizationGroup)\
                 .filter(AuthorizationGroup.users.contains(user))
        self.assertEqual(groups.count(), 1)
 
    def test_404_from_oauth_server(self):
        plugin = self._makeOne(
            request_token_url="http://localhost:6969/server404")
        environ = {'REQUEST_METHOD': 'GET',
                   'QUERY_STRING': 'oauth_token=foo'}
        self.assertRaises(Exception,
                          plugin.identify,
                          environ)

    def test_user_error_from_oauth_server(self):
        plugin = self._makeOne(
            user_url="http://localhost:6969/usererror")
        environ = {'REQUEST_METHOD': 'GET',
                   'QUERY_STRING': 'oauth_token=foo'}
        self.assertRaises(KeyError,
                          plugin.identify,
                          environ)

    def test_access_error_from_oauth_server(self):
        plugin = self._makeOne(
            access_token_url="http://localhost:6969/oautherror1")
        environ = {'REQUEST_METHOD': 'GET',
                   'QUERY_STRING': 'oauth_token=foo'}
        identity = plugin.identify(environ)
        self.assertEqual(identity, None)

    def test_wierd_error_from_oauth_server(self):
        plugin = self._makeOne(
            access_token_url="http://localhost:6969/oautherror2")
        environ = {'REQUEST_METHOD': 'GET',
                   'QUERY_STRING': 'oauth_token=foo'}
        identity = plugin.identify(environ)
        self.assertEqual(identity, None)

    def test_00duplicate_authz_group(self):
        group1 = AuthorizationGroup(name="1234567 My group")
        Session.add(group1)
        Session.commit()
        group2 = AuthorizationGroup(name="1234567 My group")
        Session.add(group2)
        Session.commit()
        plugin = self._makeOne()
        environ = {'REQUEST_METHOD': 'GET',
                   'QUERY_STRING': 'oauth_token=foo',
                   'ckan.who.oauth.challenge': '1'}
        self.assertRaises(AssertionError,
                          plugin.identify,
                          environ)
        group1.delete()
        group2.delete()
        Session.commit()

    def test_remember_forget(self):
        plugin = self._makeOne()
        self.assertEqual(plugin.remember({}, {}), None)
        self.assertEqual(plugin.forget({}, {}), None)
