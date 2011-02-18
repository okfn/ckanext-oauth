import unittest
import json
import httplib
import BaseHTTPServer
import threading


class MockHandler(BaseHTTPServer.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.end_headers()
        if "userinfo" in self.path:
            content = json.dumps({'id': 'boz',
                                 'name': 'boz',
                                 'mail': 'baz@box.com'})
        else:
            content = ("oauth_token=oauth_token&"
                       "oauth_token_secret=oauth_token_secret")
        self.wfile.write(content)

    def do_POST(self):
        return self.do_GET()

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

    def _getTargetClass(self):
        from ckanext.repoze.who.oauth import OAuthIdentifierPlugin
        return OAuthIdentifierPlugin(
            consumer_key="a",
            consumer_secret="b",
            request_token_url="http://localhost:6969/a",
            access_token_url="http://localhost:6969/b",
            authorize_url="http://localhost:6969/c",
            user_url="http://localhost:6969/userinfo")

    def _makeOne(self):
        inst = self._getTargetClass()
        return inst

    def test_authenticate_no_login(self):
        plugin = self._makeOne()
        self.assertEqual(plugin.authenticate({}, {}), None)

    def test_identify_empty_request(self):
        plugin = self._makeOne()
        environ = {}
        self.assertEqual(plugin.identify(environ), None)

    def test_identify(self):
        plugin = self._makeOne()
        environ = {'QUERY_STRING': 'oauth_token=foo'}
        identity = plugin.identify(environ)
        self.assertEqual(identity['repoze.who.userid'], 'oauth_token')

    def test_challenge(self):
        plugin = self._makeOne()
        res = plugin.challenge(None, None, None, None)
        self.assertEqual(res.status_int, 302)
        self.assert_('oauth_token' in res.location)

    def test_authenticate(self):
        plugin = self._makeOne()
        environ = {'QUERY_STRING': 'oauth_token=foo'}
        identity = plugin.identify(environ)
        username = plugin.authenticate(environ, identity)
        self.assertEqual(username, "boz")
        
