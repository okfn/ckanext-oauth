import unittest

class UsersTests(unittest.TestCase):
    def _getTargetClass(self):
        from repoze.who.plugins.zodb.users import Users
        return Users

    def _makeOne(self):
        return self._getTargetClass()()

    def _verifyPassword(self, users, userid, value):
        from repoze.who.plugins.zodb.users import get_sha_password
        self.assertEqual(users.get(userid)['password'],
                         get_sha_password(value))

    def test_class_conforms_to_IUsers(self):
        from zope.interface.verify import verifyClass
        from repoze.who.plugins.zodb.interfaces import IUsers
        verifyClass(IUsers, self._getTargetClass())

    def test_instance_conforms_to_IUsers(self):
        from zope.interface.verify import verifyObject
        from repoze.who.plugins.zodb.interfaces import IUsers
        verifyObject(IUsers, self._makeOne())

    def test_add_and_remove(self):
        from repoze.who.plugins.zodb.users import get_sha_password
        users = self._makeOne()
        users.add('id', 'login', 'password', groups=['group.foo'])
        expected = {
            'id': 'id',
            'login': 'login',
            'password': get_sha_password('password'),
            'groups': set(['group.foo']),
            }
        self.assertEqual(users.logins[u'login'], u'id')
        self.assertEqual(users.data[u'id'], expected)

        users.remove('id')
        self.assertEqual(users.data.get('id'), None)
        self.assertEqual(users.logins.get(u'login'), None)

    def test_add_both_passwords(self):
        users = self._makeOne()
        self.assertRaises(ValueError, users.add, 'id', 'login',
                          cleartext_password='123', encrypted_password='123')

    def test_add_neither_password(self):
        users = self._makeOne()
        self.assertRaises(ValueError, users.add, 'id', 'login')

    def test_add_conflicting_userid(self):
        users = self._makeOne()
        users.add('id1', 'login1', 'password')
        self.assertRaises(ValueError, users.add, 'id1', 'login2', 'password')

    def test_add_conflicting_login(self):
        users = self._makeOne()
        users.add('id1', 'login1', 'password')
        self.assertRaises(ValueError, users.add, 'id2', 'login1', 'password')

    def test_encrypted(self):
        users = self._makeOne()
        users.add('id', 'login', 'password', encrypted=True)
        self.assertEqual(users.get('id')['password'], 'password')

    def test_get_userid(self):
        users = self._makeOne()
        users.add('id', 'login', 'password', groups=['group.foo'])
        self.assertEqual(users.get('id')['login'], 'login')

    def test_get_login(self):
        users = self._makeOne()
        users.add('id', 'login', 'password', groups=['group.foo'])
        self.assertEqual(users.get(login='login')['id'], 'id')

    def test_get_neither(self):
        users = self._makeOne()
        self.assertRaises(ValueError, users.get, None, None)

    def test_get_both(self):
        users = self._makeOne()
        self.assertRaises(ValueError, users.get, 'a', 'a')

    def test_get_by_id(self):
        users = self._makeOne()
        users.add('id', 'login', 'password', groups=['group.foo'])
        self.assertEqual(users.get_by_id('id')['login'], 'login')

    def test_get_by_login(self):
        users = self._makeOne()
        users.add('id', 'login', 'password', groups=['group.foo'])
        self.assertEqual(users.get_by_login('login')['id'], 'id')

    def test_change_password(self):
        users = self._makeOne()
        users.add('id', 'login', 'password', groups=['group.foo'])
        users.change_password('id', 'another')
        self._verifyPassword(users, 'id', 'another')

    def test_change_password_unicode(self):
        password = u'an\xf2ther'
        users = self._makeOne()
        users.add('id', 'login', 'password', groups=['group.foo'])
        users.change_password('id', password)
        self._verifyPassword(users, 'id', password)

    def test_change_login(self):
        users = self._makeOne()
        users.add('id', 'login', 'password', groups=['group.foo'])
        users.change_login('id', 'another')
        self.assertEqual(users.get('id')['login'], 'another')
        self.assert_(users.get_by_login('login') is None)
        self.assert_(users.get_by_login('another') is not None)
        # Password should not have changed!
        self._verifyPassword(users, 'id', 'password')

    def test_change_login_unchanged(self):
        users = self._makeOne()
        users.add('id1', 'login1', 'password')
        users.change_login('id1', 'login1')
        self.assertEqual(users.get_by_id('id1')['login'], 'login1')
        self.assert_(users.get_by_login('login1') is not None)

    def test_change_login_conflicting(self):
        users = self._makeOne()
        users.add('id1', 'login1', 'password')
        users.add('id2', 'login2', 'password')
        self.assertRaises(ValueError, users.change_login, 'id2', 'login1')

    def test_add_user_to_group(self):
        users = self._makeOne()
        users.add('id', 'login', 'password', groups=['group.foo'])
        users.add_user_to_group('id', 'another')
        self.assertEqual(users.get('id')['groups'],
                         set(['group.foo','another']))
        # Password should not have changed!
        self._verifyPassword(users, 'id', 'password')
        self.assertEqual(users.groups['another'], set(['id']))

    def test_delete_group(self):
        users = self._makeOne()
        users.add('id', 'login', 'password', groups=['group.foo', 'group.bar'])
        users.add('id2', 'login2', 'password2', groups=['group.foo'])
        users.delete_group('group.foo')
        self.assertEqual(users.get('id')['groups'], set(['group.bar']))
        self.assertEqual(users.get('id2')['groups'], set([]))
        self.failIf('group.foo' in users.groups)
        # Passwords should not have changed!
        self._verifyPassword(users, 'id', 'password')
        self._verifyPassword(users, 'id2', 'password2')

    def test_remove_user_from_group_exists(self):
        users = self._makeOne()
        users.add('id', 'login', 'password', groups=['group.foo'])
        users.remove_user_from_group('id', 'group.foo')
        self.assertEqual(users.get('id')['groups'], set())
        self.assertEqual(users.groups['group.foo'], set([]))
        # Password should not have changed!
        self._verifyPassword(users, 'id', 'password')

    def test_remove_user_from_group_notexists(self):
        users = self._makeOne()
        users.add('id', 'login', 'password', groups=[])
        users.remove_user_from_group('id', 'group.foo')
        self.assertEqual(users.get('id')['groups'], set())
        # Password should not have changed!
        self._verifyPassword(users, 'id', 'password')

    def test_remove_user_from_group_notingroups(self):
        users = self._makeOne()
        users.add('id', 'login', 'password', groups=['abc'])
        users.groups['abc'].remove('id')
        users.remove_user_from_group('id', 'abc')
        self.assertEqual(users.get('id')['groups'], set())

    def test_member_of_group(self):
        users = self._makeOne()
        users.add('id', 'login', 'password', groups=['group.foo'])
        self.assertEqual(users.member_of_group('id', 'group.foo'), True)
        self.assertEqual(users.member_of_group('id', 'group.bar'), False)

    def test_users_in_group(self):
        users = self._makeOne()
        users.add('id1', 'login1', 'password', groups=['group.foo'])
        users.add('id2', 'login2', 'password', groups=['group.foo'])
        users.add('id3', 'login3', 'password', groups=['group.none'])
        self.assertEqual(users.users_in_group('group.foo'), set(['id1', 'id2']))

    def test_users_in_group_empty_group(self):
        users = self._makeOne()
        self.assertEqual(users.users_in_group('group.foo'), set())

    def test_upgrade(self):
        from BTrees.OOBTree import OOBTree
        from repoze.who.plugins.zodb import get_sha_password
        users = self._makeOne()
        users.add('id1', 'login1', 'password1',
                  groups=['group.foo', 'group.bar'])
        users.add('id2', 'login2', 'password2',
                  groups=['group.biz', 'group.baz'])
        bylogin = OOBTree()
        for userid, info in users.data.items():
            bylogin[info['login']] = info
        users.byid = users.data
        users.bylogin = bylogin
        users.data = None
        users.groups = None
        users.logins = None
        users._upgrade()

        self.assertEqual(len(users.data), 2)

        self.assertEqual(
            users.data[u'id1'],
            {'id':'id1',
             'login':'login1',
             'password':get_sha_password('password1'),
             'groups':set([u'group.foo',
                           u'group.bar'])}
            )

        self.assertEqual(
            users.data[u'id2'],
            {'id':'id2',
             'login':'login2',
             'password':get_sha_password('password2'),
             'groups':set([u'group.biz',
                           u'group.baz'])}
            )

        self.assertEqual(len(users.logins), 2)
        self.assertEqual(users.logins[u'login1'], u'id1')
        self.assertEqual(users.logins[u'login2'], u'id2')

        self.assertEqual(len(users.groups), 4)
        self.assertEqual(users.groups[u'group.foo'], set([u'id1']))
        self.assertEqual(users.groups[u'group.bar'], set([u'id1']))
        self.assertEqual(users.groups[u'group.biz'], set([u'id2']))
        self.assertEqual(users.groups[u'group.baz'], set([u'id2']))

class TestZODBPlugin(unittest.TestCase):
    def _getTargetClass(self):
        from repoze.who.plugins.zodb import ZODBPlugin
        return ZODBPlugin

    def _makeOne(self, users):
        inst = self._getTargetClass()('whatever', lambda root: root)
        db = DummyDB(users)
        inst.dbfactory = DummyDBFactory(db)
        return inst

    def test_authenticate_no_login(self):
        users = DummyUsers()
        plugin = self._makeOne(users)
        self.assertEqual(plugin.authenticate({}, {}), None)
        self.assertEqual(users.closed, False)

    def test_authenticate_no_such_login(self):
        users = DummyUsers()
        plugin = self._makeOne(users)
        self.assertEqual(plugin.authenticate({}, {'login':'abc'}), None)
        self.assertEqual(users.closed, True)

    def test_authenticate_bad_password(self):
        users = DummyUsers(
            {'id':'id', 'login':'login', 'password':None, 'groups':set()},
            )
        plugin = self._makeOne(users)
        result = plugin.authenticate({}, {'login':'login', 'password':'123'})
        self.assertEqual(result, None)
        self.assertEqual(users.closed, True)

    def test_authenticate_good_password(self):
        from repoze.who.plugins.zodb import get_sha_password
        pwd = get_sha_password('123')
        users = DummyUsers(
            {'id':'id', 'login':'login', 'password':pwd, 'groups':set()},
            )
        plugin = self._makeOne(users)
        result = plugin.authenticate({}, {'login':'login', 'password':'123'})
        self.assertEqual(result, 'id')
        self.assertEqual(users.closed, True)

    def test_authenticate_with_close_error(self):
        users = DummyUsers()
        plugin = self._makeOne(users)
        self.assertEqual(plugin.authenticate({}, {'login':'abc'}), None)
        self.assertEqual(users.closed, True)

    def test_add_metadata(self):
        from repoze.who.plugins.zodb import get_sha_password
        pwd = get_sha_password('123')
        users = DummyUsers(
            {'id':'one', 'login':'login', 'password':pwd,
             'groups':set(['group.one', 'group.two'])},
            )
        plugin = self._makeOne(users)
        identity = {'repoze.who.userid':'one'}
        environ = {}
        plugin.add_metadata(environ, identity)
        self.assertEqual(sorted(identity['groups']), ['group.one', 'group.two'])

        identity = {'repoze.who.userid':'not_there'}
        plugin.add_metadata(environ, identity)
        self.assertEqual(identity.get('groups'), None)
        self.assertEqual(users.closed, True)

    def test_add_metadata_close_exc(self):
        from repoze.who.plugins.zodb import get_sha_password
        pwd = get_sha_password('123')
        users = DummyUsers(
            {'id':'one', 'login':'login', 'password':pwd,
             'groups':set(['group.one', 'group.two'])},
            )
        plugin = self._makeOne(users)
        identity = {'repoze.who.userid':'one'}
        environ = {}
        plugin.add_metadata(environ, identity)
        self.assertEqual(sorted(identity['groups']), ['group.one', 'group.two'])

        identity = {'repoze.who.userid':'not_there'}
        plugin.add_metadata(environ, identity)
        self.assertEqual(identity.get('groups'), None)
        self.assertEqual(users.closed, True)

    def test_no_zodb_uri_no_environ(self):
        plugin = self._getTargetClass()(None, lambda root: root)
        self.assertRaises(ValueError, plugin.get_connection, {})

    def test_no_zodb_uri_with_environ(self):
        plugin = self._getTargetClass()(None, lambda root: root)
        db = DummyDB(object())
        environ = {'repoze.zodbconn.connection': db}
        conn, from_environ = plugin.get_connection(environ)
        self.assertEqual(conn, db)
        self.assertEqual(from_environ, True)

    def test_authenticate_with_connection_from_environment(self):
        plugin = self._getTargetClass()(None, lambda root: root)
        from repoze.who.plugins.zodb import get_sha_password
        pwd = get_sha_password('123')
        users = DummyUsers(
            {'id':'id', 'login':'login', 'password':pwd, 'groups':set()},
            )
        db = DummyDB(users)
        environ = {'repoze.zodbconn.connection': db}
        identity = {'login':'login', 'password':'123'}
        result = plugin.authenticate(environ, identity)
        self.assertEqual(result, 'id')
        self.assertEqual(users.closed, False)


class TestMakePlugin(unittest.TestCase):
    def _callFUT(self, zodb_uri, users_finder):
        from repoze.who.plugins.zodb import make_plugin
        return make_plugin(zodb_uri, users_finder)

    def test_no_users_finder(self):
        self.assertRaises(ValueError, self._callFUT, 'abc', None)

    def test_it(self):
        import os
        plugin = self._callFUT('abc', 'os')
        self.assertEqual(plugin.zodb_uri, 'abc')
        self.assertEqual(plugin.users_finder, os)
        self.assertEqual(plugin.db, None)

class TestDefaultUsersFinder(unittest.TestCase):
    def _callFUT(self, root, transaction):
        from repoze.who.plugins.zodb import default_users_finder
        return default_users_finder(root, transaction)

    def test_it(self):
        class DummyTransaction:
            def commit(self):
                self.committed = True

        txn = DummyTransaction()
        root = {}
        self._callFUT(root, txn)
        self.failUnless('users' in root)
        self.assertEqual(txn.committed, True)

class TestImpersonatePlugin(unittest.TestCase):
    def _getTargetClass(self):
        from repoze.who.plugins.zodb.impersonate import ImpersonatePlugin
        return ImpersonatePlugin

    def _makeOne(self):
        plugin = self._getTargetClass()('other', 'group.admin')
        return plugin

    def _makeEnviron(self):
        return {'repoze.who.plugins': {
                'other': DummyZODBPlugin()
                }}

    def test_implements(self):
        from zope.interface.verify import verifyClass
        from repoze.who.interfaces import IAuthenticator
        klass = self._getTargetClass()
        verifyClass(IAuthenticator, klass)

    def test_factory(self):
        from repoze.who.plugins.zodb.impersonate import make_plugin
        plugin = make_plugin('other', 'group.admin')
        self.assertEqual(plugin.plugin_name, 'other')
        self.assertEqual(plugin.super_group, 'group.admin')

    def test_no_login(self):
        plugin = self._makeOne()
        environ = self._makeEnviron()
        identity = {}
        userid = plugin.authenticate(environ, identity)
        self.assertEqual(userid, None)

    def test_no_password(self):
        plugin = self._makeOne()
        environ = self._makeEnviron()
        identity = {'login': 'minion'}
        userid = plugin.authenticate(environ, identity)
        self.assertEqual(userid, None)

    def test_wrong_password(self):
        plugin = self._makeOne()
        environ = self._makeEnviron()
        identity = {'login': 'minion', 'password': 'dictator:loveme'}
        userid = plugin.authenticate(environ, identity)
        self.assertEqual(userid, None)

    def test_normal_auth(self):
        plugin = self._makeOne()
        environ = self._makeEnviron()
        identity = {'login': 'minion', 'password': 'feedme'}
        userid = plugin.authenticate(environ, identity)
        # this plugin only handles impersonation, not normal login
        self.assertEqual(userid, None)

    def test_impersonate(self):
        plugin = self._makeOne()
        environ = self._makeEnviron()
        # dictator can impersonate minion
        identity = {'login': 'minion', 'password': 'dictator:iwin'}
        userid = plugin.authenticate(environ, identity)
        self.assertEqual(userid, 'minion')

    def test_refuse_impersonate(self):
        plugin = self._makeOne()
        environ = self._makeEnviron()
        # minion can not impersonate dictator
        identity = {'login': 'dictator', 'password': 'minion:feedme'}
        userid = plugin.authenticate(environ, identity)
        self.assertEqual(userid, None)

    def test_no_impersonate_nonexistent(self):
        plugin = self._makeOne()
        environ = self._makeEnviron()
        # dictator can not impersonate someone nonexistent
        identity = {'login': 'alien', 'password': 'dictator:iwin'}
        userid = plugin.authenticate(environ, identity)
        self.assertEqual(userid, None)

    def test_with_connection_in_environ(self):
        plugin = self._makeOne()
        other = DummyZODBPlugin()
        environ = {'repoze.who.plugins': {'other': other}}
        conn = DummyDB(DummyUsers())
        environ['repoze.zodbconn.connection'] = conn
        identity = {'login': 'minion', 'password': 'dictator:iwin'}
        plugin.authenticate(environ, identity)
        self.assertEqual(other.used_environ, True)
        self.assertFalse(conn.site.closed)


class DummyUsers:
    closed = False
    def __init__(self, *users):
        self.users = users

    def get(self, userid=None, login=None):
        for user in self.users:
            if user['id'] == userid:
                return user
            if user['login'] == login:
                return user

    def in_group(self, id, group):
        for user in self.users:
            if user['id'] == id:
                return group in user['groups']
        return False

    def get_by_login(self, login):
        return self.get(login=login)

class DummyDBFactory:
    def __init__(self, db):
        self.db = db

    def __call__(self, *arg, **kw):
        return lambda *arg: self.db

class DummyDB:
    def __init__(self, site):
        self.site = site
        self.transaction_manager = self
        self.aborted = False

    def open(self):
        return self

    def root(self):
        return self.site

    def abort(self):
        self.aborted = True

    def close(self):
        from ZODB.POSException import ConnectionStateError
        if not self.aborted:
            raise ConnectionStateError
        self.site.closed = True

class DummyTransactionManager:
    def abort(self):
        pass

class DummyZODBPlugin:
    def __init__(self):
        self._default_connection = DummyDB(DummyUsers(
            {'id': 'dictator', 'login': 'dictator', 'groups': ['group.admin']},
            {'id': 'minion', 'login': 'minion', 'groups': ['group.minions']},
            ))

    def authenticate(self, environ, identity):
        self.get_connection(environ)
        login = identity.get('login')
        password = identity.get('password')
        if login == 'minion' and password == 'feedme':
            return 'minion'
        if login == 'dictator' and password == 'iwin':
            return 'dictator'
        return None

    def get_connection(self, environ):
        conn = environ.get('repoze.zodbconn.connection')
        if conn is not None:
            self.used_environ = True
            return conn, True
        else:
            self.used_environ = False
            return self._default_connection, False

    def get_users(self, conn):
        return conn.root()
