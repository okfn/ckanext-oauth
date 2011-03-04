from ckan.plugins import implements, SingletonPlugin
from ckan.plugins import IGenshiStreamFilter
from genshi.filters.transform import Transformer
from genshi.input import HTML
from ckanext.repoze.who.oauth.plugin import LOGIN_MAGIC_KEY

oauth_login = """<form action="" method="GET">
<input type="hidden" name="%s" value="1" />
<input type="submit" name="" value="login using oauth"  />
</form>
""" % LOGIN_MAGIC_KEY


class CkanOauthPlugin(SingletonPlugin):
    implements(IGenshiStreamFilter)

    def filter(self, stream):
        from pylons import request
        routes = request.environ.get('pylons.routes_dict')
        if routes.get('controller') == 'user' and \
               routes.get('action') == 'login':
            stream = stream | Transformer('//div[@id="content"]')\
                     .prepend(HTML(oauth_login))
        return stream
