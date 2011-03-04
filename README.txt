This plugin adds oAuth login capability to CKAN.  It is currently
hard-coded for a particular client (Data.NO) setup, specifically for
use with their home-brewed oAuth service, and their particular
groups-based authorization requirements.

If you'd like to use this with another oAuth service (like Twitter),
you will need to do some work to move the client-specific code out
into parameters or plugins.  This shouldn't be too difficult to do.

The plugin assumes the presence of an authz_tkt plugin in the stack
for remembering user authentication information.

Installation
------------

This package is both a CKAN Extension and a repoze.who plugin.  Most
of the heavy lifting is done in the repoze.who plugin.  The extension
just adds a dumb "login with oAuth" button to the standard Login
screen, as a demonstration of how this might be done.  Typically you
will want to create your own custom login screen.

1. Install the package as usual, e.g.

   pip install -e hg+https://bitbucket.org/sebbacon/ckanext-oauth#egg=ckanext-oauth

2. (Optionally) load the Extension, by editing your site .ini file thus:

      ckan.plugins = oauth [other-plugins-if-required]

   This is optional because you will probably want to make a
   nicer-looking login form than the one this provides (see below)

3. Configure who.ini to add the repoze.who plugin, something like:

    [plugin:oauth]
    use = ckanext.repoze.who.oauth.plugin:make_identification_plugin
    consumer_key = xxxxxxxx
    consumer_secret = xxxxxxxx
    request_token_url = https://mi.difi.no/server/oauth/request_token
    callback_url = http://localhost:5000/user/logged_in
    access_token_url = https://mi.difi.no/server/oauth/access_token
    authorize_url = https://mi.difi.no/server/oauth/authorize
    user_url = https://mi.difi.no/server/oauth/user # service that looks up user details

    [general]
    request_classifier = repoze.who.classifiers:default_request_classifier
    challenge_decider = ckanext.repoze.who.oauth.plugin:oauth_challenge_decider

    [identifiers]
    plugins =
        friendlyform;browser
        oauth
        openid
        auth_tkt

    [challengers]
    plugins =
        oauth
        openid
        friendlyform;browser
        
4. Visit the login form and try it out.

Customising
-----------

The login process is simply triggered by the existence of a POST or
GET parameter with the name "oauth_login".

The part of ```OAuthIdentifierPlugin``` that is specific to CKAN and
Data.NO is all encapsulated in the ```preauthenticate``` method.  You
are likely to want to keep the first part of this, which synchronises
the user_id received from the oAuth service with a CKAN User object.

The second part looks up a "groups" variable in the oAuth 'user'
service, and then sychronises them with authz groups in CKAN.  You may
well not need to use this sort of functionality.  If you do, note that
the current implementation assumes that group names that look like
"1234567890 Group Name" are all from the oAuth service.  This
assumption is the basis of the synchronisation logic.


Running tests
-------------

With your ckan virtualenv activated, run the following command from within pyenv/src/ckan:

    nosetests --ckan ../ckanext-oauth/tests

Note that sometimes the tests fail with a "Connection reset by peer"
error; you may have to run them a few times to get a full test run
without these (which aren't true errors; feel free to provide a patch
to work around this!)
