import json

from flask import Blueprint, abort, url_for, redirect, request, session, flash, \
    render_template
from flask_login import current_user, login_user
from rauth import OAuth2Service
from wtforms_components import read_only

import config
from models import User, Config
from users import RegisterForm, register_user

blueprint = Blueprint('oauth', __name__, template_folder='templates')


def json_wrapper(s):
    return json.loads(str(s).strip())


@blueprint.route('/authorize/<provider>')
def authorize(provider):
    if not current_user.is_anonymous:
        return redirect(url_for('users.login'))
    oauth = OAuthSignIn.get_provider(provider)
    if oauth is None:
        abort(404)
    return oauth.authorize()


@blueprint.route('/callback/<provider>')
def callback(provider):
    if not current_user.is_anonymous:
        return redirect(url_for('users.login'))
    oauth = OAuthSignIn.get_provider(provider)
    data = oauth.callback()
    if data.get('id') is None:
        flash('Authentication failed. %s' % data, 'danger')
        return redirect(url_for('users.login'))
    user = User.query.filter_by(**{'%s_id' % provider: data['id']}).first()
    if not user:
        session['service'] = provider
        session['%s_id' % provider] = data.get('id')
        session['email'] = data.get('email')
        session['name'] = data.get('name')
        return redirect(url_for('oauth.register'))
    login_user(user, True)
    return redirect(url_for('users.profile'))


@blueprint.route('/register', methods=['GET', 'POST'])
def register():
    register_form = RegisterForm()
    register_form.email.data = session.get('email')
    register_form.name.data = session.get('name')
    if session.get('email'):
        read_only(register_form.email)
    if register_form.validate_on_submit():
        services = dict(
            [('%s_id' % provider, session.get('%s_id' % provider)) for provider
             in config.SERVICES])
        new_user = register_user(register_form.name.data,
                                 register_form.email.data,
                                 register_form.username.data,
                                 register_form.password.data,
                                 int(register_form.level.data), admin=False,
                                 **services)
        login_user(new_user)
        return redirect(url_for("users.profile"))
    return render_template('users/register.html', service=session['service'],
                           register_form=register_form, oauth=True)


class OAuthSignIn(object):
    providers = None

    def __init__(self, provider_name):
        self.provider_name = provider_name
        credentials = dict(client_id=Config.get(("%s_ID" %
                                                 provider_name).lower()),
                           client_secret=Config.get(("%s_SECRET" %
                                                     provider_name).lower()))
        # current_app.config['OAUTH_CREDENTIALS'].get(provider_name)
        if not credentials:
            raise ValueError("No credentials.")
        self.client_id = credentials['client_id']
        self.client_secret = credentials['client_secret']

    def authorize(self):
        raise NotImplementedError()

    def callback(self):
        raise NotImplementedError()

    def get_callback_url(self):
        return url_for('oauth.callback', provider=self.provider_name,
                       _external=True)

    @classmethod
    def get_provider(cls, provider_name):
        if cls.providers is None:
            cls.providers = {}
            for provider_class in cls.__subclasses__():
                provider = provider_class()
                cls.providers[provider.provider_name] = provider
        return cls.providers.get(provider_name)


class GithubSignIn(OAuthSignIn):
    def __init__(self):
        super(GithubSignIn, self).__init__('github')
        self.service = OAuth2Service(
            name='github',
            client_id=self.client_id,
            client_secret=self.client_secret,
            authorize_url='https://github.com/login/oauth/authorize',
            access_token_url='https://github.com/login/oauth/access_token',
            base_url='https://api.github.com'
        )

    def authorize(self):
        return redirect(self.service.get_authorize_url(
            scope='user:email',
            response_type='code',
            redirect_uri=self.get_callback_url())
        )

    def callback(self):
        if 'code' not in request.args:
            return dict()
        oauth_session = self.service.get_auth_session(data=dict(
            code=request.args['code'],
            grant_type='authorization_code',
            redirect_uri=self.get_callback_url()
        ))
        emails = oauth_session.get('/user/emails').json()
        email = filter(lambda e: e['primary'], emails)[0]
        me = oauth_session.get('/user').json()
        return dict(id=int(me['id']), email=email['email'], name=me['name'])


class GoogleSignIn(OAuthSignIn):
    def __init__(self):
        super(GoogleSignIn, self).__init__('google')
        self.service = OAuth2Service(
            name='google',
            client_id=self.client_id,
            client_secret=self.client_secret,
            authorize_url='https://accounts.google.com/o/oauth2/v2/auth',
            access_token_url='https://www.googleapis.com/oauth2/v4/token',
            base_url='https://www.googleapis.com'
        )

    def authorize(self):
        return redirect(self.service.get_authorize_url(
            scope='https://www.googleapis.com/auth/userinfo.email https://www.googleapis.com/auth/userinfo.profile',
            response_type='code',
            redirect_uri=self.get_callback_url())
        )

    def callback(self):
        if 'code' not in request.args:
            return dict()
        oauth_session = self.service.get_auth_session(data=dict(
            code=request.args['code'],
            grant_type='authorization_code',
            redirect_uri=self.get_callback_url()
        ), decoder=json_wrapper)
        me = oauth_session.get('/userinfo/v2/me').json()
        return dict(id=int(me['id']), email=me['email'], name=me['name'])
