import base64
from email.mime.text import MIMEText
import json

from apiclient import discovery
from cryptography.fernet import Fernet
import flask
from flask_login import login_required
from google.auth.transport.requests import Request
import oauth2client
from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
import psycopg2

from .. import app
from ..db import execute_sql


def create_secrets_file(token_name):
    f = Fernet(app.settings['CREDENTIALS_SECRET'])
    tokens = execute_sql({'sql': 'SELECT credentials'
                                 '  FROM credentials '
                                 ' WHERE name = %s',
                          'values': [token_name],
                          'fetchone': True})
    if tokens:
        with open('credentials.json', 'w+') as creds_file:
            decrypted_tokens = json.loads(f.decrypt(tokens[0].encode('utf-8')))
            json.dump(decrypted_tokens, creds_file)


def get_credentials(token_name):
    tokens = execute_sql({'sql': 'SELECT credentials'
                                 '  FROM credentials'
                                 ' WHERE name = %s',
                          'values': [token_name],
                          'fetchone': True})
    f = Fernet(app.settings['CREDENTIALS_SECRET'])
    oauth2 = json.loads(f.decrypt(tokens[0].encode('utf-8')))
    return oauth2client.client.OAuth2Credentials(
        oauth2['access_token'],
        oauth2['client_id'],
        oauth2['client_secret'],
        oauth2['refresh_token'],
        oauth2['token_expiry'],
        oauth2['token_uri'],
        oauth2['user_agent'],
        oauth2['revoke_uri'],
        oauth2['id_token'],
        oauth2['token_response'],
        oauth2['scopes'],
        oauth2['token_info_uri'],
        oauth2['id_token_jwt'])


def store_credentials(user_id, credentials):
    f = Fernet(app.settings['CREDENTIALS_SECRET'])
    creds = f.encrypt(credentials.to_json().encode('utf-8')).decode('utf-8')
    try:
        execute_sql({'sql': 'INSERT INTO credentials'
                            '            (name, credentials, modified_at)'
                            '     VALUES (%s, %s, now())',
                     'values': [user_id, creds]},
                    raise_error=psycopg2.errors.UniqueViolation)
    except psycopg2.errors.UniqueViolation:
        # keys already exist, so update them
        app.logger.info('Duplicate key error, updating tokens')
        execute_sql({'sql': 'UPDATE credentials'
                            '   SET credentials=%s'
                            ' WHERE name=%s', 'values': [creds, user_id]})
    except Exception as e:
        app.logger.exception('EXCEPTION %s', e)


def get_authorization_url(state):
    flow = flow_from_clientsecrets(
        'credentials.json',
        ' '.join(['https://www.googleapis.com/auth/gmail.compose']))
    flow.params['access_type'] = 'offline'
    flow.params['approval_prompt'] = 'force'
    flow.params['user_id'] = 'me'
    flow.params['state'] = state
    url = flask.url_for('gmail',
                        _scheme=app.settings['SCHEME'],
                        _external=True)
    app.logger.info(url)
    return flow.step1_get_authorize_url(url)


class GetCredentialsException(Exception):
    def __init__(self, authorization_url):
        """Construct a GetCredentialsException."""
        self.authorization_url = authorization_url


class CodeExchangeException(GetCredentialsException):
    """Error raised when a code exchange has failed."""


class NoRefreshTokenException(GetCredentialsException):
    """Error raised when no refresh token has been found."""


class NoUserIdException(Exception):
    """Error raised when no user ID could be retrieved."""


def exchange_code(authorization_code):
    flow = flow_from_clientsecrets(
        'credentials.json',
        ' '.join(['https://www.googleapis.com/auth/gmail.compose']))
    flow.redirect_uri = flask.url_for('gmail',
                                      _scheme=app.settings['SCHEME'],
                                      _external=True)
    try:
        credentials = flow.step2_exchange(authorization_code)
        return credentials
    except FlowExchangeError as error:
        app.logger.error('An error occurred: %s', error)
        raise CodeExchangeException(None)


def get_gmail_credentials(authorization_code, state):
    try:
        credentials = exchange_code(authorization_code)
        user_id = 'gmail_tokens'
        if credentials.refresh_token is not None:
            store_credentials(user_id, credentials)
            return credentials
        else:
            credentials = get_credentials(user_id)
            if credentials and credentials.refresh_token is not None:
                return credentials
    except CodeExchangeException as error:
        app.logger.error('An error occurred during code exchange.')
        error.authorization_url = get_authorization_url(state)
        raise error
    except NoUserIdException:
        app.logger.error('No user ID could be retrieved.')
        # No refresh token has been retrieved.
        authorization_url = get_authorization_url(state)
        raise NoRefreshTokenException(authorization_url)


def send_email(recipients, template_name, subject, **kwargs):
    credentials = get_credentials('gmail_tokens')
    if credentials.invalid:
        if credentials and credentials.expired and credentials.refresh_token:
            credentials.refresh(Request())
        else:
            raise Exception('Do not have valid credentials for gmail!')
    service = discovery.build('gmail', 'v1', credentials=credentials,
                              cache_discovery=False)
    with open(f'templates/{template_name}.html', 'r') as f:
        email = f.read().format(**kwargs)
    message = MIMEText(email, 'html')
    message['to'] = recipients
    message['from'] = 'Sponsor Cat <straycatblues.sponsorcat@gmail.com>'
    message['subject'] = subject
    body = {'raw': base64.urlsafe_b64encode(
        message.as_bytes()).decode('utf-8')}
    try:
        service.users().messages().send(userId='me', body=body).execute()
    except Exception as e:
        app.logger.warning('Failed to make gmail request: %s', e)


@app.route("/gmail")
@login_required
def gmail():
    code = flask.request.args.get('code')
    state = flask.request.args.get('state')
    if code:
        get_gmail_credentials(code, state)
        return flask.render_template_string('<html>Connected!</html>')

    authorization_url = get_authorization_url('state')
    return flask.redirect(authorization_url)
