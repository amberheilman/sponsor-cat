import base64
from email.mime.text import MIMEText
import hashlib
import json
from logging.config import dictConfig
import os
import urllib

from apiclient import discovery
from cryptography.fernet import Fernet
from oauth2client.client import flow_from_clientsecrets
from google.auth.transport.requests import Request
from oauth2client.client import FlowExchangeError
import oauth2client
import flask
from flask import Flask
from flask_cors import CORS
from flask_login import LoginManager, login_user, login_required, logout_user
import psycopg2
from psycopg2.extras import RealDictCursor
from wtforms import Form, StringField, PasswordField, validators
import uuid
import waitress


app = Flask(__name__)
dictConfig({
    'version': 1,
    'formatters': {'default': {
        'format': '[%(asctime)s] %(levelname)s in %(module)s: %(message)s',
    }},
    'handlers': {'wsgi': {
        'class': 'logging.StreamHandler',
        'stream': 'ext://flask.logging.wsgi_errors_stream',
        'formatter': 'default'
    }},
    'root': {
        'level': 'INFO',
        'handlers': ['wsgi']
    }
})
app.config.from_mapping({
    "DEBUG": False,
    "PREFERRED_URL_SCHEME": "https"
})
SCHEME = os.environ.get('SCHEME', 'http')
CREDENTIALS_SECRET = os.environ.get('CREDENTIALS_SECRET', 'secret')
TRUSTED_ORIGINS = os.environ.get('TRUSTED_ORIGINS', 'localhost 127.0.0.1')
CORS(app, resources={r"/sponsor/": {"origins": TRUSTED_ORIGINS,
                                    "allowed_headers": ["content-type"]}})
app.conn = psycopg2.connect(os.environ['DATABASE_URL'])  # TODO: reconnect logic
app.secret_key = os.environ['SECRET_KEY']
login_manager = LoginManager()
login_manager.init_app(app)


SELECT_USER_BY_ID_SQL = 'SELECT * FROM users WHERE id=%s;'
SELECT_USER_SQL = 'SELECT id, password_hash, salt FROM users WHERE email=%s;'
INSERT_SPONSORSHIP = ('INSERT INTO sponsorships (id, sponsored_at, '
                      '            sponsor_amount,'
                      '            name, email, paypal_order_id,'
                      '            cat_self_link, cat_img, cat_name,'
                      '            petfinder_id)'
                      '     VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)')
SELECT_SPONSORSHIPS = 'SELECT * FROM sponsorships'
SELECT_SPONSORSHIPS_BY_ID = ('SELECT petfinder_id FROM sponsorships'
                             ' WHERE petfinder_id IN ({})')
SELECT_RECIPIENTS = "SELECT * FROM recipients WHERE email_subscription='on'"
INSERT_RECIPIENTS = ('INSERT INTO recipients (id, email, email_subscription)'
                     '     VALUES {} RETURNING *')
DROP_RECIPIENTS = 'TRUNCATE TABLE recipients'
SELECT_CREDENTIALS = 'SELECT credentials FROM credentials WHERE name = %s'
INSERT_CREDENTIALS = ('INSERT INTO credentials (name, credentials)'
                      '     VALUES (%s, %s)')
UPDATE_CREDENTIALS = 'UPDATE credentials SET credentials=%s WHERE name=%s'


@app.route("/index", methods=['GET'])
@login_required
def index():
    cats = execute_sql({'sql': SELECT_SPONSORSHIPS, 'fetchall': True},
                       cursor_factory=RealDictCursor)
    scheme = 'https' \
        if os.environ.get('ENVIRONMENT') == 'production' else 'http'
    return flask.render_template('index.html', cats=cats, scheme=scheme)


@app.route('/', methods=['GET', 'POST'])
def login():
    error = None
    form = None
    if flask.request.method == 'POST':
        form = LoginForm(formdata=flask.request.form)
        valid = form.validate()
        if valid:
            app.logger.info('validated')
            user = User(form.email.data,
                        form.password.data)
            login_user(user)

            _next = flask.request.args.get('next')
            if not is_safe_url(_next):
                return flask.abort(400)

            return flask.redirect(_next or flask.url_for('index'))
        else:
            error = 'Login failed'
            app.logger.info('login failed')
    app.logger.info('showing form')
    scheme = 'https' \
        if os.environ.get('ENVIRONMENT') == 'production' else 'http'
    return flask.render_template('login.html',
                                 form=form,
                                 scheme=scheme,
                                 _next='/',
                                 error=error)


@app.route("/sponsor", methods=['POST', 'OPTIONS'])
def sponsor():
    if flask.request.method == 'POST':
        body = flask.request.get_json()
        app.logger.debug('Received body %r', body)
        execute_sql({'sql': INSERT_SPONSORSHIP,
                     'values': (str(uuid.uuid4()),
                                body['create_time'],
                                body['sponsor_amount'],
                                body['given_name'],
                                body['email'],
                                body['paypal_order_id'],
                                body['cat_self_link'],
                                body['cat_img'],
                                body['cat_name'],
                                body['petfinder_id'])})
        send_email(body['email'], 'thank-you-email',
                   f"Thank you for sponsoring {body['cat_name']}", **body)
        recipients = ' '.join([row[1] for row in execute_sql(
            {'sql': SELECT_RECIPIENTS, 'fetchall': True})])
        send_email(recipients, 'recipient-email',
                   f"{body['cat_name']} is sponsored!", **body)

    response = flask.Response()
    response.headers['Access-Control-Allow-Origin'] = TRUSTED_ORIGINS
    response.headers['Access-Control-Allow-Headers'] = 'content-type'
    return response


@app.route("/sponsored", methods=['POST'])
def get_sponsored():
    body = flask.request.get_json()
    app.logger.debug('Received body %r', body)
    cat_ids = [int(_id) for _id in body['cat_ids']]
    sql = SELECT_SPONSORSHIPS_BY_ID.format(
        ('%s, ' * len(cat_ids)).rstrip(', '))
    data = {'cat_ids': [row[0] for row in execute_sql(
        {'sql': sql, 'values': cat_ids, 'fetchall': True})]}
    return flask.jsonify(data)


@app.route('/sponsor-emails', methods=['GET', 'POST'])
@login_required
def sponsor_emails():
    if flask.request.method == 'GET':
        recipients = [row[1] for row in execute_sql(
            {'sql': SELECT_RECIPIENTS, 'fetchall': True})]
        return flask.render_template('sponsor-emails.html',
                                     recipients=recipients)
    elif flask.request.method == 'POST':
        form = RecipientForm(formdata=flask.request.form)
        recipients = email_validator(form.recipients)
        fail_msg = None
        if recipients:
            value_stub = '(%s, %s, %s), ' * len(recipients)
            sql = INSERT_RECIPIENTS.format(value_stub.rstrip(', '))
            r = []
            for recipient in recipients:
                r.extend((str(uuid.uuid4()), recipient, 'on'))
            result = execute_sql({'sql': DROP_RECIPIENTS},
                                 {'sql': sql, 'values': r, 'fetchall': True})
            recipients = [row[1] for row in result]
        return flask.render_template('sponsor-emails.html',
                                     recipients=recipients,
                                     fail_msg=fail_msg)


def execute_sql(*sql_dict, raise_error=None, cursor_factory=None):
    result = None
    error = None
    app.logger.debug('Running query %r', sql_dict)
    try:
        with app.conn.cursor(cursor_factory=cursor_factory) as cur:
            for sql in sql_dict:
                if sql.get('values'):
                    cur.execute(sql['sql'], sql['values'])
                else:
                    cur.execute(sql['sql'])
                if sql.get('fetchall') is True:
                    result = cur.fetchall()
                elif sql.get('fetchone') is True:
                    result = cur.fetchone()
                else:
                    pass
            cur.close()
        app.conn.commit()
    except psycopg2.Error as e:
        error = e
        app.conn.rollback()
        app.logger.exception('Encountered db error sql: %r', sql_dict)
    except Exception as e:
        error = e
        app.conn.rollback()
        app.logger.exception('Encountered unknown error sql: %r', sql_dict)
    if raise_error and isinstance(error, raise_error):
        raise error
    return result


def get_credentials(token_name):
    tokens = execute_sql({'sql': SELECT_CREDENTIALS,
                          'values': [token_name],
                          'fetchone': True})
    # f = Fernet(CREDENTIALS_SECRET)
    # decrypted_tokens = base64.b64decode(f.decrypt(tokens[0].encode('utf-8')))
    decrypted_tokens = tokens[0]
    oauth2 = json.loads(decrypted_tokens)
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
    # f = Fernet(CREDENTIALS_SECRET)
    # creds = f.encrypt(base64.b64encode(credentials.to_json().encode('utf-8')))
    creds = credentials.to_json()
    try:
        execute_sql({'sql': INSERT_CREDENTIALS, 'values': [user_id, creds]},
                    raise_error=psycopg2.errors.UniqueViolation)
    except psycopg2.errors.UniqueViolation:
        # keys already exist, so update them
        app.logger.info('Duplicate key error, updating tokens')
        execute_sql({'sql': UPDATE_CREDENTIALS, 'values': [creds, user_id]})
    except Exception as e:
        app.logger.exception('EXCEPTION %s', e)


def send_email(recipients, template_name, subject, **kwargs):
    credentials = get_credentials('gmail_tokens')

    if credentials.invalid:
        if credentials and credentials.expired and credentials.refresh_token:
            credentials.refresh(Request())
        else:
            raise Exception('Do not have valid credentials for gmail!')
    service = discovery.build('gmail', 'v1', credentials=credentials)
    with open(f'templates/{template_name}.html', 'r') as f:
        # email = flask.render_template(f.read(), **kwargs)
        email = f.read()
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


def get_authorization_url(state):
    flow = flow_from_clientsecrets(
        'credentials.json',
        ' '.join(['https://www.googleapis.com/auth/gmail.compose']))
    flow.params['access_type'] = 'offline'
    flow.params['approval_prompt'] = 'force'
    flow.params['user_id'] = 'me'
    flow.params['state'] = state
    url = flask.url_for('gmail', _scheme=SCHEME, _external=True)
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
    flow.redirect_uri = flask.url_for('gmail', _scheme=SCHEME, _external=True)
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


@app.route("/logout")
@login_required
def logout():
    logout_user()
    return flask.redirect('/')


@login_manager.user_loader
def load_user(user_id):
    data = execute_sql({'sql': SELECT_USER_BY_ID_SQL, 'values': [user_id],
                        'fetchone': True})
    return User({'id': data[0],
                 'email': data[1]}) if data else None


class User:
    def __init__(self, email, password=None):
        self.email = email
        self.password = password

    @property
    def is_authenticated(self):
        return True

    @property
    def is_active(self):
        return True

    @property
    def is_anonymous(self):
        return False

    def get_id(self):
        data = execute_sql({'sql': SELECT_USER_SQL, 'values': [self.email],
                            'fetchone': True})
        if data:
            pw_hash = hashlib.sha256(
                f'{self.password}{data[2]}'.encode()).hexdigest()
            if pw_hash == data[1]:
                return data[0]
        return str(uuid.uuid4())


class LoginForm(Form):
    email = StringField('Email Address', [validators.Length(min=6, max=35)])
    password = PasswordField('Password', [validators.DataRequired()])


def email_validator(recipients):
    return [email.strip() for email in recipients.data.split(',')]


class RecipientForm(Form):
    recipients = StringField('Recipients', [])


def is_safe_url(target):
    ref_url = urllib.parse.urlparse(flask.request.host_url)
    test_url = urllib.parse.urlparse(
        urllib.parse.urljoin(flask.request.host_url, target))
    return test_url.scheme in ('http', 'https') and \
        ref_url.netloc == test_url.netloc


if __name__ == "__main__":
    waitress.serve(app, port=os.environ.get('PORT', 5000))
