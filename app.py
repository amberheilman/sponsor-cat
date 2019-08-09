import hashlib
from logging.config import dictConfig
import os
import urllib

import flask
from flask import Flask
from flask_cors import CORS
from flask_login import LoginManager, login_user, login_required, logout_user
import psycopg2
from psycopg2.extras import RealDictCursor
import requests
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


@app.route("/index", methods=['GET'])
@login_required
def index():
    cats = None
    try:
        with app.conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(SELECT_SPONSORSHIPS)
            cats = cur.fetchall()
            cur.close()
    except psycopg2.Error:
        app.conn.rollback()
        app.logger.exception('Encountered db error while inserting sponsor')
        pass
    except Exception:
        app.conn.rollback()
        app.logger.exception('Encountered error while inserting sponsor')
        pass
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
        try:
            with app.conn.cursor() as cur:
                cur.execute(INSERT_SPONSORSHIP,
                            (str(uuid.uuid4()),
                             body['create_time'],
                             body['sponsor_amount'],
                             body['given_name'],
                             body['email'],
                             body['paypal_order_id'],
                             body['cat_self_link'],
                             body['cat_img'],
                             body['cat_name'],
                             body['petfinder_id']))
                cur.close()
            app.conn.commit()
        except psycopg2.Error:
            app.conn.rollback()
            app.logger.exception('Encountered db error while inserting sponsor')
            pass
        except Exception:
            app.conn.rollback()
            app.logger.exception('Encountered error while inserting sponsor')
            pass

        recipients = [row[1] for row in execute_sql(
            {'sql': SELECT_RECIPIENTS, 'fetchall': True})]
        send_simple_message(recipients, cat_name=body['cat_name'], **body)

    response = flask.Response()
    response.headers['Access-Control-Allow-Origin'] = TRUSTED_ORIGINS
    response.headers['Access-Control-Allow-Headers'] = 'content-type'
    return response


@app.route("/sponsored", methods=['POST'])
def get_sponsored():
    body = flask.request.get_json()
    app.logger.debug('Received body %r', body)
    cat_ids = [int(_id) for _id in body['cat_ids']]
    sql = SELECT_SPONSORSHIPS_BY_ID.format(('%s, ' * len(cat_ids)).rstrip(', '))
    data = {'cat_ids': []}
    try:
        with app.conn.cursor() as cur:
            cur.execute(sql, cat_ids)
            data['cat_ids'].extend([row[0] for row in cur.fetchall()])
        app.conn.commit()
    except psycopg2.Error:
        app.conn.rollback()
        app.logger.exception('Encountered db error while inserting sponsor')
        pass
    except Exception:
        app.conn.rollback()
        app.logger.exception('Encountered error while inserting sponsor')
        pass
    return flask.jsonify(data)


@app.route('/sponsor-emails', methods=['GET', 'POST'])
@login_required
def sponsor_emails():
    recipients = []
    if flask.request.method == 'GET':
        try:
            with app.conn.cursor() as cur:
                cur.execute(SELECT_RECIPIENTS)
                recipients = [row[1] for row in cur.fetchall()]
                cur.close()
            app.conn.commit()
        except psycopg2.Error:
            app.conn.rollback()
            app.logger.exception('Encountered db error while inserting sponsor')
            pass
        except Exception:
            app.conn.rollback()
            app.logger.exception('Encountered error while inserting sponsor')
            pass
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


def execute_sql(*sql_dict):
    result = None
    try:
        with app.conn.cursor() as cur:
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
        app.conn.rollback()
        app.logger.exception('Encountered db error while inserting sponsor')
        pass
    except Exception as e:
        app.conn.rollback()
        app.logger.exception('Encountered error while inserting sponsor')
        pass
    return result


def send_simple_message(recipients, cat_name, **kwargs):
    try:
        response = requests.post(
            'https://api.mailgun.net/v3/sandbox17b468264b55449886dc'
            'a2ef5e962fbc.mailgun.org/messages',
            auth=('api', os.environ['MAILGUN_API_KEY']),
            data={'from': 'Sponsor Cat <mailgun@sandbox17b468264b55449886d'
                          'ca2ef5e962fbc.mailgun.org>',
                  'to': recipients,
                  'subject': f'{cat_name} sponsorship',
                  'text': f"sponsor amount: {kwargs['sponsor_amount']}"
                  f"cat link: {kwargs['cat_self_link']}"})
        app.logger.info('Mailgun response: %s', response.json())
    except Exception as e:
        app.logger.warning('Failed to make mailgun request: %s', e)


@app.route("/logout")
@login_required
def logout():
    logout_user()
    return flask.redirect('/')


@login_manager.user_loader
def load_user(user_id):
    with app.conn.cursor() as cur:
        cur.execute(SELECT_USER_BY_ID_SQL, (user_id,))
        # TODO: error handling
        data = cur.fetchone()
        cur.close()
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
        with app.conn.cursor() as cur:
            cur.execute(SELECT_USER_SQL, (self.email,))
            data = cur.fetchone()
            cur.close()
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
