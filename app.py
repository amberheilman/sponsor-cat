import os
import urllib

import flask
from flask import Flask
from flask_cors import CORS, cross_origin
from flask_login import LoginManager, login_user, login_required, logout_user
import psycopg2
from psycopg2.extras import RealDictCursor
from wtforms import Form, StringField, PasswordField, validators
import uuid
import waitress

app = Flask(__name__)
CORS(app)
app.conn = psycopg2.connect(os.environ['DATABASE_URL'])  # TODO: reconnect logic
app.secret_key = os.environ['SECRET_KEY']
login_manager = LoginManager()
login_manager.init_app(app)

SELECT_USER_BY_ID_SQL = 'SELECT * FROM users WHERE id=%s;'
SELECT_USER_SQL = 'SELECT id FROM users WHERE email=%s AND password=%s;'
INSERT_SPONSORSHIP = ('INSERT INTO sponsorships (id, sponsored_at, '
                      '            sponsor_amount,'
                      '            name, email, paypal_order_id,'
                      '            self_link, img)'
                      '     VALUES (%s, %s, %s, %s, %s, %s, %s, %s)')
SELECT_SPONSORSHIPS = 'SELECT * FROM sponsorships'


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
        app.logger.exception('Encountered db error while inserting sponsor')
        pass
    except Exception:
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


@cross_origin(allow_headers=['Content-Type'], methods=['POST'])
@app.route("/sponsor", methods=['POST'])
def sponsor():
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
                         body['cat_img']))
            cur.close()
    except psycopg2.Error:
        app.logger.exception('Encountered db error while inserting sponsor')
        pass
    except Exception:
        app.logger.exception('Encountered error while inserting sponsor')
        pass
    response = flask.Response('ok')
    response.headers['Access-Control-Allow-Origin'] = '*'
    return response


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
            cur.execute(SELECT_USER_SQL, (self.email, self.password))
            data = cur.fetchone()
            cur.close()
            return data[0] if data else str(uuid.uuid4())


class LoginForm(Form):
    email = StringField('Email Address', [validators.Length(min=6, max=35)])
    password = PasswordField('Password', [validators.DataRequired()])


def is_safe_url(target):
    ref_url = urllib.parse.urlparse(flask.request.host_url)
    test_url = urllib.parse.urlparse(
        urllib.parse.urljoin(flask.request.host_url, target))
    return test_url.scheme in ('http', 'https') and \
        ref_url.netloc == test_url.netloc


if __name__ == "__main__":
    waitress.serve(app)
