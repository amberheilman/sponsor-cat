import os
import urllib
import uuid

import arrow
import flask
from flask_login import login_user, login_required, logout_user
from psycopg2.extras import RealDictCursor
import yarl

from .. import app, login_manager
from ..db import execute_sql
from ..forms.admin import LoginForm, RecipientForm, SponsorForm
from ..lib import petfinder
from ..models.admin import User
from ..views import gmail


@app.route("/index", methods=['GET'])
@login_required
def index():
    cats = execute_sql({'sql': '   SELECT *'
                               '     FROM sponsorships'
                               ' ORDER BY sponsored_at DESC',
                        'fetchall': True},
                       cursor_factory=RealDictCursor)
    scheme = 'https' \
        if os.environ.get('ENVIRONMENT') == 'production' else 'http'
    return flask.render_template('index.html', cats=cats, scheme=scheme)


@login_manager.user_loader
def load_user(user_id):
    data = execute_sql({'sql': 'SELECT * FROM users WHERE id=%s;',
                        'values': [user_id],
                        'fetchone': True})
    return User({'id': data[0],
                 'email': data[1]}) if data else None


def is_safe_url(target):
    ref_url = urllib.parse.urlparse(flask.request.host_url)
    test_url = urllib.parse.urlparse(
        urllib.parse.urljoin(flask.request.host_url, target))
    return test_url.scheme in ('http', 'https') and \
        ref_url.netloc == test_url.netloc


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


@app.route("/logout")
@login_required
def logout():
    logout_user()
    return flask.redirect('/')


@app.route("/cat/search", methods=['GET'])
@login_required
def search():
    name = flask.request.args.get('name', '')
    if not name:
        return flask.render_template_string('<p>No Results</p>')
    url = yarl.URL(app.settings['BASE_PETFINDER_URL']).update_query(
        {'name': name})
    app.logger.debug('Finding cats by name: %r', name)
    cats = petfinder.make_petfinder_request(str(url))
    if not cats.get('animals'):
        return flask.render_template_string('<p>No Results</p>')

    app.logger.debug('Retrieved cat names: %r',
                     [cat['name'] for cat in cats['animals']])
    return flask.render_template_string(
        """
           {% for cat in cats %}
                <div class="card img-item" style="width: 18rem;">
                    {% if cat['photos'] %}
                    <img class="card-img-top" src="{{ cat['photos'][0]['medium'] }}" alt="{{ cat['name'] }}">
                    {% else %}
                    <img class="card-img-top" src="{{ url_for('static', filename='cat-solid.svg', _external=True, _scheme=scheme) }}" alt="{{ cat['name'] }}">
                    {% endif %}
                    <div class="card-body">
                    <h5 class="card-title">{{ cat['name'] }}</h5>
                    <p class="card-text">{{ cat['description'] }}</p>
                    <input type="hidden" id="cat-img" name="cat_img" value="{{ fields.get('cat_img') or '' }}">
                    <input type="hidden" id="cat-self-link" name="cat_self_link" value="{{ fields.get('cat_self_link') or '' }}">
                    <input type="hidden" id="petfinder-id" name="petfinder_id" value="{{ fields.get('petfinder_id') or '' }}">
                    {% if cat['photos'] %}
                    <div class="btn btn-primary" onclick="select_cat(this, '{{ cat['name'] }}', '{{ cat['url'] }}', '{{ cat['id'] }}', '{{ cat['photos'][0]['medium'] }}')">Select</div>
                    {% else %}
                    <div class="btn btn-primary" onclick="select_cat(this, '{{ cat['name'] }}', '{{ cat['url'] }}', '{{ cat['id'] }}', '{{ url_for('static', filename='cat-solid.svg', _external=True, _scheme=scheme) }}')">Select</div>
                    {% endif %}
                  </div>
                </div>
              {% endfor %}
        """, cats=cats['animals'], fields={})


@app.route("/sponsor", methods=['GET'])
@login_required
def get_sponsor_form():
    cats = petfinder.make_petfinder_request(app.settings['BASE_PETFINDER_URL'])
    return flask.render_template('new-sponsor.html', cats=cats['animals'],
                                 scheme=app.settings['SCHEME'])


def notify_of_sponsorship(sponsor_id, **body):
    gmail.send_email(body['email'],
                     'thank-you-email',
                     f"Thank you for sponsoring {body['cat_name']}",
                     signup_url=f'{app.settings["BASE_SPONSOR_JOURNEY_URL"]}'
                     f'/{sponsor_id}',
                     **body)
    recipients = ', '.join([row[1] for row in execute_sql(
        {'sql': "SELECT * FROM recipients WHERE email_subscription='on'",
         'fetchall': True})])
    app.logger.info('Informing recipients of sponsorship: %r', recipients)
    gmail.send_email(recipients, 'recipient-email',
                     f"{body['cat_name']} is sponsored!",
                     **body)


@app.route("/admin/sponsor", methods=['GET', 'POST'])
@login_required
def manual_sponsor():
    error = None
    fields = {}
    if flask.request.method == 'POST':
        form = SponsorForm(formdata=flask.request.form)
        app.logger.debug('form fields: %r', flask.request.form)
        valid = form.validate()
        if valid:
            body = flask.request.form
            sponsor_id = str(uuid.uuid4())
            execute_sql({'sql': 'INSERT INTO sponsorships (id, sponsored_at, '
                                '            sponsor_amount, payment_type,'
                                '            name, email, cat_self_link, '
                                '            cat_img, cat_name,'
                                '            petfinder_id)'
                                '     VALUES (%s, %s, %s, %s, %s, %s, %s,'
                                '             %s, %s, %s)',
                         'values': (sponsor_id,
                                    body.get('create_time',
                                             arrow.utcnow().isoformat()),
                                    body['sponsor_amount'],
                                    body['payment_type'],
                                    body['given_name'],
                                    body['email'],
                                    body['cat_self_link'],
                                    body['cat_img'],
                                    body['cat_name'],
                                    body['petfinder_id'])})
            notify_of_sponsorship(sponsor_id, **body)
            return flask.redirect(flask.url_for('index',
                                                _scheme=app.settings['SCHEME'],
                                                _external=True))
        else:
            error = f'Invalid submission: {form.errors}'
            app.logger.info('manual sponsorship failed: %r', form.errors)
            fields = flask.request.form
    cats = petfinder.make_petfinder_request(app.settings['BASE_PETFINDER_URL'])
    return flask.render_template('new-sponsor.html', cats=cats['animals'],
                                 _scheme=app.settings['SCHEME'],
                                 error=error,
                                 fields=fields)


def email_validator(recipients):
    return [email.strip() for email in recipients.data.split(',')]


@app.route('/sponsor-emails', methods=['GET', 'POST'])
@login_required
def sponsor_emails():
    if flask.request.method == 'GET':
        recipients = [row[1] for row in execute_sql(
            {'sql': "SELECT * FROM recipients WHERE email_subscription='on'",
             'fetchall': True})]
        return flask.render_template('sponsor-emails.html',
                                     recipients=recipients)
    elif flask.request.method == 'POST':
        form = RecipientForm(formdata=flask.request.form)
        recipients = email_validator(form.recipients)
        fail_msg = None
        if recipients:
            value_stub = '(%s, %s, %s), ' * len(recipients)
            sql = ('INSERT INTO recipients (id, email, email_subscription)'
                   '     VALUES {} RETURNING *').format(
                value_stub.rstrip(', '))
            r = []
            for recipient in recipients:
                r.extend((str(uuid.uuid4()), recipient, 'on'))
            result = execute_sql({'sql': 'TRUNCATE TABLE recipients'},
                                 {'sql': sql, 'values': r, 'fetchall': True})
            recipients = [row[1] for row in result]
        return flask.render_template('sponsor-emails.html',
                                     recipients=recipients,
                                     fail_msg=fail_msg)

