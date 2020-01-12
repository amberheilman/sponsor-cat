import atexit
import datetime
from logging.config import dictConfig
import os

from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.interval import IntervalTrigger
from flask import Flask
from flask_cors import CORS
from flask_login import LoginManager

from pytz import utc
import sentry_sdk
from sentry_sdk.integrations.flask import FlaskIntegration
import waitress
import yarl

from .db import execute_sql
from .views import cron, gmail

SENTRY_DSN = os.environ.get('SENTRY_DSN')
if SENTRY_DSN:
    sentry_sdk.init(
        dsn=SENTRY_DSN,
        integrations=[FlaskIntegration()]
    )
app = Flask(__name__)

scheduler = BackgroundScheduler(daemon=True,
                                timezone=utc)
# Shutdown your cron thread if the web process is stopped
atexit.register(lambda: scheduler.shutdown(wait=False))

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
SCHEME = os.environ.get('SCHEME', 'https')
BASE_PETFINDER_URL = yarl.URL(
    'https://api.petfinder.com/v2/animals').with_query(
    {'organization': 'PA16', 'status': 'adoptable'})
BASE_SPONSOR_JOURNEY_URL = os.environ.get('BASE_SPONSOR_JOURNEY_URL',
                                          'http://localhost:9999')
PETFINDER_CLIENT_ID = os.environ['PETFINDER_CLIENT_ID']
PETFINDER_CLIENT_SECRET = os.environ['PETFINDER_CLIENT_SECRET']
CREDENTIALS_SECRET = os.environ.get('CREDENTIALS_SECRET', 'secret')
TRUSTED_ORIGINS = os.environ.get('TRUSTED_ORIGINS', 'localhost 127.0.0.1')
CORS(app, resources={r"/sponsor": {"origins": TRUSTED_ORIGINS,
                                   "allowed_headers": ["content-type"]}})

app.secret_key = os.environ['SECRET_KEY']
login_manager = LoginManager()
login_manager.init_app(app)


gmail.create_secrets_file('gmail_secrets')
scheduler.add_job(func=cron.process_adopted,
                  trigger=IntervalTrigger(
                      hours=24,
                      start_date=datetime.datetime.utcnow().replace(
                          hour=12,
                          minute=0,
                          second=0,
                          microsecond=0,
                          tzinfo=utc)),
                  name='adopted-cron',
                  replace_existing=True,
                  max_instances=1)
app.logger.info('starting scheduler')
scheduler.start()
scheduler.print_jobs()
waitress.serve(app, port=os.environ.get('PORT', 5000))
