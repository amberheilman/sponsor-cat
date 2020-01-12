import uuid

import flask

from .. import app
from ..db import execute_sql
from ..views import gmail


@app.route("/intent", methods=['POST', 'OPTIONS'])
def intent():
    if flask.request.method == 'POST':
        body = flask.request.get_json()
        app.logger.debug('Received intent: %r', body)
        execute_sql({'sql': 'INSERT INTO intents (id, sponsored_at, '
                            '            sponsor_amount,'
                            '            cat_self_link, cat_img, cat_name,'
                            '            petfinder_id)'
                            '     VALUES (%s, %s, %s, %s, %s, %s, %s)',
                     'values': (body['intent_id'],
                                body['create_time'],
                                body['sponsor_amount'],
                                body['cat_self_link'],
                                body['cat_img'],
                                body['cat_name'],
                                body['petfinder_id'])})
    response = flask.Response()
    response.headers[
        'Access-Control-Allow-Origin'] = app.settings['TRUSTED_ORIGINS']
    response.headers['Access-Control-Allow-Headers'] = 'content-type'
    return response


@app.route("/sponsor", methods=['POST', 'OPTIONS'])
def sponsor():
    if flask.request.method == 'POST':
        body = flask.request.get_json()
        app.logger.debug('Received body %r', body)
        sponsor_id = str(uuid.uuid4())
        execute_sql({'sql': 'INSERT INTO sponsorships (id, sponsored_at, '
                            '            sponsor_amount,'
                            '            name, email, paypal_order_id,'
                            '            cat_self_link, cat_img, cat_name,'
                            '            petfinder_id)'
                            '     VALUES (%s, %s, %s, %s, %s, %s, '
                            '             %s, %s, %s, %s)',
                     'values': (sponsor_id,
                                body['create_time'],
                                body['sponsor_amount'],
                                body['given_name'],
                                body['email'],
                                body['paypal_order_id'],
                                body['cat_self_link'],
                                body['cat_img'],
                                body['cat_name'],
                                body['petfinder_id'])})
        gmail.send_email(
            body['email'],
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

    response = flask.Response()
    response.headers[
        'Access-Control-Allow-Origin'] = app.settings['TRUSTED_ORIGINS']
    response.headers['Access-Control-Allow-Headers'] = 'content-type'
    return response


@app.route("/sponsored", methods=['POST'])
def get_sponsored():
    body = flask.request.get_json()
    app.logger.debug('Received body %r', body)
    cat_ids = [int(_id) for _id in body['cat_ids']]
    sql = ('SELECT petfinder_id FROM sponsorships'
           ' WHERE petfinder_id IN ({})').format(
        ('%s, ' * len(cat_ids)).rstrip(', '))
    data = {'cat_ids': [row[0] for row in execute_sql(
        {'sql': sql, 'values': cat_ids, 'fetchall': True})]}
    return flask.jsonify(data)
