import socket

import requests

from .. import app


def make_petfinder_request(url):
    try:
        token_response = requests.post(
            'https://api.petfinder.com/v2/oauth2/token',
            headers={'Content-Type': 'application/x-www-form-urlencoded'},
            data={'grant_type': 'client_credentials',
                  'client_id': app.settings['PETFINDER_CLIENT_ID'],
                  'client_secret': app.settings['PETFINDER_CLIENT_SECRET']},
            timeout=(3.05, 3))
    except (OSError, socket.error, requests.exceptions.RequestException) as e:
        app.logger.warning('Error making request to url:%r error:%r', url, e)
        return

    if token_response.status_code != 200:
        app.logger.warning('Error retrieving new token: %r',
                           token_response.content)
        return
    else:
        token = token_response.json()['access_token']
        app.logger.info('Getting url %s', url)
        response = requests.get(url,
                                headers={'Authorization': f'Bearer {token}'},
                                timeout=(3.05, 3))
        if response.status_code != 200:
            app.logger.warning('Error making request to url:%r error:%r',
                               url,
                               token_response.content)
            return
    return response.json()
