#!/usr/bin/env python2.7
import collections
import datetime
import hashlib
import hmac
import json
import logging
import os
import warnings

from flask import Flask, current_app, redirect, request
from google.appengine.api import memcache, urlfetch
from jwt import encode, register_algorithm, unregister_algorithm
from jwt.contrib.algorithms.pycrypto import RSAAlgorithm
from dateutil.parser import isoparse
from dateutil.tz import UTC
from werkzeug.exceptions import BadRequest


CHECK_NAME = 'changelog'
UNIX_EPOCH = datetime.datetime(1970, 1, 1, tzinfo=UTC)

try:
    unregister_algorithm('RS256')
except KeyError:
    pass
register_algorithm('RS256', RSAAlgorithm(RSAAlgorithm.SHA256))


app = Flask(__name__)
try:
    app.config['APP_ID'] = int(os.environ['APP_ID'])
except KeyError:
    raise KeyError(
        'The environment variable APP_ID does not exist. '
        'Define env_variables.APP_ID in app.yaml file so that '
        "it is the same to your GitHub App's ID."
    )
except ValueError:
    raise KeyError(
        'The environment variable APP_ID must consists of only digits.'
    )
if os.environ.get('SECRET_KEY'):
    app.secret_key = os.environ['SECRET_KEY']
else:
    warnings.warn(
        'The envrionment variable SECRET_KEY does not exist. '
        'Define env_variables.SECRET_KEY in app.yaml file so that '
        "it is the same to your GitHub App's Webhook secret.  See also:\n"
        '  https://developer.github.com/webhooks/securing/'
    )
    app.secret_key = os.urandom(20)
try:
    app.config['PRIVATE_KEY'] = os.environ['PRIVATE_KEY']
except KeyError:
    raise KeyError(
        'The environment variable PRIVATE_KEY does not exist. '
        'Generate a private key for your GitHub App and fefine '
        'env_variables.PRIVATE_KEY in app.yaml file to its content.'
    )
app.debug = \
    os.environ.get('DEBUG', '').strip() in ('1', 'true', 't', 'yes', 'y')


def validate_signature(request=request):
    try:
        actual_sig = request.headers['X-Hub-Signature']
    except KeyError:
        raise BadRequest('X-Hub-Signature header is missing.')
    data = request.get_data()
    digest = hmac.new(current_app.secret_key, data, hashlib.sha1)
    expected_sig = 'sha1=' + digest.hexdigest()
    if not hmac.compare_digest(actual_sig.encode('utf-8'), expected_sig):
        raise BadRequest('X-Hub-Signature header has an invalid signature.')


@app.route('/', methods=['GET'])
def index():
    return redirect('https://github.com/apps/changelog-check')


@app.route('/', methods=['POST'])
def receive_webhook():
    validate_signature()
    event = request.headers.get('X-Github-Event')
    data = request.get_json()
    actions = check_suite, ping
    for action in actions:
        if action.__name__ == event:
            return action(data)
    return (
        'Ignored event type: ' + repr(event),
        200,
        {'Content-Type': 'text/plain'},
    )


def lookup(data, *keys):
    if not isinstance(data, collections.Mapping):
        raise BadRequest(
            'Expected an object, but the following was given:\n' +
            json.dumps(data, ensure_ascii=False, indent=2, sort_keys=True)
        )
    path = None
    for key in keys:
        if not isinstance(data, collections.Mapping):
            raise BadRequest(
                'Expected an object from ' + path +
                ', but the following was given:\n' +
                json.dumps(data, ensure_ascii=False, indent=2, sort_keys=True)
            )
        path = key if path is None else path + '.' + key
        try:
            data = data[key]
        except KeyError:
            raise BadRequest('Failed to find: ' + path)
    return data


def log_response(logger, response):
    if isinstance(logger, basestring):
        logger = logging.getLogger(logger)
    if 200 <= response.status_code < 400:
        logger.debug('response.status_code = %r', response.status_code)
        logger.debug('response.headers = %r', response.headers)
        logger.debug('response.content = %r', response.content)
    else:
        logger.error('response.status_code = %r', response.status_code)
        logger.error('response.headers = %r', response.headers)
        logger.error('response.content = %r', response.content)


def get_access_token():
    app_id = current_app.config['APP_ID']
    pem = current_app.config['PRIVATE_KEY']
    now = datetime.datetime.utcnow()
    payload = {
        'iat': now,
        'exp': now + datetime.timedelta(minutes=10),
        'iss': app_id,
    }
    return encode(payload, pem, algorithm='RS256')


def get_installation_token(installation_id):
    cache_key = 'installation_token_{0}'.format(installation_id)
    token = memcache.get(cache_key)
    if token:
        return token
    response = urlfetch.fetch(
        'https://api.github.com/app/installations/{0}/access_tokens'.format(
            installation_id
        ),
        method='POST',
        headers={
            'Accept': 'application/vnd.github.machine-man-preview+json',
            'Authorization': 'Bearer ' + get_access_token(),
        },
    )
    log_response(__name__ + '.get_installation_token', response)
    result = json.loads(response.content)
    expires_at = isoparse(result['expires_at'])
    token = result['token']
    time = (expires_at - UNIX_EPOCH -
            datetime.timedelta(seconds=5)).total_seconds()
    memcache.set(cache_key, token, time)
    return token


def check_suite(data):
    action = lookup(data, 'action')
    if action == 'requested':
        before = lookup(data, 'check_suite', 'before')
        after = lookup(data, 'check_suite', 'after')
        repo_url = lookup(data, 'repository', 'url')
        installation_id = lookup(data, 'installation', 'id')
        token = get_installation_token(installation_id)
        check_runs_url = repo_url + '/check-runs'
        response = urlfetch.fetch(
            check_runs_url,
            method='POST',
            headers={
                'Content-Type': 'application/json',
                'Accept': 'application/vnd.github.antiope-preview+json',
                'Authorization': 'Bearer ' + token,
            },
            payload=json.dumps({
                'name': CHECK_NAME,
                'head_sha': after,
            }),
        )
        log_response(__name__ + '.check_suite', response)
    return json.dumps(data), 200, {'Content-Type': 'application/json'}


def ping(data):
    return '', 200, {'Content-Type': 'text/plain'}
