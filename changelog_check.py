#!/usr/bin/env python2.7
import collections
import datetime
import hashlib
import hmac
import json
import logging
import os
import re
import warnings

from flask import Flask, current_app, redirect, request
from google.appengine.api import memcache, urlfetch
from google.appengine.ext.deferred import defer
from jwt import encode, register_algorithm, unregister_algorithm
from jwt.contrib.algorithms.pycrypto import RSAAlgorithm
from dateutil.parser import isoparse
from dateutil.tz import UTC
from werkzeug.exceptions import BadRequest


CHECK_NAME = 'changelog'
UNIX_EPOCH = datetime.datetime(1970, 1, 1, tzinfo=UTC)
FILENAME_RE = re.compile(
    ur'(?:^|/)change(?:s|log)(?:\.|$)',
    re.IGNORECASE | re.UNICODE,
)
SKIP_RE = re.compile(
    ur'\[(?:changelog\s+skip|skip\s+changelog)\]',
    re.IGNORECASE | re.UNICODE,
)

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
    actions = check_suite, pull_request, ping
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


def ping(data):
    return '', 200, {'Content-Type': 'text/plain'}


def check_suite(data):
    action = lookup(data, 'action')
    if action == 'requested':
        before = lookup(data, 'check_suite', 'before')
        after = lookup(data, 'check_suite', 'after')
        repo_url = lookup(data, 'repository', 'url')
        default_branch = lookup(data, 'repository', 'default_branch')
        installation_id = lookup(data, 'installation', 'id')
        check_run_url = ack_check_run(installation_id, repo_url, after)
        if before == '0' * 40:
            # It's probably a new branch; let's use heuristics assuming
            # this branch is based on the default branch.
            before = default_branch
        defer(
            scan_commits,
            installation_id,
            repo_url,
            check_run_url,
            before,
            after,
        )
    return json.dumps(data), 200, {'Content-Type': 'application/json'}


def ack_check_run(installation_id, repository_url, head):
    check_runs_url = repository_url + '/check-runs'
    token = get_installation_token(installation_id)
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
            'head_sha': head,
        }),
    )
    log_response(__name__ + '.ack_check_run', response)
    return json.loads(response.content)['url']


def scan_commits(installation_id, repository_url, check_run_url,
                 before, after):
    def update_check_run(status, **payload):
        payload.update(status=status, name=CHECK_NAME)
        token = get_installation_token(installation_id)
        response = urlfetch.fetch(
            check_run_url,
            method='PATCH',
            headers={
                'Content-Type': 'application/json',
                'Accept': 'application/vnd.github.antiope-preview+json',
                'Authorization': 'Bearer ' + token,
            },
            payload=json.dumps(payload),
        )
        log_response(__name__ + '.scan_commits.update_check_run', response)
        assert 200 <= response.status_code < 400, \
            '{0}\n{1}'.format(check_run_url, response.content)
        return response

    update_check_run('in_progress')
    compare_url = '{0}/compare/{1}...{2}'.format(repository_url, before, after)
    token = get_installation_token(installation_id)
    response = urlfetch.fetch(
        compare_url,
        method='GET',
        headers={'Authorization': 'Bearer ' + token},
    )
    log_response(__name__ + '.scan_commits', response)
    assert 200 <= response.status_code < 400, \
        '{0}\n{1}'.format(compare_url, response.content)
    result = json.loads(response.content)
    skipped = False
    skipped_details = []
    for commit in result['commits']:
        if SKIP_RE.search(commit['commit']['message']):
            skipped = True
            skipped_details.append(commit)
    changelog_written = False
    changelog_details = []
    for file in result['files']:
        if FILENAME_RE.search(file['filename']):
            changelog_written = True
            changelog_details.append(file)
    valid = changelog_written or skipped
    if changelog_written:
        message = u'This contains self-describing changelog.'
        details = u''.join(
            u'\n\n### [{filename}]({html_url})\n\n```diff\n{patch}\n```'.format(
                html_url=u'{0}#diff-{1}'.format(
                    result['html_url'],
                    hashlib.md5(file['filename']).hexdigest(),
                ),
                **file
            )
            for file in changelog_details
        )
    elif skipped:
        message = u'Check was skipped.'
        details = u'\n\n'.join(
            u' -  [`{sha}`]({html_url}) {message}'.format(
                message=u'\n    '.join(
                    commit['commit']['message'].split(u'\n')
                ),
                **commit
            )
            for commit in skipped_details
        )
    else:
        message = 'This lacks self-describing changelog.'
        details = ''
    update_check_run(
        'completed',
        conclusion='success' if valid else 'failure',
        completed_at=datetime.datetime.now(UTC).isoformat(),
        output={
            'title': message,
            'summary': message + details,
        },
    )


def pull_request(data):
    action = lookup(data, 'action')
    if action in ('opened', 'reopened', 'synchronized'):
        repo_url = lookup(data, 'pull_request', 'base', 'repo', 'url')
        head = lookup(data, 'pull_request', 'head', 'sha')
        base = lookup(data, 'pull_request', 'base', 'sha')
        installation_id = lookup(data, 'installation', 'id')
        check_run_url = ack_check_run(installation_id, repo_url, head)
        defer(
            scan_commits,
            installation_id,
            repo_url,
            check_run_url,
            base,
            head,
        )
    return json.dumps(data), 200, {'Content-Type': 'application/json'}
