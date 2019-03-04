#!/usr/bin/env python2.7
# changelog-check: A GitHub App to check if changelog was written
# Copyright (C) 2019 Hong Minhee <https://hongminhee.org/>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.
import collections
import datetime
import hashlib
import hmac
import json
import logging
import os
import re
import warnings

from Crypto.PublicKey import RSA
from flask import (
    Flask,
    current_app,
    redirect,
    request,
    render_template,
    url_for,
)
from google.appengine.api import memcache, urlfetch
from google.appengine.ext import ndb
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
app.debug = \
    os.environ.get('DEBUG', '').strip() in ('1', 'true', 't', 'yes', 'y')


class ConfigItem(ndb.Model):
    value = ndb.BlobProperty()


def set_config(name, value):
    key = ndb.Key(ConfigItem, name)
    item = key.get()
    if isinstance(value, unicode):
        value = value.encode('utf-8')
    if item is None:
        item = ConfigItem(id=name, value=value)
    else:
        item.value = value
    item.put()


RAISE_ERROR = object()


def get_config(name, error_value=RAISE_ERROR):
    key = ndb.Key(ConfigItem, name)
    item = key.get()
    if item is None:
        if error_value is RAISE_ERROR:
            url = url_for('config_form', _external=True)
            raise BadRequest('Not properly configured yet.  Go to ' + url)
        return error_value
    return item.value


def validate_signature(request=request):
    try:
        actual_sig = request.headers['X-Hub-Signature']
    except KeyError:
        raise BadRequest('X-Hub-Signature header is missing.')
    data = request.get_data()
    secret_key = get_config('webhook_secret')
    digest = hmac.new(secret_key, data, hashlib.sha1)
    expected_sig = 'sha1=' + digest.hexdigest()
    if not hmac.compare_digest(actual_sig.encode('utf-8'), expected_sig):
        raise BadRequest('X-Hub-Signature header has an invalid signature.')


@app.route('/')
def index():
    configs = 'webhook_secret', 'app_id', 'app_slug', 'private_key'
    if any(get_config(cfg, None) is None for cfg in configs):
        return redirect(url_for('config_form'))
    return redirect('https://github.com/apps/changelog-check')


@app.route('/config/')
def config_form(error_response=None):
    private_key = get_config('private_key', None)
    if private_key:
        pubkey = RSA.importKey(private_key).publickey()
        digest = hashlib.sha1(pubkey.exportKey('DER')).digest()
        fingerprint = ':'.join('{0:02x}'.format(ord(b)) for b in digest)
    else:
        fingerprint = None
    return render_template(
        'config_form.html',
        get_config=get_config,
        error_response=error_response,
        fingerprint=fingerprint,
    )


@app.route('/config/', methods=['POST'])
def save_config():
    app_id = request.form['app_id']
    try:
        private_key = request.files['private_key']
    except KeyError:
        pass
    else:
        private_key = private_key.stream.read()
    token = get_access_token(app_id, private_key)
    response = urlfetch.fetch(
        'https://api.github.com/app',
        method='GET',
        headers={
            'Accept': 'application/vnd.github.machine-man-preview+json',
            'Authorization': 'Bearer ' + token,
        },
    )
    log_response(__name__ + '.save_config', response)
    if 200 <= response.status_code < 400:
        html_url = json.loads(response.content)['html_url']
        set_config('app_slug', html_url.split('/')[-1])
        set_config('app_id', app_id)
        set_config('webhook_secret', request.form['webhook_secret'])
        set_config('private_key', private_key)
        return config_form()
    return config_form(error_response=response)


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


def get_access_token(app_id=None, private_key=None):
    app_id = app_id or get_config('app_id')
    pem = private_key or get_config('private_key')
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
