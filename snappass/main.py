import os
import sys
import uuid
import re

import redis
from redis.exceptions import ConnectionError

from flask import abort, Flask, render_template, request, redirect


# SSL is on unless specifically requested
SSL = not os.environ.get('NO_SSL')

app = Flask(__name__)
if os.environ.get('DEBUG'):
    app.debug = True
app.secret_key = os.environ.get('SECRET_KEY', 'Secret Key')
app.config.update(
    dict(STATIC_URL=os.environ.get('STATIC_URL', 'static')))

if os.environ.get('REDIS_URL'):
    redis_client = redis.StrictRedis.from_url(os.environ.get('REDIS_URL'))
else:
    redis_host = os.environ.get('REDIS_HOST', 'localhost')
    redis_port = os.environ.get('REDIS_PORT', 6379)
    redis_db = os.environ.get('SNAPPASS_REDIS_DB', 0)
    redis_client = redis.StrictRedis(
        host=redis_host, port=redis_port, db=redis_db)

time_conversion = {
    '1 hour': 3600,
    '5 hours': 10800,
    '1 day': 86400,
    '3 days': 259200,
    '1 week': 604800
}


def check_redis_alive(fn):
    def inner(*args, **kwargs):
        try:
            if fn.__name__ == 'main':
                redis_client.ping()
            return fn(*args, **kwargs)
        except ConnectionError as e:
            print('Failed to connect to redis! %s' % e.message)
            if fn.__name__ == 'main':
                sys.exit(0)
            else:
                return abort(500)
    return inner


@check_redis_alive
def set_password(password, ttl):
    key = uuid.uuid4().hex
    redis_client.setex(key, ttl, password)
    return key


@check_redis_alive
def get_password(key):
    password = redis_client.get(key)
    if password is not None:
        password = password.decode('utf-8')
    redis_client.delete(key)
    return password


def clean_input():
    """
    Make sure we're not getting bad data from the front end,
    format data to be machine readable
    """
    if 'password' not in request.form:
        abort(400)

    if 'ttl' not in request.form:
        abort(400)

    time_period = request.form['ttl'].lower()
    if time_period not in time_conversion:
        abort(400)

    return time_conversion[time_period], request.form['password']

@app.before_request
def before_request():
    """
    Redirect to https if SSL active and request is using simple http
    If behind a AWS Elastic Load Balancer (ELB), the header 'X-Forwarded-Proto' would contain the protocol used
    https://docs.aws.amazon.com/elasticloadbalancing/latest/classic/x-forwarded-headers.html#x-forwarded-proto
    """
    if SSL and request.headers.get('X-Forwarded-Proto') and request.headers.get('X-Forwarded-Proto') == 'http':
        url = request.url.replace('http://', 'https://', 1)
        return redirect(url, code=301)

@app.route('/', methods=['GET'])
def index():
    return render_template('set_password.html')


@app.route('/', methods=['POST'])
def handle_password():
    ttl, password = clean_input()
    key = set_password(password, ttl)

    if SSL:
        base_url = request.url_root.replace("http://", "https://")
    else:
        base_url = request.url_root
    link = base_url + key
    return render_template('confirm.html', password_link=link)


@app.route('/<password_key>', methods=['GET'])
def show_password(password_key):
    if re.search('bot', request.headers.get('User-Agent', '')):
        abort(404)
    password = get_password(password_key)
    if not password:
        abort(404)

    return render_template('password.html', password=password)


@check_redis_alive
def main():
    app.run(host='0.0.0.0')


if __name__ == '__main__':
    main()
