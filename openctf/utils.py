import random
import re
from string import hexdigits
from urllib.parse import urljoin, urlparse

from flask import redirect, request, url_for

VALID_USERNAME = re.compile(r"^[A-Za-z_][A-Za-z\d_]*$")
VALID_PROBLEM_NAME = re.compile(r"^[a-z_][a-z\-\d_]*$")


def generate_string(length=32, alpha=hexdigits):
    characters = [random.choice(alpha) for x in range(length)]
    return "".join(characters)

# http://flask.pocoo.org/snippets/62/


def is_safe_url(target):
    ref_url = urlparse(request.host_url)
    test_url = urlparse(urljoin(request.host_url, target))
    return test_url.scheme in ("http", "https") and ref_url.netloc == test_url.netloc


def get_redirect_target():
    for target in request.values.get("next"), request.referrer:
        if not target:
            continue
        if is_safe_url(target):
            return target


def redirect_back(endpoint, **values):
    target = request.form.get("next", url_for("users.profile"))
    if not target or not is_safe_url(target):
        target = url_for(endpoint, **values)
    return redirect(target)
