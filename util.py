"""
    server.util
    ~~~~~~~~~~~

    Contains functions that may be useful for various other places in the
    platform. This file should be independent from the rest of the platform
    (that is, it should not depend on any of the other modules in the
    platform.)
"""

import cPickle as pickle
import datetime
import hashlib
import json
import random
import re
import threading
import time
from functools import wraps
from string import hexdigits

import enum
import requests
from flask import current_app as app
from PIL import Image, ImageDraw
from redis import Redis


VALID_USERNAME = re.compile(r"^[A-Za-z_][A-Za-z\d_]*$")
VALID_PROBLEM_NAME = re.compile(r"^[a-z_][a-z\-\d_]*$")


def sendmail(recipient, subject, body):
    """
    Sends an email to the specified recipient, with the specified subject
    and body, using the Mailchimp API. This function can only be used if a
    MAILCHIMP_API_KEY has been specified in the environment variables.

    :param recipient: If a string is provided, it will be used as the
        primary recipient. If an array of strings is provided, then every
        string will be treated as a recipient, and the email will be BCC'd
        to every recipient.
    :param subject: The subject of the email.
    :param body: The body of the email.
    """
    data = {
        "from": app.config["ADMIN_EMAIL"],
        "subject": subject,
        "html": body
    }
    data["to" if type(recipient) in [str, unicode] else "bcc"] = recipient
    auth = ("api", app.config["MAILGUN_APIKEY"])
    return requests.post("%s/messages" % app.config["MAILGUN_URL"],
                         auth=auth, data=data)


def generate_string(length=32, alpha=hexdigits):
    characters = [random.choice(alpha) for x in range(length)]
    return "".join(characters)


def get_attrs(obj, attrs):
    return {attr: getattr(obj, attr) for attr in attrs}


def column_dict(obj):
    return get_attrs(obj, [column.name for column in obj.__table__.columns])


class JSONEncoder(json.JSONEncoder):

    def default(self, obj):
        if isinstance(obj, enum.Enum):
            return str(obj)
        elif isinstance(obj, datetime.datetime):
            return str(int(time.mktime(obj.timetuple())))
        return json.JSONEncoder.default(self, obj)


def generate_identicon(email):
    email = email.strip().lower()
    h = hashlib.sha1(email).hexdigest()
    size = 256
    margin = 0.08
    base_margin = int(size * margin)
    cell = int((size - base_margin * 2.0) / 5)
    margin = int((size - cell * 5.0) / 2)
    image = Image.new("RGB", (size, size))
    draw = ImageDraw.Draw(image)

    def hsl2rgb(h, s, b):
        h *= 6
        s1 = []
        s *= b if b < 0.5 else 1 - b
        b += s
        s1.append(b)
        s1.append(b - h % 1 * s * 2)
        s *= 2
        b -= s
        s1.append(b)
        s1.append(b)
        s1.append(b + h % 1 * s)
        s1.append(b + s)

        return [
            s1[~~h % 6], s1[(h | 16) % 6], s1[(h | 8) % 6]
        ]

    rgb = hsl2rgb(int(h[-7:], 16) & 0xfffffff, 0.5, 0.7)
    bg = (255, 255, 255)
    fg = (int(rgb[0] * 255), int(rgb[1] * 255), int(rgb[2] * 255))
    draw.rectangle([(0, 0), (size, size)], fill=bg)

    for i in range(15):
        c = bg if int(h[i], 16) % 2 == 1 else fg
        if i < 5:
            draw.rectangle([(2 * cell + margin, i * cell + margin),
                            (3 * cell + margin, (i + 1) * cell + margin)],
                           fill=c)
        elif i < 10:
            draw.rectangle([(1 * cell + margin, (i - 5) * cell + margin),
                            (2 * cell + margin, (i - 4) * cell + margin)],
                           fill=c)
            draw.rectangle([(3 * cell + margin, (i - 5) * cell + margin),
                            (4 * cell + margin, (i - 4) * cell + margin)],
                           fill=c)
        elif i < 15:
            draw.rectangle(
                [(0 * cell + margin, (i - 10) * cell + margin),
                 (1 * cell + margin, (i - 9) * cell + margin)], fill=c)
            draw.rectangle(
                [(4 * cell + margin, (i - 10) * cell + margin),
                 (5 * cell + margin, (i - 9) * cell + margin)], fill=c)

    return image
