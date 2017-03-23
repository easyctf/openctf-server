import logging
import time
from functools import wraps

import requests

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
logging.info('Starting up')

SUPPORTED_LANGUAGES = {
    'cxx': 'C++',
    'python2': 'Python 2',
    'python3': 'Python 3',
    'java': 'Java',
}


def retry_connection(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        retry_freq = kwargs.pop('retry_freq', 0)  # Don't retry by default.
        while True:
            try:
                return func(*args, **kwargs)
            except requests.exceptions.ConnectionError:
                if retry_freq:
                    logger.warning('Failed to connect to judge API, retrying in %d seconds.', retry_freq)
                    time.sleep(retry_freq)
                else:
                    logger.warning('Failed to connect to judge API, not retrying.')
                    return None

    return wrapper


class APIResponse:
    def __init__(self, status_code, data):
        self.status_code = status_code
        self.data = data

    def __repr__(self):
        return '<APIResponse %d>' % self.status_code

    @classmethod
    def from_requests_response(cls, response):
        return cls(response.status_code, response.json() if response.text else None)

    def is_ok(self):
        return self.status_code // 100 == 2


def response(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        result = func(*args, **kwargs)
        return APIResponse(result[0], result[1])
    return wrapper


# Deserialize responses into (status_code, json)
def response_json(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        result = func(*args, **kwargs)
        if result is not None:
            result = APIResponse.from_requests_response(result)
        return result
    return wrapper


class JudgeAPI:
    def __init__(self, url=None, api_key=None):
        self.url = url
        self.api_key = api_key

    @retry_connection
    def request(self, method, endpoint, data=None):
        return requests.request(method, url=self.url + endpoint, data=data, headers={
            'api_key': self.api_key,
        })

    def get(self, endpoint):
        return self.request('GET', endpoint)

    def post(self, endpoint, data=None):
        return self.request('POST', endpoint, data=data)

    def put(self, endpoint, data=None):
        return self.request('PUT', endpoint, data=data)

    @response_json
    def submissions_list(self):
        return self.get('/submissions')

    @response_json
    def submissions_list_by_gid(self, gid):
        return self.get('/submissions/gid/{}'.format(gid))

    @response_json
    def submissions_create(self, problem_id, language, code, uid=None, gid=None, callback_url=None):
        data = {
            'problem_id': problem_id,
            'language': language,
            'code': code,
            'uid': uid,
            'gid': gid,

            'callback_url': callback_url,
        }
        return self.post('/submissions', data=data)

    @response_json
    def submissions_details(self, submission_id):
        return self.get('/submissions/{}'.format(submission_id))

    @response_json
    def problems_list(self):
        return self.get('/problems')

    @response_json
    def problems_get(self, problem_id):
        return self.get('/problems/%s' % problem_id)

    @response_json
    def problems_create(self, problem_id, test_cases, time_limit, memory_limit,
                        generator_code, generator_language, grader_code, grader_language,
                        source_verifier_code=None, source_verifier_language=None):
        data = {
            'id': str(problem_id),
            'test_cases': test_cases,
            'time_limit': time_limit,
            'memory_limit': memory_limit,
            'generator_code': generator_code,
            'generator_language': generator_language,
            'grader_code': grader_code,
            'grader_language': grader_language,
        }
        if source_verifier_code and source_verifier_language:
            data.update({
                'source_verifier_code': source_verifier_code,
                'source_verifier_language': source_verifier_language,
            })
        return self.post('/problems', data=data)

    @response_json
    def problems_modify(self, problem_id, test_cases, time_limit, memory_limit,
                        generator_code, generator_language, grader_code, grader_language,
                        source_verifier_code=None, source_verifier_language=None):
        data = {
            'id': problem_id,
            'test_cases': test_cases,
            'time_limit': time_limit,
            'memory_limit': memory_limit,
            'generator_code': generator_code,
            'generator_language': generator_language,
            'grader_code': grader_code,
            'grader_language': grader_language,
        }
        if source_verifier_code and source_verifier_language:
            data.update({
                'source_verifier_code': source_verifier_code,
                'source_verifier_language': source_verifier_language,
            })
        return self.put('/problems/{}'.format(problem_id), data=data)


class FlaskJudgeAPI(JudgeAPI):
    def init_app(self, app):
        self.url = app.config['JUDGE_URL']
        self.api_key = app.config['JUDGE_API_KEY']

judge_api = FlaskJudgeAPI()
