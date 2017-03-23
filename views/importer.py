import hashlib
import hmac
import json
import os
import shutil
import threading
import traceback
from cStringIO import StringIO

import git
import paramiko
import yaml
from flask import Blueprint, request

from judge_api import judge_api
from models import Config, File, Problem, db

blueprint = Blueprint("importer", __name__, template_folder="templates")

SSH_FOLDER = os.path.expanduser("~/.ssh")
SSH_CONFIG_FILE = os.path.join(SSH_FOLDER, "config")
GIT_DIR = os.path.expanduser("~/git")
KEYFILE = os.path.expanduser("~/key")


def create_folders():
    if not os.path.exists(SSH_FOLDER):
        os.mkdir(SSH_FOLDER)
    if hasattr(os, "mknod"):
        if not os.path.exists(SSH_CONFIG_FILE):
            os.mknod(SSH_CONFIG_FILE)
    if not os.path.exists(GIT_DIR):
        os.mkdir(GIT_DIR)


@blueprint.route("/webhook", methods=["POST"])
def github_webhook():
    secret = Config.get("webhook_secret", "")
    if len(secret) == 0:
        return "A webhook has not been enabled for this platform. Set a secret to enable the webhook.", 500
    payload = request.get_data()
    hashed = hmac.new(secret, payload, hashlib.sha1)
    if request.headers.get("X-Hub-Signature") != "sha1=%s" % hashed.hexdigest():
        return "Forged request detected.", 500
    try:
        data = json.loads(payload)
        url = data["repository"]["ssh_url"]
        key, dummy = Config.get_ssh_keys()
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        private_key = paramiko.RSAKey.from_private_key(StringIO(key))
    except:
        return "An error occurred while reading the payload.\n" + traceback.format_exc(), 500
    try:
        client.connect(hostname="github.com", username="git", pkey=private_key)
    except paramiko.AuthenticationException:
        return "Github is denying access to this repository. Make sure the public key has been installed correctly.", 500
    data["delivery_id"] = request.headers["X-GitHub-Delivery"]
    return clone_repository(data)


def clone_repository(payload):
    GIT_REPO = str(os.path.join(GIT_DIR, payload["delivery_id"]))
    if os.path.exists(GIT_REPO):
        shutil.rmtree(GIT_REPO)
    repo = git.Repo.init(GIT_REPO)
    origin = repo.create_remote("origin", payload["repository"]["ssh_url"])
    with open(KEYFILE, "w") as f:
        f.write(Config.get_ssh_keys()[0])
    with open(SSH_CONFIG_FILE, "w") as f:
        f.write("Host *\n\tStrictHostKeyChecking no")
    os.chmod(KEYFILE, 0600)
    os.chmod(SSH_CONFIG_FILE, 0600)
    if os.system("cd %s; ssh-agent bash -c 'ssh-add %s; git pull origin master'" % (GIT_REPO, KEYFILE)) == 0:
        os.unlink(KEYFILE)
        problems = []
        for problem in os.listdir(GIT_REPO):
            problem = str(problem)
            if problem in [".", "..", ".git", ".exclude"]: continue
            if not os.path.isdir(os.path.join(GIT_REPO, problem)): continue
            files = os.listdir(os.path.join(GIT_REPO, problem))
            ready = True
            for required_file in ["grader.py", "problem.yml", "description.md"]:
                if required_file not in files:
                    ready = False
                    break # return "Expected required file %s in '%s'." % (required_file, problem), 500
            if ready:
                metadata = yaml.load(open(os.path.join(GIT_REPO, problem, "problem.yml")))
                for required_key in ["author", "title", "category", "value"]:
                    if required_key not in metadata:
                        ready = False
                        break # return "Expected required key %s in 'problem.yml' for problem '%s'." % (required_key, problem), 500
                if metadata.get("programming", False):
                    if "generator.py" not in files:
                        ready = False
                        break # return "Expected required file 'generator.py' in '%s'." % problem, 500
                if ready:
                    problems.append(problem)
        return import_repository(GIT_REPO, problems)
    else:
        return "Failed to pull from remote.", 500


def import_repository(path, problems=None):
    if not problems:
        problems = os.listdir(path)
    for problem in problems:
        problem_path = os.path.join(path, problem)
        try:
            if os.path.isdir(problem_path):
                import_problem(problem_path, problem)
        except:
            pass  # Failed this problem.
    shutil.rmtree(path)
    return "Import successful."


def import_problem(path, name):
    problem = Problem.query.filter_by(name=name).first()
    if not problem:
        problem = Problem(name=name)

    metadata = yaml.load(open(os.path.join(path, "problem.yml")))
    problem.author = metadata.get("author", "")
    problem.title = metadata.get("title", "")
    problem.category = metadata.get("category", "")
    problem.value = int(metadata.get("value", "0"))
    problem.hint = metadata.get("hint", "")
    problem.autogen = metadata.get("autogen", False)
    problem.programming = metadata.get("programming", False)

    problem.description = open(os.path.join(path, "description.md")).read()
    problem.grader = open(os.path.join(path, "grader.py")).read()

    db.session.add(problem)
    db.session.flush()

    if problem.programming:
        for required_key in ["test_cases", "time_limit", "memory_limit"]:
            if required_key not in metadata:
                raise "Expected required key %s in 'problem.yml' for problem '%s'." % (required_key, name)
        """
        for language_key in ["generator_language", "grader_language", "source_verifier_language"]:
            if language_key in metadata and metadata[language_key] not in SUPPORTED_LANGUAGES:
                raise "Languange %s in %s not supported!" % (metadata[language_key], language_key)
        """
        if judge_api.problems_get(problem.pid).status_code == 404:
            api_method = judge_api.problems_create
        else:
            api_method = judge_api.problems_modify
        judge_problem_info = {
            "problem_id": problem.pid,
            "test_cases": int(metadata.get("test_cases", 10)),
            "time_limit": int(metadata.get("time_limit", 1)),
            "memory_limit": int(metadata.get("memory_limit", 256000)),
            "generator_code": open(os.path.join(path, "generator.py")).read(),
            "generator_language": "python2",
            "grader_code": open(os.path.join(path, "grader.py")).read(),
            "grader_language": "python2",
        }
        source_verifier_path = os.path.join(path, "source_verifier.py")
        if os.path.isfile(source_verifier_path):
            judge_problem_info.update({
                "source_verifier_code": open(os.path.join(path, "grader.py")).read(),
                "source_verifier_language": "python2",
            })
        threading.Thread(target=api_method, kwargs=judge_problem_info).start()
        # result = api_method(**judge_problem_info)
        # if not result.is_ok():
        #     raise "Failed to add problem to judge"
    db.session.commit()
    if "files" in metadata:
        files = metadata["files"]
        for file in files:
            src_file = open(os.path.join(path, file), "rb")
            file = File(pid=problem.pid, filename=file, data=src_file)
            db.session.add(file)
    db.session.commit()
