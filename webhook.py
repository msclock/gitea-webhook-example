from datetime import datetime
from pathlib import Path
import re
from tempfile import TemporaryDirectory
from typing import Optional
from flask import Flask, request, jsonify
from git import Repo
from pydantic import BaseModel, ValidationError
import hmac
import hashlib
from loguru import logger

app = Flask(__name__)

WEBHOOK_SECRET = "webhook_secret" # should be in env


class GiteaDeleteEvent(BaseModel):
    ref: str
    ref_type: str
    pusher_type: str
    repository: dict
    sender: dict


class GiteaCreateEvent(BaseModel):
    sha: str
    ref: str
    ref_type: str
    repository: dict
    sender: dict


class GiteaPushEvent(BaseModel):
    ref: str
    before: str
    after: str
    compare_url: str
    repository: dict
    commits: list
    total_commits: int
    head_commit: dict
    pusher: dict
    sender: dict


class GiteaPullRequestEvent(BaseModel):
    action: str
    number: int
    pull_request: dict
    requested_reviewer: Optional[dict] = None
    repository: dict
    sender: dict
    commit_id: str
    review: Optional[dict] = None


def verify_signature(payload: bytes, signature: str, secret: str) -> bool:
    """Verify Gitea signature（HMAC SHA256）"""
    digest = hmac.new(secret.encode(), payload, hashlib.sha256).hexdigest()
    return hmac.compare_digest(digest, signature)


@app.route("/webhook", methods=["POST"])
def handle_gitea_webhook():
    logger.info(f"Received:\n{request.headers}\n{request.json}")
    x_gitea_event = request.headers.get("X-Gitea-Event")
    x_gitea_signature = request.headers.get("X-Gitea-Signature")
    if not x_gitea_event or not x_gitea_signature:
        return webhook_response("Missing required headers", 400)

    if not verify_signature(request.data, x_gitea_signature, WEBHOOK_SECRET):
        return webhook_response("Invalid webhook secret", 403)

    try:
        logger.info(f"Received event: {x_gitea_event}")
        if x_gitea_event == "push":
            event = GiteaPushEvent(**request.json)
            return webhook_response(x_gitea_event, 200)
        elif x_gitea_event == "pull_request":
            event = GiteaPullRequestEvent(**request.json)
            pull_request_handler(event)
            return webhook_response(x_gitea_event, 200)
        elif x_gitea_event == "pull_request_approved":
            event = GiteaPullRequestEvent(**request.json)
            return webhook_response(x_gitea_event, 200)
        else:
            return webhook_response(f"Unsupported event type: {x_gitea_event}", 400)
    except ValidationError as e:
        return webhook_response(f"Invalid event data: {e}", 400)


def webhook_response(message, code):
    return jsonify({"status": "success" if code == 200 else "failed", "message": message}), code


def pull_request_handler(event: GiteaPullRequestEvent):
    if not event.action == "review_requested":
        return

    try:
        clone_url = event.repository["clone_url"]
        base_sha = event.pull_request["base"]["sha"]
        head_ref = event.pull_request["head"]["ref"]
        reviewer_user = event.requested_reviewer["username"]
        reviewer_email = event.requested_reviewer["email"]
        required_reviewed_text = f"Reviewed-by: {reviewer_user} <{reviewer_email}>"
        with TemporaryDirectory() as temp_dir:
            temp_git = Path(temp_dir).joinpath("git")
            repo = Repo.clone_from(clone_url, temp_git, branch=head_ref)
            commits = reversed(
                list(repo.iter_commits(f"{base_sha}..{head_ref}")))
            for commit in commits:
                if re.match(rf"^{required_reviewed_text}", commit.message):
                    continue

                commit_date = datetime.fromtimestamp(
                    commit.committed_date).strftime("%Y-%m-%d %H:%M:%S")
                repo.git.execute(command=["git", "checkout", commit.hexsha])
                repo.git.execute(
                    command=[
                        "git",
                        "commit",
                        "--amend",
                        "--message",
                        commit.message + "\n\n" + required_reviewed_text,
                        "--date",
                        commit_date,
                        "--author",
                        f"{commit.author.name} <{commit.author.email}>",
                    ],
                    env={
                        "GIT_COMMITTER_DATE": commit_date,
                        "GIT_COMMITTER_NAME": f"{commit.committer.name}",
                        "GIT_COMMITTER_EMAIL": f"{commit.committer.email}",
                    },
                )
                repo.git.execute(
                    command=["git", "replace", commit.hexsha, "HEAD"])
            repo.git.execute(
                command=["git", "filter-repo", "--partial", "--force"])
            repo.git.execute(
                command=[
                    "git",
                    "push",
                    "--force",
                    "origin",
                    f"{head_ref}:{head_ref}",
                ]
            )
            repo.close()
    except Exception as e:
        logger.warning(f"invalid remote: {clone_url}, e:{e}")


if __name__ == "__main__":
    app.run(debug=True, port=8888)
