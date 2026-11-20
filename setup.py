#!/usr/bin/env python3
"""Register and inspect a GitHub.com App for an izmm runner coordinator."""

import argparse
import base64
import html
import json
import os
import re
import secrets
import stat
import subprocess
import sys
import tempfile
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qs, urlencode, urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

GITHUB_API = "https://api.github.com"
MANIFEST = Path(__file__).with_name("manifest.json")
SLUG = re.compile(r"[A-Za-z0-9][A-Za-z0-9-]{0,99}\Z")
CLIENT_ID = re.compile(r"[A-Za-z0-9_.-]{1,100}\Z")
CODE = re.compile(r"[A-Za-z0-9_-]{8,200}\Z")
KEY_NAME = "github-app.pem"
METADATA_NAME = "github-app.json"


class SetupError(Exception):
    pass


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def api(path, method="GET", jwt=None):
    headers = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2026-03-10",
        "User-Agent": "izmm-github-app-setup",
    }
    if jwt:
        headers["Authorization"] = "Bearer " + jwt
    request = Request(
        GITHUB_API + path,
        data=b"" if method == "POST" else None,
        headers=headers,
        method=method,
    )
    try:
        with build_opener(NoRedirect()).open(request, timeout=15) as response:
            payload = response.read(2 * 1024 * 1024 + 1)
    except HTTPError as exc:
        raise SetupError(f"GitHub API rejected the request (HTTP {exc.code})") from None
    except (OSError, URLError):
        raise SetupError("Could not reach the GitHub API") from None
    if len(payload) > 2 * 1024 * 1024:
        raise SetupError("GitHub API response is too large")
    try:
        return json.loads(payload)
    except ValueError:
        raise SetupError("GitHub API returned invalid JSON") from None


def owner_directory(path, create=False):
    if create:
        path.mkdir(parents=True, mode=0o700, exist_ok=True)
    details = path.lstat()
    if not stat.S_ISDIR(details.st_mode) or details.st_uid != os.getuid() or details.st_mode & 0o077:
        raise SetupError("The output directory must be an owner-only directory (0700)")
    return path.resolve()


def private_read(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        details = os.fstat(stream.fileno())
        if not stat.S_ISREG(details.st_mode) or details.st_uid != os.getuid() or details.st_mode & 0o077:
            raise SetupError("GitHub App credentials must use owner-only regular files (0600)")
        data = stream.read(65537)
    if len(data) > 65536:
        raise SetupError("GitHub App credential file is too large")
    return data


def publish_private(path, data):
    # Commit a complete file without replacing an existing credential.
    fd, temp = tempfile.mkstemp(dir=path.parent, prefix=".github-app-")
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.link(temp, path)
    finally:
        os.unlink(temp)


def save_registration(root, organization, response):
    if not isinstance(response, dict):
        raise SetupError("GitHub returned invalid App metadata")
    slug, client_id, app_id = (response.get(k) for k in ("slug", "client_id", "id"))
    owner, key = response.get("owner"), response.get("pem")
    if not (
        isinstance(owner, dict) and str(owner.get("login")).lower() == organization.lower()
        and isinstance(slug, str) and SLUG.fullmatch(slug)
        and isinstance(client_id, str) and CLIENT_ID.fullmatch(client_id)
        and type(app_id) is int and app_id > 0
        and isinstance(key, str) and key.startswith(("-----BEGIN RSA PRIVATE KEY-----", "-----BEGIN PRIVATE KEY-----"))
        and len(key) <= 65536
    ):
        raise SetupError("GitHub returned an incomplete App registration or a different owner")
    # GitHub also returns client and webhook secrets. The coordinator uses
    # neither, so persist only the signing key and installation lookup metadata.
    publish_private(root / KEY_NAME, key.encode("ascii"))
    metadata = {"slug": slug, "client_id": client_id, "app_id": app_id, "organization": organization}
    publish_private(root / METADATA_NAME, (json.dumps(metadata, indent=2) + "\n").encode())
    return metadata


class RegistrationServer(HTTPServer):
    def __init__(self, root, organization, name, scope):
        super().__init__(("127.0.0.1", 0), RegistrationHandler)
        self.root = root
        self.organization = organization
        self.state = secrets.token_urlsafe(32)
        self.origin = f"http://127.0.0.1:{self.server_port}"
        self.metadata = None
        self.error = None
        self.consumed = False
        self.finished = False
        self.manifest = json.loads(MANIFEST.read_text())
        self.manifest["name"] = name
        self.manifest["redirect_url"] = self.origin + "/callback"
        if scope == "repository":
            self.manifest["default_permissions"] = {"metadata": "read", "administration": "write"}

    @property
    def approval_url(self):
        return self.origin + "/register?" + urlencode({"state": self.state})


class RegistrationHandler(BaseHTTPRequestHandler):
    def setup(self):
        self.request.settimeout(5)
        super().setup()

    def log_message(self, *_args):
        # The callback URL includes a temporary credential.
        return

    def respond(self, status, body="", location=None):
        encoded = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(encoded)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Security-Policy", "default-src 'none'; form-action https://github.com; frame-ancestors 'none'")
        if location:
            self.send_header("Location", location)
        self.end_headers()
        if encoded:
            self.wfile.write(encoded)

    def do_GET(self):
        server = self.server
        if self.headers.get("Host") != f"127.0.0.1:{server.server_port}":
            self.respond(400, "Invalid callback host.")
            return
        try:
            path = urlsplit(self.path)
            query = parse_qs(path.query, max_num_fields=5)
        except ValueError:
            self.respond(400, "Invalid callback query.")
            return
        if path.path in ("/register", "/callback"):
            states = query.get("state", [])
            if len(states) != 1 or not secrets.compare_digest(states[0].encode("utf-8"), server.state.encode("ascii")):
                self.respond(403, "Registration state did not match.")
                return
        if path.path == "/register":
            self.form()
        elif path.path == "/callback":
            self.exchange(query.get("code", []))
        elif path.path == "/complete" and server.consumed:
            self.respond(200, "App registration complete. Continue in the setup terminal." if server.metadata else
                         "App registration failed. See the setup terminal.")
            server.finished = True
        else:
            self.respond(404, "Page not found.")

    def form(self):
        url = "https://github.com/organizations/" + self.server.organization + "/settings/apps/new"
        url += "?" + urlencode({"state": self.server.state})
        fields = html.escape(json.dumps(self.server.manifest), quote=True)
        self.respond(200, '<!doctype html><meta charset="utf-8"><title>Register the izmm GitHub App</title>'
                     '<h1>Register the izmm GitHub App</h1>'
                     f'<form method="post" action="{html.escape(url, quote=True)}">'
                     f'<input type="hidden" name="manifest" value="{fields}">'
                     '<button>Review and register on GitHub</button></form>')

    def exchange(self, codes):
        server = self.server
        if server.consumed or len(codes) != 1 or not CODE.fullmatch(codes[0]):
            self.respond(400, "Invalid or consumed registration.")
            return
        server.consumed = True
        try:
            response = api(f"/app-manifests/{codes[0]}/conversions", "POST")
            server.metadata = save_registration(server.root, server.organization, response)
        except (SetupError, OSError, UnicodeError) as exc:
            server.error = exc if isinstance(exc, SetupError) else SetupError("Could not store GitHub App registration")
        self.respond(303, location="/complete")


def registration_metadata(root, organization=None):
    try:
        metadata = json.loads(private_read(root / METADATA_NAME))
        owner = metadata["organization"]
        if not (
            isinstance(owner, str) and SLUG.fullmatch(owner)
            and (organization is None or owner.lower() == organization.lower())
            and SLUG.fullmatch(metadata["slug"])
            and CLIENT_ID.fullmatch(metadata["client_id"])
            and type(metadata["app_id"]) is int and metadata["app_id"] > 0
        ):
            raise ValueError
    except (ValueError, KeyError, TypeError):
        raise SetupError("App metadata does not match the expected organization") from None
    private_read(root / KEY_NAME)
    return metadata


def print_registration(root, metadata):
    print(f"App ID: {metadata['app_id']}")
    print(f"Client ID: {metadata['client_id']}")
    print(f"Private key file: {root / KEY_NAME}")
    print(f"Install the App at https://github.com/apps/{metadata['slug']}/installations/new")


def app_name(organization, name):
    suffix = " Fleet for GitHub"
    name = name if name is not None else organization[: 34 - len(suffix)].rstrip("-") + suffix
    if not 1 <= len(name.strip()) <= 34 or len(name) > 34 or not name.isprintable():
        raise SetupError("Use a printable GitHub App name of at most 34 characters")
    return name


def register(args):
    if not SLUG.fullmatch(args.organization):
        raise SetupError("Use the GitHub organization login")
    name = app_name(args.organization, args.name)
    output = args.output_dir.resolve()
    if any((directory / ".git").exists() for directory in (output, *output.parents)):
        raise SetupError("Store the GitHub App credentials outside Git checkouts")
    root = owner_directory(args.output_dir, create=True)
    guard = root / ".register.lock"
    fd = os.open(guard, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    os.close(fd)
    try:
        existing = [os.path.lexists(root / filename) for filename in (KEY_NAME, METADATA_NAME)]
        if all(existing):
            print_registration(root, registration_metadata(root, args.organization))
            return
        if any(existing):
            raise SetupError("App registration files are incomplete. Keep them and recover the existing App in GitHub settings.")
        with RegistrationServer(root, args.organization, name, args.scope) as server:
            print(f"Open {server.approval_url} in a browser signed in as an organization owner.", flush=True)
            deadline = time.monotonic() + 60 * 60
            server.timeout = 1
            while not server.finished and time.monotonic() < deadline:
                server.handle_request()
                if server.consumed:
                    deadline = min(deadline, time.monotonic() + 5)
            if server.error is not None:
                raise server.error
            if server.metadata is None:
                raise SetupError("GitHub App registration expired")
            print_registration(root, server.metadata)
    finally:
        guard.unlink()


def b64url(content):
    return base64.urlsafe_b64encode(content).rstrip(b"=")


def signed_jwt(client_id, key_path):
    now = int(time.time())
    message = b".".join((b64url(b'{"alg":"RS256","typ":"JWT"}'),
                         b64url(json.dumps({"iat": now - 60, "exp": now + 540, "iss": client_id}).encode())))
    try:
        signed = subprocess.run(
            ["openssl", "dgst", "-sha256", "-sign", str(key_path)],
            input=message, capture_output=True, check=True, timeout=10,
        ).stdout
    except (OSError, subprocess.SubprocessError):
        raise SetupError("OpenSSL could not sign the GitHub App request") from None
    return (message + b"." + b64url(signed)).decode("ascii")


def installations(args):
    root = owner_directory(args.output_dir)
    metadata = registration_metadata(root)
    organization = metadata["organization"]
    jwt = signed_jwt(metadata["client_id"], root / KEY_NAME)
    results = []
    # A private organization App should only have its owner's installation.
    for page in range(1, 11):
        batch = api(f"/app/installations?per_page=100&page={page}", jwt=jwt)
        if not isinstance(batch, list):
            raise SetupError("GitHub returned invalid App installation data")
        for row in batch:
            if row["account"]["login"].lower() == organization.lower():
                results.append({
                    "installation_id": row["id"],
                    "organization": organization,
                    "repository_selection": row["repository_selection"],
                    "suspended": bool(row.get("suspended_at")),
                })
        if len(batch) < 100:
            break
    else:
        raise SetupError("GitHub returned too many installations")
    print(json.dumps(results, indent=2))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    xdg_config = os.getenv("XDG_CONFIG_HOME")
    config_home = Path(xdg_config) if xdg_config else Path.home() / ".config"
    default_output = config_home / "izmachine" / "github-app"
    commands = parser.add_subparsers(dest="command", required=True)
    create = commands.add_parser("register", help="Serve a loopback approval page and securely store the returned key")
    create.add_argument("--organization", required=True)
    create.add_argument("--name", help="GitHub App name (default: organization name followed by Fleet for GitHub)")
    create.add_argument("--scope", choices=["organization", "repository"], default="organization")
    create.add_argument("--output-dir", type=Path, default=default_output)
    listing = commands.add_parser("list", help="Print installation IDs using the stored App key")
    listing.add_argument("--output-dir", type=Path, default=default_output)
    args = parser.parse_args()
    try:
        (register if args.command == "register" else installations)(args)
    except SetupError as exc:
        parser.exit(1, f"{exc}\n")
    except (OSError, ValueError, KeyError, TypeError):
        parser.exit(1, "GitHub App setup could not read or write its state. Check the output directory and App configuration.\n")
    except KeyboardInterrupt:
        sys.exit(130)


if __name__ == "__main__":
    main()
