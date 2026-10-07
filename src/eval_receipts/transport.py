"""Bounded HTTPS requests; credentials never follow redirects."""
import ipaddress
import json
import os
import urllib.error
import urllib.parse
import urllib.request
from .core import InvalidReceipt, canonical, require, strict_json


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def registry_url(url):
    require(isinstance(url, str), "Invalid registry URL")
    url = url.rstrip("/")
    p = urllib.parse.urlsplit(url)
    require(not p.username and not p.password and not p.query and not p.fragment, "Invalid registry URL")
    loopback = p.hostname == "localhost"
    try:
        loopback = loopback or ipaddress.ip_address(p.hostname).is_loopback
    except ValueError:
        pass
    require(p.scheme == "https" or (p.scheme == "http" and loopback), "Registry needs HTTPS (HTTP allowed only on loopback)")
    require(p.hostname and p.path in ("", "/", "/eval"), "Registry URL may have only the /eval prefix")
    return url.rstrip("/")


def request(url, data=None, token=None, limit=16_000_000, timeout=30):
    headers = {"User-Agent": "creationloop-eval-receipts/0.1.0"}
    if token:
        require(len(token) <= 1024 and token.isascii() and not any(c.isspace() for c in token), "Invalid registry token")
        headers["Authorization"] = "Bearer " + token
    if data is not None:
        headers["Content-Type"] = "application/json"
        data = canonical(data)
    req = urllib.request.Request(url, data=data, headers=headers)
    try:
        with urllib.request.build_opener(NoRedirect).open(req, timeout=timeout) as r:
            result = r.read(limit + 1)
            require(len(result) <= limit, "Response exceeds bound")
            return result
    except urllib.error.HTTPError as e:
        raise InvalidReceipt(f"Registry HTTP {e.code}; local artifacts are retained") from None
    except (urllib.error.URLError, TimeoutError) as e:
        raise InvalidReceipt("Network request failed; local artifacts are retained") from None


def api(base, path, data=None, token=None):
    return strict_json(request(registry_url(base) + path, data=data,
                               token=token or os.environ.get("RECEIPT_TOKEN")))
