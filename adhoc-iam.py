#!/usr/bin/env python3
from configparser import ConfigParser
from datetime import datetime, timedelta
from functools import wraps
import hmac
from hashlib import sha256
from http.client import HTTPSConnection
from io import BytesIO
from os import environ
from re import compile
from sys import argv
from traceback import print_exc
from typing import Dict, List, Optional, Tuple, Union
from urllib.error import HTTPError
from urllib.parse import quote
from urllib.request import Request, urlopen


MULTISPACE = compile(rb" {2,}")
responsetests = []


def urlencode(s):
    return quote(s, safe="")


def responsetest(f):
    global responsetests

    @wraps(f)
    def wrapper(*args, **kw):
        print(f.__name__)
        try:
            return f(*args, **kw)
        except Exception:
            print_exc()
        finally:
            print("-" * 78)

    responsetests.append(wrapper)
    return wrapper


class SignedRequest:
    s3 = False
    allow_bad_url = False

    def __init__(self, method: str, path: str, region: str, service: str, query_string: Union[bytes, str] = "",
                 headers: Dict[str, Union[bytes, str]] = None, body: Optional[bytes] = None):
        super(SignedRequest, self).__init__()
        self.method = method
        self.path = path
        self.query_string = query_string
        self.region = region
        self.service = service
        self.headers = headers if headers is not None else {}
        self.body = body
        self._date = None
        self._credential_scope = None
        self._signed_headers = None

    def get_canonical_request(self) -> bytes:
        creq = BytesIO()
        creq.write(self.method.encode("utf-8"))
        creq.write(b"\n")
        creq.write(self.get_canonical_uri(allow_bad=self.allow_bad_url))
        creq.write(b"\n")
        creq.write(self.get_canonical_query_string())
        creq.write(b"\n")
        creq.write(self.get_canonical_headers())
        creq.write(b"\n")
        creq.write(self.get_signed_headers().encode("utf-8"))
        creq.write(b"\n")
        creq.write(self.get_payload_hash())

        return creq.getvalue()

    def get_header(self, name: str) -> Optional[Union[str, bytes]]:
        for header, value in self.headers.items():
            if header.lower() == name.lower():
                return value

        return None

    def get_canonical_uri(self, allow_bad=False) -> bytes:
        path = self.path.encode("utf-8")
        parts = path.split(b"/")
        if not parts or parts[0] != b"":
            if allow_bad:
                return path
            raise ValueError("Path must be absolute")

        i = 1
        while i < len(parts):
            if not self.s3 and (parts[i] == b"." or parts[i] == b""):
                del parts[i]
            elif not self.s3 and parts[i] == b"..":
                if i > 0:
                    del parts[i-1:i+1]
                    i -= 1
                else:
                    del parts[0]
                    i = 0
            else:
                parts[i] = url_encode(parts[i], self.s3, allow_bad=self.allow_bad_url)
                i += 1

        if len(parts) == 1:
            result = b"/"
        else:
            result = b"/".join(parts)
        return result

    def get_string_to_sign(self) -> bytes:
        result = BytesIO()
        result.write(b"AWS4-HMAC-SHA256\n")

        date = self.get_date()
        result.write(date.encode("utf-8"))
        result.write(b"\n")

        cred_scope = self.get_credential_scope().encode("utf-8")
        result.write(cred_scope)
        result.write(b"\n")

        creq = self.get_canonical_request()
        print("creq:\n" + creq.decode("utf-8", errors="replace"))
        creq_hash = sha256(creq).hexdigest().encode("utf-8")
        result.write(creq_hash)
        return result.getvalue()

    def get_credential_scope(self) -> str:
        if self._credential_scope is None:
            date = self.get_date()
            self._credential_scope = date[:8] + "/" + self.region + "/" + self.service + "/aws4_request"
        return self._credential_scope

    def get_canonical_query_string(self) -> bytes:
        if isinstance(self.query_string, bytes):
            query_string = self.query_string
        else:
            query_string = self.query_string.encode("utf-8")

        if not query_string:
            return b""

        parts = query_string.split(b"&")
        result: List[Tuple[bytes, bytes]] = []

        for part in parts:
            try:
                key, value = part.split(b"=", 1)
            except TypeError:
                raise ValueError("Invalid query string: missing '=' in %r", part.encode("utf-8"))

            key = url_encode(key, True)
            value = value.replace(b"=", b"%3D")  # Double encode '=' in values
            value = url_encode(value, True)

            result.append(key + b"=" + value)

        result.sort()
        return b"&".join(result)

    def get_canonical_headers(self) -> bytes:
        result = BytesIO()

        headers = {header.lower(): value for header, value in self.headers.items()}
        for header_str, value_str in sorted(headers.items()):
            result.write(header_str.encode("utf-8"))
            result.write(b":")

            if isinstance(value_str, bytes):
                value = value_str
            else:
                value = value_str.encode("utf-8")

            value = value.strip()
            while True:
                m = MULTISPACE.search(value)
                if m is None:
                    break

                value = value[:m.start() + 1] + value[m.end():]

            result.write(value)
            result.write(b"\n")

        return result.getvalue()

    def get_signed_headers(self) -> str:
        if self._signed_headers is None:
            self._signed_headers = ";".join(sorted([header.lower() for header in self.headers.keys()]))
        return self._signed_headers

    def get_payload_hash(self) -> bytes:
        hasher = sha256()
        if self.body is not None:
            hasher.update(self.body)

        return hasher.hexdigest().encode("utf-8")

    def get_date(self) -> str:
        if self._date is None:
            self._date = self.get_header("x-amz-date")
            if self._date is None:
                self._date = self.get_header("date")
            if self._date is None:
                raise ValueError("Missing X-Amz-Date/Date header")
            if isinstance(self._date, bytes):
                self._date = self._date.decode("ascii")
        return self._date

    def get_signing_key(self, secret_key: str) -> bytes:
        k_secret = secret_key.encode("utf-8")
        k_date = hmac.digest(b"AWS4" + k_secret, self.get_date()[:8].encode("utf-8"), "sha256")
        k_region = hmac.digest(k_date, self.region.encode("utf-8"), "sha256")
        k_service = hmac.digest(k_region, self.service.encode("utf-8"), "sha256")
        k_signing = hmac.digest(k_service, b"aws4_request", "sha256")
        return k_signing

    def get_signature(self, secret_key: str) -> str:
        sts = self.get_string_to_sign()
        print("string to sign:")
        print(sts.decode("utf-8"))
        return hmac.new(self.get_signing_key(secret_key), sts, "sha256").hexdigest()

    def get_authorization_header(self, access_key: str, secret_key: str) -> str:
        return (f"AWS4-HMAC-SHA256 Credential={access_key}/{self.get_credential_scope()}, "
                f"SignedHeaders={self.get_signed_headers()}, Signature={self.get_signature(secret_key)}")


def is_rfc3986_unreserved(c: int) -> bool:
    # c must be numeric (48-57), ASCII upper (65-90), ASCII lower (97-122), or '-' (45), '.' (46), '_' (95), '~' (126).
    return (48 <= c <= 57) or (65 <= c <= 90) or (97 <= c <= 122) or c in (45, 46, 95, 126)


def url_encode(url: bytes, s3: bool, allow_bad: bool = False) -> bytes:
    i = 0

    result = BytesIO()

    while i < len(url):
        c: int = url[i]
        if c == 37:  # '%'
            if i + 2 < len(url):  # We have enough characters to interpret this as an escape.
                hex_escape = url[i+1:i+3]
                try:
                    c = int(hex_escape, 16)
                except ValueError:
                    if allow_bad:
                        result.write(b"%" + hex_escape)
                        i += 2
                        continue

                    raise ValueError("Invalid hex escape")

                if is_rfc3986_unreserved(c):
                    result.write(b"%" + bytes((c,)))
                else:
                    if s3:
                        result.write(b"%" + b"%02X" % c)
                    else:
                        result.write(b"%25" + b"%02X" % c)
                i += 3
            else:
                result.write(bytes((c,)))
                i += 1
        elif is_rfc3986_unreserved(c):
            result.write(bytes((c,)))
            i += 1
        else:
            if s3:
                result.write(b"%" + b"%02X" % c)
            else:
                assert 1 == 0
                result.write(b"%25" + b"%02X" % c)
            i += 1

    return result.getvalue()


def get_current_time() -> str:
    return datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")


def get_time_delta(td: timedelta) -> str:
    return (datetime.utcnow() + td).strftime("%Y%m%dT%H%M%SZ")


def get_key_from_profile(profile_name: str) -> Optional[Tuple[str, str, Optional[str]]]:
    cp = ConfigParser(default_section=None)
    cp.read([environ["HOME"] + "/.aws/credentials"])
    if not cp.has_section(profile_name):
        return None

    access_key = cp.get(profile_name, "aws_access_key_id", fallback=None)
    if access_key is None:
        return None

    secret_key = cp.get(profile_name, "aws_secret_access_key", fallback=None)
    if secret_key is None:
        return None

    session_token = cp.get(profile_name, "aws_session_token", fallback=None)
    return (access_key, secret_key, session_token)


def main(args):
    global responsetests
    profile = environ.get("AWS_PROFILE")
    if profile is not None:
        keys = get_key_from_profile(profile)
    else:
        keys = None

    if keys is None:
        access_key = environ.get("AWS_ACCESS_KEY_ID")
        secret_key = environ.get("AWS_SECRET_ACCESS_KEY")
        session_token = environ.get("AWS_SESSION_TOKEN")
        if access_key is not None and secret_key is not None:
            keys = (access_key, secret_key, session_token)

    if keys is None:
        keys = get_key_from_profile("default")

    if keys is None:
        raise RuntimeError("No AWS credentials available")

    for rt in responsetests:
        if not args or rt.__name__ in args:
            rt(keys)

@responsetest
def test_basic_request(keys: Tuple[str, str, Optional[str]]):
    now = get_current_time()
    headers = {"x-amz-date": now, "host": "iam.amazonaws.com"}
    if keys[2] is not None:
        headers["x-amz-security-token"] = keys[2]
    qs = "Action=ListRoles&Version=2010-05-08"
    sr = SignedRequest("GET", "/", "us-east-1", "iam", qs, headers)
    auth = sr.get_authorization_header(keys[0], keys[1])
    headers["authorization"] = auth
    print(headers)

    req = Request(f"https://iam.amazonaws.com/?{qs}", headers=headers)
    try:
        resp = urlopen(req)
        print(resp.read().decode("utf-8"))
    except HTTPError as e:
        print(e)
        print(e.read())


@responsetest
def test_basic_request_post(keys: Tuple[str, str, Optional[str]]):
    now = get_current_time()
    headers = {
        "x-amz-date": now,
        "host": "sts.amazonaws.com",
        "content-type": "application/x-www-form-urlencoded",
    }
    if keys[2] is not None:
        headers["x-amz-security-token"] = keys[2]
    body = b"Action=GetCallerIdentity&Version=2011-06-15"
    sr = SignedRequest("POST", "/", "us-east-1", "sts", "", headers, body)
    auth = sr.get_authorization_header(keys[0], keys[1])
    headers["authorization"] = auth
    curl_headers = " ".join(f"-H '{k}:{v}'" for k, v in headers.items())
    print(f"curl -v -X POST {curl_headers} --data-binary '{body.decode('utf-8')}' https://sts.amazonaws.com/")

    req = Request("https://sts.amazonaws.com/", headers=headers, data=body, method="POST")
    try:
        resp = urlopen(req)
        print(resp.read().decode("utf-8"))
    except HTTPError as e:
        print_exc()
        print(e)
        print(e.read())


@responsetest
def test_post_wrong_content_type(keys: Tuple[str, str, Optional[str]]):
    now = get_current_time()
    headers = {
        "x-amz-date": now,
        "host": "iam.amazonaws.com",
        "content-type": "application/octet-stream",
    }
    if keys[2] is not None:
        headers["x-amz-security-token"] = keys[2]
    body = "Action=ListRoles&Version=2010-05-08".encode("utf-8")
    sr = SignedRequest("POST", "/", "us-east-1", "iam", "", headers, body)
    auth = sr.get_authorization_header(keys[0], keys[1])
    headers["authorization"] = auth
    print(headers)

    req = Request("https://iam.amazonaws.com/", headers=headers, data=body, method="POST")
    try:
        resp = urlopen(req)
        print(resp.read().decode("utf-8"))
    except HTTPError as e:
        print_exc()
        print(e)
        print(e.read())


@responsetest
def test_wrong_method(keys: Tuple[str, str, Optional[str]]):
    now = get_current_time()
    headers = {
        "x-amz-date": now,
        "host": "sts.amazonaws.com",
        "content-type": "application/x-www-form-urlencoded",
    }
    if keys[2] is not None:
        headers["x-amz-security-token"] = keys[2]
    body = "Action=GetCallerIdentity&Version=2011-06-15".encode("utf-8")
    sr = SignedRequest("PUT", "/", "us-east-1", "sts", "", headers, body)
    auth = sr.get_authorization_header(keys[0], keys[1])
    headers["authorization"] = auth
    print(headers)

    req = Request("https://sts.amazonaws.com/", headers=headers, data=body, method="PUT")
    try:
        resp = urlopen(req)
        print(resp.read().decode("utf-8"))
        for key, value in resp.headers().items():
            print(f"{key}: {value}")
    except HTTPError as e:
        print(e, e.reason)
        print(e.read())
        for key, value in e.headers.items():
            print(f"{key}: {value}")


@responsetest
def test_unsigned_request(keys: Tuple[str, str, Optional[str]]):
    headers = {"host": "sts.amazonaws.com"}
    qs = "Action=GetCallerIdentity&Version=2011-06-15"
    req = Request(f"https://sts.amazonaws.com/?{qs}", headers=headers)
    try:
        resp = urlopen(req)
        print(resp.read().decode("utf-8"))
    except HTTPError as e:
        print(e)
        print(e.read())


@responsetest
def test_unicode_header(keys: Tuple[str, str, Optional[str]]):
    now = get_current_time()
    headers = {"x-amz-date": now, "host": "sts.amazonaws.com", "hello": "ÿ"}
    if keys[2] is not None:
        headers["x-amz-security-token"] = keys[2]
    qs = "Action=GetCallerIdentity&Version=2011-06-15"
    sr = SignedRequest("GET", "/", "us-east-1", "sts", qs, headers)
    auth = sr.get_authorization_header(keys[0], keys[1])
    headers["authorization"] = auth
    print(headers)

    req = Request(f"https://sts.amazonaws.com/?{qs}", headers=headers)
    try:
        resp = urlopen(req)
        print(resp.read().decode("utf-8"))
    except HTTPError as e:
        print(e)
        print(e.read())


@responsetest
def test_nonunicode_header(keys: Tuple[str, str, Optional[str]]) -> bool:
    now = get_current_time()
    headers = {
        "x-amz-date": now.encode("ascii"),
        "host": "sts.amazonaws.com".encode("ascii"),
        "hello": b"\xc3\xa2\xc2\x82\xc2\xac",
    }
    if keys[2] is not None:
        headers["x-amz-security-token"] = keys[2].encode("ascii")
    qs = "Action=GetCallerIdentity&Version=2011-06-15"
    sr = SignedRequest("GET", "/", "us-east-1", "sts", qs, headers)
    auth = sr.get_authorization_header(keys[0], keys[1])
    headers["hello"] = b"\xe2\x82\xac"
    headers["authorization"] = auth
    print(headers)

    c = HTTPSConnection("sts.amazonaws.com")
    c.request("GET", "/?" + qs, headers=headers)
    resp = c.getresponse()
    print(resp.status, resp.reason)
    print(resp.read())

    return 200 <= resp.status < 300


# @responsetest
# def test_bad_escape(keys: Tuple[str, str, Optional[str]], sbad: bytes) -> bool:
#     now = get_current_time()
#     headers = {
#         "x-amz-date": now.encode("ascii"),
#         "host": "sts.amazonaws.com".encode("ascii"),
#     }
#     if keys[2] is not None:
#         headers["x-amz-security-token"] = keys[2].encode("ascii")
#     qs = b"Action=GetCallerIdentity&Bad=" + sbad + b"&Version=2011-06-15"
#     sr = SignedRequest("GET", "/", "us-east-1", "sts", qs, headers)
#     auth = sr.get_authorization_header(keys[0], keys[1])
#     headers["authorization"] = auth

#     c = HTTPSConnection("sts.amazonaws.com")
#     qs = "Action=GetCallerIdentity&Bad=%FF&Version=2011-06-15"
#     c.request("GET", "/?" + qs, headers=headers)
#     resp = c.getresponse()
#     print(resp.status, resp.reason)
#     print(resp.read())

#     return 200 <= resp.status < 300


@responsetest
def test_missing_date(keys: Tuple[str, str, Optional[str]]):
    now = get_current_time()
    headers = {"host": "sts.amazonaws.com"}
    if keys[2] is not None:
        headers["x-amz-security-token"] = keys[2]
    qs = "Action=GetCallerIdentity&Version=2011-06-15"
    sr = SignedRequest("GET", "/", "us-east-1", "sts", qs, headers)
    sr._date = now
    auth = sr.get_authorization_header(keys[0], keys[1])
    headers["authorization"] = auth
    print(headers)

    req = Request(f"https://sts.amazonaws.com/?{qs}", headers=headers)
    try:
        resp = urlopen(req)
        print(resp.read().decode("utf-8"))
    except HTTPError as e:
        print(e)
        print(e.read())


@responsetest
def test_missing_date_and_auth_parameters(keys: Tuple[str, str, Optional[str]]):
    headers = {"host": "sts.amazonaws.com", "authorization": "AWS4-HMAC-SHA256"}
    qs = "Action=GetCallerIdentity&Version=2011-06-15"
    print(headers)

    req = Request(f"https://sts.amazonaws.com/?{qs}", headers=headers)
    try:
        resp = urlopen(req)
        print(resp.read().decode("utf-8"))
    except HTTPError as e:
        print(e)
        print(e.read())


@responsetest
def test_bad_escape_uri(keys: Tuple[str, str, Optional[str]]) -> bool:
    now = get_current_time()
    headers = {
        "x-amz-date": now.encode("ascii"),
        "host": "sts.amazonaws.com".encode("ascii"),
    }
    if keys[2] is not None:
        headers["x-amz-security-token"] = keys[2].encode("ascii")
    qs = b"Action=GetCallerIdentity&Version=2011-06-15"
    sr = SignedRequest("GET", "/%", "us-east-1", "sts", qs, headers)
    sr.allow_bad_url = True
    auth = sr.get_authorization_header(keys[0], keys[1])
    headers["authorization"] = auth

    c = HTTPSConnection("sts.amazonaws.com")
    qs = "Action=GetCallerIdentity&Version=2011-06-15"
    c.request("GET", "/%?" + qs, headers=headers)
    resp = c.getresponse()
    print(resp.status, resp.reason)
    for key, value in resp.getheaders():
        print(f"{key}: {value}")
    print(resp.read())

    return 200 <= resp.status < 300


@responsetest
def test_uri_with_qmark(keys: Tuple[str, str, Optional[str]]) -> bool:
    now = get_current_time()
    headers = {
        "x-amz-date": now.encode("ascii"),
        "host": "sts.amazonaws.com".encode("ascii"),
    }
    if keys[2] is not None:
        headers["x-amz-security-token"] = keys[2].encode("ascii")
    qs = b"Action=GetCallerIdentity&Version=2011-06-15"
    sr = SignedRequest("GET", "/%FF", "us-east-1", "sts", qs, headers)
    auth = sr.get_authorization_header(keys[0], keys[1])
    headers["authorization"] = auth

    c = HTTPSConnection("sts.amazonaws.com")
    qs = "Action=GetCallerIdentity&Version=2011-06-15"
    c.request("GET", "/%3F?" + qs, headers=headers)
    resp = c.getresponse()
    print(resp.status, resp.reason)
    for key, value in resp.getheaders():
        print(f"{key}: {value}")
    print(resp.read())

    return 200 <= resp.status < 300


@responsetest
def test_uri_above_root(keys: Tuple[str, str, Optional[str]]) -> bool:
    now = get_current_time()
    headers = {
        "x-amz-date": now.encode("ascii"),
        "host": "sts.amazonaws.com".encode("ascii"),
    }
    if keys[2] is not None:
        headers["x-amz-security-token"] = keys[2].encode("ascii")
    qs = b"Action=GetCallerIdentity&Version=2011-06-15"
    sr = SignedRequest("GET", "/x", "us-east-1", "sts", qs, headers)
    sr.allow_bad_url = True
    auth = sr.get_authorization_header(keys[0], keys[1])
    headers["authorization"] = auth

    c = HTTPSConnection("sts.amazonaws.com")
    qs = "Action=GetCallerIdentity&Version=2011-06-15"
    c.request("GET", "/x?" + qs, headers=headers)
    resp = c.getresponse()
    print(resp.status, resp.reason)
    for key, value in resp.getheaders():
        print(f"{key}: {value}")
    print(resp.read())

    return 200 <= resp.status < 300


@responsetest
def test_date_too_far_in_past_request(keys: Tuple[str, str, Optional[str]]):
    now = get_time_delta(timedelta(minutes=-30))
    headers = {"x-amz-date": now, "host": "sts.amazonaws.com"}
    if keys[2] is not None:
        headers["x-amz-security-token"] = keys[2]
    qs = "Action=GetCallerIdentity&Version=2011-06-15"
    sr = SignedRequest("GET", "/", "us-east-1", "sts", qs, headers)
    auth = sr.get_authorization_header(keys[0], keys[1])
    headers["authorization"] = auth
    print(headers)

    req = Request(f"https://sts.amazonaws.com/?{qs}", headers=headers)
    try:
        resp = urlopen(req)
        print(resp.read().decode("utf-8"))
    except HTTPError as e:
        print(e)
        print(e.read())


@responsetest
def test_date_too_far_in_future_request(keys: Tuple[str, str, Optional[str]]):
    now = get_time_delta(timedelta(minutes=30))
    headers = {"x-amz-date": now, "host": "sts.amazonaws.com"}
    if keys[2] is not None:
        headers["x-amz-security-token"] = keys[2]
    qs = "Action=GetCallerIdentity&Version=2011-06-15"
    sr = SignedRequest("GET", "/", "us-east-1", "sts", qs, headers)
    auth = sr.get_authorization_header(keys[0], keys[1])
    headers["authorization"] = auth
    print(headers)

    req = Request(f"https://sts.amazonaws.com/?{qs}", headers=headers)
    try:
        resp = urlopen(req)
        print(resp.read().decode("utf-8"))
    except HTTPError as e:
        print(e)
        print(e.read())

@responsetest
def test_auth_header_empty(keys: Tuple[str, str, Optional[str]]):
    now = datetime.utcnow()
    now_8601_micros = now.strftime("%Y%m%dT%H:%M:%S.%fZ")
    now_8601 = now.strftime("%Y%m%dT%H%M%SZ")
    headers = {"date": now_8601_micros, "host": "sts.amazonaws.com"}
    if keys[2] is not None:
        headers["x-amz-security-token"] = keys[2]
    qs = "Action=GetCallerIdentity&Version=2011-06-15"
    sr = SignedRequest("GET", "/", "us-east-1", "sts", qs, headers)
    sr._credential_scope = now_8601[:8] + "/us-east-1/sts/aws4_request"
    sr._date = now_8601
    headers["authorization"] = "Basic asdpfoijqweofqwe"
    print(headers)

    req = Request(f"https://sts.amazonaws.com/?{qs}", headers=headers)
    try:
        resp = urlopen(req)
        print(resp.read().decode("utf-8"))
    except HTTPError as e:
        print(e)
        print(e.read())

@responsetest
def test_auth_header_missing_parameters(keys: Tuple[str, str, Optional[str]]):
    now = datetime.utcnow()
    now_8601_micros = now.strftime("%Y%m%dT%H:%M:%S.%fZ")
    now_8601 = now.strftime("%Y%m%dT%H%M%SZ")
    headers = {"date": now_8601_micros, "host": "sts.amazonaws.com"}
    if keys[2] is not None:
        headers["x-amz-security-token"] = keys[2]
    qs = "Action=GetCallerIdentity&Version=2011-06-15"
    sr = SignedRequest("GET", "/", "us-east-1", "sts", qs, headers)
    sr._credential_scope = now_8601[:8] + "/us-east-1/sts/aws4_request"
    sr._date = now_8601
    headers["authorization"] = "AWS4-HMAC-SHA256"
    print(headers)

    req = Request(f"https://sts.amazonaws.com/?{qs}", headers=headers)
    try:
        resp = urlopen(req)
        print(resp.read().decode("utf-8"))
    except HTTPError as e:
        print(e)
        print(e.read())

@responsetest
def test_auth_header_malformed_parameter(keys: Tuple[str, str, Optional[str]]):
    now = datetime.utcnow()
    now_8601_micros = now.strftime("%Y%m%dT%H:%M:%S.%fZ")
    now_8601 = now.strftime("%Y%m%dT%H%M%SZ")
    headers = {"date": now_8601_micros, "host": "sts.amazonaws.com"}
    if keys[2] is not None:
        headers["x-amz-security-token"] = keys[2]
    qs = "Action=GetCallerIdentity&Version=2011-06-15"
    sr = SignedRequest("GET", "/", "us-east-1", "sts", qs, headers)
    auth = sr.get_authorization_header(keys[0], keys[1])
    auth_params = auth.split(" ", 1)[1]
    auth_params = [param.strip().replace("=", "-'") for param in auth_params.split(",")]
    auth = "AWS4-HMAC-SHA256 " + ", ".join(auth_params)

    sr._credential_scope = now_8601[:8] + "/us-east-1/sts/aws4_request"
    sr._date = now_8601
    headers["authorization"] = auth
    print(headers)

    req = Request(f"https://sts.amazonaws.com/?{qs}", headers=headers)
    try:
        resp = urlopen(req)
        print(resp.read().decode("utf-8"))
    except HTTPError as e:
        print(e)
        print(e.read())

@responsetest
def test_auth_header_extra_parameters(keys: Tuple[str, str, Optional[str]]):
    now = get_current_time()
    headers = {"x-amz-date": now, "host": "sts.amazonaws.com"}
    if keys[2] is not None:
        headers["x-amz-security-token"] = keys[2]
    qs = "Action=GetCallerIdentity&Version=2011-06-15"
    sr = SignedRequest("GET", "/", "us-east-1", "sts", qs, headers)
    auth = sr.get_authorization_header(keys[0], keys[1])
    auth_params = auth.split(" ", 1)[1]
    headers["authorization"] = f"AWS4-HMAC-SHA256 Extra1=Parameter, {auth_params}, Extra2=Parameter"
    print(headers)

    req = Request(f"https://sts.amazonaws.com/?{qs}", headers=headers)
    try:
        resp = urlopen(req)
        print(resp.read().decode("utf-8"))
    except HTTPError as e:
        print(e)
        print(e.read())


@responsetest
def test_auth_header_wrong_alg(keys: Tuple[str, str, Optional[str]]):
    now = get_current_time()
    headers = {"x-amz-date": now, "host": "sts.amazonaws.com"}
    if keys[2] is not None:
        headers["x-amz-security-token"] = keys[2]
    qs = "Action=GetCallerIdentity&Version=2011-06-15"
    sr = SignedRequest("GET", "/", "us-east-1", "sts", qs, headers)
    auth = sr.get_authorization_header(keys[0], keys[1])
    headers["authorization"] = auth.replace("AWS4-HMAC-SHA256", "AWS4-FOO-BAR")
    print(headers)

    req = Request(f"https://sts.amazonaws.com/?{qs}", headers=headers)
    try:
        resp = urlopen(req)
        print(resp.read().decode("utf-8"))
    except HTTPError as e:
        print(e)
        print(e.read())


@responsetest
def test_auth_header_wrong_signature(keys: Tuple[str, str, Optional[str]]):
    now = get_current_time()
    headers = {"x-amz-date": now, "host": "sts.amazonaws.com"}
    if keys[2] is not None:
        headers["x-amz-security-token"] = keys[2]
    qs = "Action=GetCallerIdentity&Version=2011-06-15"
    sr = SignedRequest("GET", "/", "us-east-1", "sts", qs, headers)
    auth = sr.get_authorization_header(keys[0], "a" * 40)
    
    headers["authorization"] = auth
    print(headers)

    req = Request(f"https://sts.amazonaws.com/?{qs}", headers=headers)
    try:
        resp = urlopen(req)
        print(resp.read().decode("utf-8"))
    except HTTPError as e:
        print(e)
        print(e.read())


@responsetest
def test_auth_header_nonunicode_junk(keys: Tuple[str, str, Optional[str]]):
    now = get_current_time()
    headers = {"x-amz-date": now, "host": "sts.amazonaws.com"}
    if keys[2] is not None:
        headers["x-amz-security-token"] = keys[2]
    qs = "Action=GetCallerIdentity&Version=2011-06-15"
    sr = SignedRequest("GET", "/", "us-east-1", "sts", qs, headers)
    auth = sr.get_authorization_header(keys[0], keys[1])
    alg, params = auth.split(" ", 1)
    headers["authorization"] = alg.encode("utf-8") + b" Foo\x80Bar\xa4, " + params.encode("utf-8")
    print(headers)

    req = Request(f"https://sts.amazonaws.com/?{qs}", headers=headers)
    try:
        resp = urlopen(req)
        print(resp.read().decode("utf-8"))
    except HTTPError as e:
        print(e)
        print(e.read())


@responsetest
def test_cscope_wrong_date(keys: Tuple[str, str, Optional[str]]):
    now = get_current_time()
    old = get_time_delta(timedelta(days=-2))
    headers = {"x-amz-date": now, "host": "sts.amazonaws.com"}
    if keys[2] is not None:
        headers["x-amz-security-token"] = keys[2]
    qs = "Action=GetCallerIdentity&Version=2011-06-15"
    sr = SignedRequest("GET", "/", "us-east-1", "sts", qs, headers)
    sr._credential_scope = old[:8] + "/us-east-1/sts/aws4_request"
    auth = sr.get_authorization_header(keys[0], keys[1])
    headers["authorization"] = auth
    print(headers)

    req = Request(f"https://sts.amazonaws.com/?{qs}", headers=headers)
    try:
        resp = urlopen(req)
        print(resp.read().decode("utf-8"))
    except HTTPError as e:
        print(e)
        print(e.read())


@responsetest
def test_cscope_wrong_region(keys: Tuple[str, str, Optional[str]]):
    now = get_current_time()
    headers = {"x-amz-date": now, "host": "sts.amazonaws.com"}
    if keys[2] is not None:
        headers["x-amz-security-token"] = keys[2]
    qs = "Action=GetCallerIdentity&Version=2011-06-15"
    sr = SignedRequest("GET", "/", "us-east-1", "sts", qs, headers)
    sr._credential_scope = now[:8] + "/us-east-99/sts/aws4_request"
    auth = sr.get_authorization_header(keys[0], keys[1])
    headers["authorization"] = auth
    print(headers)

    req = Request(f"https://sts.amazonaws.com/?{qs}", headers=headers)
    try:
        resp = urlopen(req)
        print(resp.read().decode("utf-8"))
    except HTTPError as e:
        print(e)
        print(e.read())


@responsetest
def test_cscope_wrong_service(keys: Tuple[str, str, Optional[str]]):
    now = get_current_time()
    headers = {"x-amz-date": now, "host": "sts.amazonaws.com"}
    if keys[2] is not None:
        headers["x-amz-security-token"] = keys[2]
    qs = "Action=GetCallerIdentity&Version=2011-06-15"
    sr = SignedRequest("GET", "/", "us-east-1", "sts", qs, headers)
    sr._credential_scope = now[:8] + "/us-east-1/foo/aws4_request"
    auth = sr.get_authorization_header(keys[0], keys[1])
    headers["authorization"] = auth
    print(headers)

    req = Request(f"https://sts.amazonaws.com/?{qs}", headers=headers)
    try:
        resp = urlopen(req)
        print(resp.read().decode("utf-8"))
    except HTTPError as e:
        print(e)
        print(e.read())


@responsetest
def test_cscope_wrong_terminator(keys: Tuple[str, str, Optional[str]]):
    now = get_current_time()
    headers = {"x-amz-date": now, "host": "sts.amazonaws.com"}
    if keys[2] is not None:
        headers["x-amz-security-token"] = keys[2]
    qs = "Action=GetCallerIdentity&Version=2011-06-15"
    sr = SignedRequest("GET", "/", "us-east-1", "sts", qs, headers)
    sr._credential_scope = now[:8] + "/us-east-1/sts/aws5_request"
    auth = sr.get_authorization_header(keys[0], keys[1])
    headers["authorization"] = auth
    print(headers)

    req = Request(f"https://sts.amazonaws.com/?{qs}", headers=headers)
    try:
        resp = urlopen(req)
        print(resp.read().decode("utf-8"))
    except HTTPError as e:
        print(e)
        print(e.read())


@responsetest
def test_cscope_wrong_everything(keys: Tuple[str, str, Optional[str]]):
    now = get_current_time()
    future = get_time_delta(timedelta(days=2))
    headers = {"x-amz-date": now, "host": "sts.amazonaws.com"}
    if keys[2] is not None:
        headers["x-amz-security-token"] = keys[2]
    qs = "Action=GetCallerIdentity&Version=2011-06-15"
    sr = SignedRequest("GET", "/", "us-east-1", "sts", qs, headers)
    sr._credential_scope = future[:8] + "/us-east-99/foo/aws5_request"
    auth = sr.get_authorization_header(keys[0], keys[1])
    headers["authorization"] = auth
    print(headers)

    req = Request(f"https://sts.amazonaws.com/?{qs}", headers=headers)
    try:
        resp = urlopen(req)
        print(resp.read().decode("utf-8"))
    except HTTPError as e:
        print(e)
        print(e.read())


@responsetest
def test_cscope_rfc_1123_date(keys: Tuple[str, str, Optional[str]]):
    now = datetime.utcnow()
    now_1123 = now.strftime("%a, %d %b %Y %H:%M:%S GMT")
    now_8601 = now.strftime("%Y%m%dT%H%M%SZ")
    headers = {"date": now_1123, "host": "sts.amazonaws.com"}
    if keys[2] is not None:
        headers["x-amz-security-token"] = keys[2]
    qs = "Action=GetCallerIdentity&Version=2011-06-15"
    sr = SignedRequest("GET", "/", "us-east-1", "sts", qs, headers)
    sr._credential_scope = now_8601[:8] + "/us-east-1/sts/aws4_request"
    auth = sr.get_authorization_header(keys[0], keys[1])
    headers["authorization"] = auth
    print(headers)

    req = Request(f"https://sts.amazonaws.com/?{qs}", headers=headers)
    try:
        resp = urlopen(req)
        print(resp.read().decode("utf-8"))
    except HTTPError as e:
        print(e)
        print(e.read())


@responsetest
def test_cscope_iso_8601_ext_date(keys: Tuple[str, str, Optional[str]]):
    now = datetime.utcnow()
    now_8601_ext = now.strftime("%Y-%m-%dT%H:%M:%SZ")
    now_8601 = now.strftime("%Y%m%dT%H%M%SZ")
    headers = {"date": now_8601_ext, "host": "sts.amazonaws.com"}
    if keys[2] is not None:
        headers["x-amz-security-token"] = keys[2]
    qs = "Action=GetCallerIdentity&Version=2011-06-15"
    sr = SignedRequest("GET", "/", "us-east-1", "sts", qs, headers)
    sr._credential_scope = now_8601[:8] + "/us-east-1/sts/aws4_request"
    sr._date = now_8601
    auth = sr.get_authorization_header(keys[0], keys[1])
    headers["authorization"] = auth
    print(headers)

    req = Request(f"https://sts.amazonaws.com/?{qs}", headers=headers)
    try:
        resp = urlopen(req)
        print(resp.read().decode("utf-8"))
    except HTTPError as e:
        print(e)
        print(e.read())


@responsetest
def test_cscope_rfc_3339_date(keys: Tuple[str, str, Optional[str]]):
    now = datetime.utcnow()
    now_3339 = now.strftime("%Y%m%d %H:%M:%SZ")
    now_8601 = now.strftime("%Y%m%dT%H%M%SZ")
    headers = {"date": now_3339, "host": "sts.amazonaws.com"}
    if keys[2] is not None:
        headers["x-amz-security-token"] = keys[2]
    qs = "Action=GetCallerIdentity&Version=2011-06-15"
    sr = SignedRequest("GET", "/", "us-east-1", "sts", qs, headers)
    sr._credential_scope = now_8601[:8] + "/us-east-1/sts/aws4_request"
    sr._date = now_8601
    auth = sr.get_authorization_header(keys[0], keys[1])
    headers["authorization"] = auth
    print(headers)

    req = Request(f"https://sts.amazonaws.com/?{qs}", headers=headers)
    try:
        resp = urlopen(req)
        print(resp.read().decode("utf-8"))
    except HTTPError as e:
        print(e)
        print(e.read())


@responsetest
def test_cscope_iso_8601_micros(keys: Tuple[str, str, Optional[str]]):
    now = datetime.utcnow()
    now_8601_micros = now.strftime("%Y%m%dT%H:%M:%S.%fZ")
    now_8601 = now.strftime("%Y%m%dT%H%M%SZ")
    headers = {"date": now_8601_micros, "host": "sts.amazonaws.com"}
    if keys[2] is not None:
        headers["x-amz-security-token"] = keys[2]
    qs = "Action=GetCallerIdentity&Version=2011-06-15"
    sr = SignedRequest("GET", "/", "us-east-1", "sts", qs, headers)
    sr._credential_scope = now_8601[:8] + "/us-east-1/sts/aws4_request"
    sr._date = now_8601
    auth = sr.get_authorization_header(keys[0], keys[1])
    headers["authorization"] = auth
    print(headers)

    req = Request(f"https://sts.amazonaws.com/?{qs}", headers=headers)
    try:
        resp = urlopen(req)
        print(resp.read().decode("utf-8"))
    except HTTPError as e:
        print(e)
        print(e.read())


@responsetest
def test_cscope_missing3(keys: Tuple[str, str, Optional[str]]):
    now = get_current_time()
    headers = {"x-amz-date": now, "host": "sts.amazonaws.com"}
    if keys[2] is not None:
        headers["x-amz-security-token"] = keys[2]
    qs = "Action=GetCallerIdentity&Version=2011-06-15"
    sr = SignedRequest("GET", "/", "us-east-1", "sts", qs, headers)
    sr._credential_scope = now[:8]
    auth = sr.get_authorization_header(keys[0], keys[1])
    headers["authorization"] = auth
    print(headers)

    req = Request(f"https://sts.amazonaws.com/?{qs}", headers=headers)
    try:
        resp = urlopen(req)
        print(resp.read().decode("utf-8"))
    except HTTPError as e:
        print(e)
        print(e.read())


@responsetest
def test_cscope_missing2(keys: Tuple[str, str, Optional[str]]):
    now = get_current_time()
    headers = {"x-amz-date": now, "host": "sts.amazonaws.com"}
    if keys[2] is not None:
        headers["x-amz-security-token"] = keys[2]
    qs = "Action=GetCallerIdentity&Version=2011-06-15"
    sr = SignedRequest("GET", "/", "us-east-1", "sts", qs, headers)
    sr._credential_scope = now[:8] + "/us-east-1"
    auth = sr.get_authorization_header(keys[0], keys[1])
    headers["authorization"] = auth
    print(headers)

    req = Request(f"https://sts.amazonaws.com/?{qs}", headers=headers)
    try:
        resp = urlopen(req)
        print(resp.read().decode("utf-8"))
    except HTTPError as e:
        print(e)
        print(e.read())


@responsetest
def test_cscope_missing1(keys: Tuple[str, str, Optional[str]]):
    now = get_current_time()
    headers = {"x-amz-date": now, "host": "sts.amazonaws.com"}
    if keys[2] is not None:
        headers["x-amz-security-token"] = keys[2]
    qs = "Action=GetCallerIdentity&Version=2011-06-15"
    sr = SignedRequest("GET", "/", "us-east-1", "sts", qs, headers)
    sr._credential_scope = now[:8] + "/us-east-1/sts"
    auth = sr.get_authorization_header(keys[0], keys[1])
    headers["authorization"] = auth
    print(headers)

    req = Request(f"https://sts.amazonaws.com/?{qs}", headers=headers)
    try:
        resp = urlopen(req)
        print(resp.read().decode("utf-8"))
    except HTTPError as e:
        print(e)
        print(e.read())


@responsetest
def test_cscope_extra1(keys: Tuple[str, str, Optional[str]]):
    now = get_current_time()
    headers = {"x-amz-date": now, "host": "sts.amazonaws.com"}
    if keys[2] is not None:
        headers["x-amz-security-token"] = keys[2]
    qs = "Action=GetCallerIdentity&Version=2011-06-15"
    sr = SignedRequest("GET", "/", "us-east-1", "sts", qs, headers)
    sr._credential_scope = now[:8] + "/us-east-1/sts/aws4_request/bad"
    auth = sr.get_authorization_header(keys[0], keys[1])
    headers["authorization"] = auth
    print(headers)

    req = Request(f"https://sts.amazonaws.com/?{qs}", headers=headers)
    try:
        resp = urlopen(req)
        print(resp.read().decode("utf-8"))
    except HTTPError as e:
        print(e)
        print(e.read())


@responsetest
def test_cscope_wrong_everything_extra1(keys: Tuple[str, str, Optional[str]]):
    now = get_current_time()
    future = get_time_delta(timedelta(days=2))
    headers = {"x-amz-date": now, "host": "sts.amazonaws.com"}
    if keys[2] is not None:
        headers["x-amz-security-token"] = keys[2]
    qs = "Action=GetCallerIdentity&Version=2011-06-15"
    sr = SignedRequest("GET", "/", "us-east-1", "sts", qs, headers)
    sr._credential_scope = future[:8] + "/us-east-99/notsts/aws5_request/bad"
    auth = sr.get_authorization_header(keys[0], keys[1])
    headers["authorization"] = auth
    print(headers)

    req = Request(f"https://sts.amazonaws.com/?{qs}", headers=headers)
    try:
        resp = urlopen(req)
        print(resp.read().decode("utf-8"))
    except HTTPError as e:
        print(e)
        print(e.read())


@responsetest
def test_mutiple_dates_query_string(keys: Tuple[str, str, Optional[str]]):
    now = get_current_time()
    old = get_time_delta(timedelta(days=-5))
    headers = {"host": "sts.amazonaws.com"}
    cscope = now[:8] + "/us-east-1/sts/aws4_request"
    qs = (f"Action=GetCallerIdentity&Version=2011-06-15&X-Amz-Algorithm=AWS4-HMAC-SHA256&"
          f"X-Amz-Credential={urlencode(keys[0] + '/' + cscope)}&X-Amz-Date={now}&X-Amz-Date={old}&"
          "X-Amz-SignedHeaders=host")
    if keys[2] is not None:
        qs += f"X-Amz-Security-Token={urlencode(keys[2])}"
    sr = SignedRequest("GET", "/", "us-east-1", "sts", qs, headers)
    sr._credential_scope = cscope
    sr._date = now
    sr._signed_headers = "host"
    signature = sr.get_signature(keys[1])
    qs += f"&X-Amz-Signature={signature}"

    req = Request(f"https://sts.amazonaws.com/?{qs}", headers=headers)
    try:
        resp = urlopen(req)
        print(resp.read().decode("utf-8"))
    except HTTPError as e:
        print(e)
        print(e.read())


@responsetest
def test_query_string_multiple_signatures(keys: Tuple[str, str, Optional[str]]):
    now = get_current_time()
    headers = {"host": "sts.amazonaws.com"}
    cscope = now[:8] + "/us-east-1/sts/aws4_request"
    qs = (f"Action=GetCallerIdentity&Version=2011-06-15&X-Amz-Algorithm=AWS4-HMAC-SHA256&"
          f"X-Amz-Credential={urlencode(keys[0] + '/' + cscope)}&X-Amz-Date={now}&"
          "X-Amz-SignedHeaders=host")
    if keys[2] is not None:
        qs += f"X-Amz-Security-Token={urlencode(keys[2])}"
    sr = SignedRequest("GET", "/", "us-east-1", "sts", qs, headers)
    sr._credential_scope = cscope
    sr._date = now
    sr._signed_headers = "host"
    signature = sr.get_signature(keys[1])
    qs += f"&X-Amz-Signature={signature}&X-Amz-Signature=2039482"

    req = Request(f"https://sts.amazonaws.com/?{qs}", headers=headers)
    try:
        resp = urlopen(req)
        print(resp.read().decode("utf-8"))
    except HTTPError as e:
        print(e)
        print(e.read())


@responsetest
def test_query_string_date_in_header(keys: Tuple[str, str, Optional[str]]):
    now = get_current_time()
    headers = {"host": "sts.amazonaws.com", "x-amz-date": now}
    cscope = now[:8] + "/us-east-1/sts/aws4_request"
    qs = (f"Action=GetCallerIdentity&Version=2011-06-15&X-Amz-Algorithm=AWS4-HMAC-SHA256&"
          f"X-Amz-Credential={urlencode(keys[0] + '/' + cscope)}&"
          "X-Amz-SignedHeaders=host")
    if keys[2] is not None:
        qs += f"X-Amz-Security-Token={urlencode(keys[2])}"
    sr = SignedRequest("GET", "/", "us-east-1", "sts", qs, headers)
    sr._credential_scope = cscope
    sr._date = now
    sr._signed_headers = "host"
    signature = sr.get_signature(keys[1])
    qs += f"&X-Amz-Signature={signature}&X-Amz-Signature=2039482"

    req = Request(f"https://sts.amazonaws.com/?{qs}", headers=headers)
    try:
        resp = urlopen(req)
        print(resp.read().decode("utf-8"))
    except HTTPError as e:
        print(e)
        print(e.read())


@responsetest
def test_query_string_missing_alg(keys: Tuple[str, str, Optional[str]]):
    now = get_current_time()
    headers = {"host": "sts.amazonaws.com"}
    cscope = now[:8] + "/us-east-1/sts/aws4_request"
    qs = (f"Action=GetCallerIdentity&Version=2011-06-15&"
          f"X-Amz-Credential={urlencode(keys[0] + '/' + cscope)}&X-Amz-Date={now}&"
          "X-Amz-SignedHeaders=host")
    if keys[2] is not None:
        qs += f"X-Amz-Security-Token={urlencode(keys[2])}"
    sr = SignedRequest("GET", "/", "us-east-1", "sts", qs, headers)
    sr._credential_scope = cscope
    sr._date = now
    sr._signed_headers = "host"
    signature = sr.get_signature(keys[1])
    qs += f"&X-Amz-Signature={signature}"

    req = Request(f"https://sts.amazonaws.com/?{qs}", headers=headers)
    try:
        resp = urlopen(req)
        print(resp.read().decode("utf-8"))
    except HTTPError as e:
        print(e)
        print(e.read())


@responsetest
def test_query_string_wrong_alg(keys: Tuple[str, str, Optional[str]]):
    now = get_current_time()
    headers = {"host": "sts.amazonaws.com"}
    cscope = now[:8] + "/us-east-1/sts/aws4_request"
    qs = (f"Action=GetCallerIdentity&Version=2011-06-15&X-Amz-Algorithm=AWS5-FOO-BAR&"
          f"X-Amz-Credential={urlencode(keys[0] + '/' + cscope)}&X-Amz-Date={now}&"
          "X-Amz-SignedHeaders=host")
    if keys[2] is not None:
        qs += f"X-Amz-Security-Token={urlencode(keys[2])}"
    sr = SignedRequest("GET", "/", "us-east-1", "sts", qs, headers)
    sr._credential_scope = cscope
    sr._date = now
    sr._signed_headers = "host"
    signature = sr.get_signature(keys[1])
    qs += f"&X-Amz-Signature={signature}"

    req = Request(f"https://sts.amazonaws.com/?{qs}", headers=headers)
    try:
        resp = urlopen(req)
        print(resp.read().decode("utf-8"))
    except HTTPError as e:
        print(e)
        print(e.read())


@responsetest
def test_query_string_wrong_alg_first(keys: Tuple[str, str, Optional[str]]):
    now = get_current_time()
    headers = {"host": "sts.amazonaws.com"}
    cscope = now[:8] + "/us-east-1/sts/aws4_request"
    qs = (f"Action=GetCallerIdentity&Version=2011-06-15&X-Amz-Algorithm=AWS5-FOO-BAR&X-Amz-Algorithm=AWS4-HMAC-SHA256&"
          f"X-Amz-Credential={urlencode(keys[0] + '/' + cscope)}&X-Amz-Date={now}&"
          "X-Amz-SignedHeaders=host")
    if keys[2] is not None:
        qs += f"X-Amz-Security-Token={urlencode(keys[2])}"
    sr = SignedRequest("GET", "/", "us-east-1", "sts", qs, headers)
    sr._credential_scope = cscope
    sr._date = now
    sr._signed_headers = "host"
    signature = sr.get_signature(keys[1])
    qs += f"&X-Amz-Signature={signature}"

    req = Request(f"https://sts.amazonaws.com/?{qs}", headers=headers)
    try:
        resp = urlopen(req)
        print(resp.read().decode("utf-8"))
    except HTTPError as e:
        print(e)
        print(e.read())


@responsetest
def test_query_string_wrong_alg_second(keys: Tuple[str, str, Optional[str]]):
    now = get_current_time()
    headers = {"host": "sts.amazonaws.com"}
    cscope = now[:8] + "/us-east-1/sts/aws4_request"
    qs = (f"Action=GetCallerIdentity&Version=2011-06-15&X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Algorithm=AWS5-FOO-BAR&"
          f"X-Amz-Credential={urlencode(keys[0] + '/' + cscope)}&X-Amz-Date={now}&"
          "X-Amz-SignedHeaders=host")
    if keys[2] is not None:
        qs += f"X-Amz-Security-Token={urlencode(keys[2])}"
    sr = SignedRequest("GET", "/", "us-east-1", "sts", qs, headers)
    sr._credential_scope = cscope
    sr._date = now
    sr._signed_headers = "host"
    signature = sr.get_signature(keys[1])
    qs += f"&X-Amz-Signature={signature}"

    req = Request(f"https://sts.amazonaws.com/?{qs}", headers=headers)
    try:
        resp = urlopen(req)
        print(resp.read().decode("utf-8"))
    except HTTPError as e:
        print(e)
        print(e.read())


@responsetest
def test_query_string_missing_credential_date_signedheaders(keys: Tuple[str, str, Optional[str]]):
    now = get_current_time()
    headers = {"host": "sts.amazonaws.com"}
    cscope = now[:8] + "/us-east-1/sts/aws4_request"
    qs = "Action=GetCallerIdentity&Version=2011-06-15&X-Amz-Algorithm=AWS4-HMAC-SHA256"
    sr = SignedRequest("GET", "/", "us-east-1", "sts", qs, headers)
    sr._credential_scope = cscope
    sr._date = now
    sr._signed_headers = "host"
    signature = sr.get_signature(keys[1])
    qs += f"&X-Amz-Signature={signature}"

    req = Request(f"https://sts.amazonaws.com/?{qs}", headers=headers)
    try:
        resp = urlopen(req)
        print(resp.read().decode("utf-8"))
    except HTTPError as e:
        print(e)
        print(e.read())

@responsetest
def test_query_string_missing_credential_date_signedheaders_signature(keys: Tuple[str, str, Optional[str]]):
    headers = {"host": "sts.amazonaws.com"}
    qs = "Action=GetCallerIdentity&Version=2011-06-15&X-Amz-Algorithm=AWS4-HMAC-SHA256"

    req = Request(f"https://sts.amazonaws.com/?{qs}", headers=headers)
    try:
        resp = urlopen(req)
        print(resp.read().decode("utf-8"))
    except HTTPError as e:
        print(e)
        print(e.read())

@responsetest
def test_query_string_missing_credential(keys: Tuple[str, str, Optional[str]]):
    now = get_current_time()
    headers = {"host": "sts.amazonaws.com"}
    cscope = now[:8] + "/us-east-1/sts/aws4_request"
    qs = (f"Action=GetCallerIdentity&Version=2011-06-15&X-Amz-Algorithm=AWS4-HMAC-SHA256&"
          f"X-Amz-Date={now}&X-Amz-SignedHeaders=host")
    if keys[2] is not None:
        qs += f"X-Amz-Security-Token={urlencode(keys[2])}"
    sr = SignedRequest("GET", "/", "us-east-1", "sts", qs, headers)
    sr._credential_scope = cscope
    sr._date = now
    sr._signed_headers = "host"
    signature = sr.get_signature(keys[1])
    qs += f"&X-Amz-Signature={signature}"

    req = Request(f"https://sts.amazonaws.com/?{qs}", headers=headers)
    try:
        resp = urlopen(req)
        print(resp.read().decode("utf-8"))
    except HTTPError as e:
        print(e)
        print(e.read())


@responsetest
def test_query_string_date_rfc_1123(keys: Tuple[str, str, Optional[str]]):
    now = quote(datetime.utcnow().strftime("%a, %d %b %Y %H:%M:%S GMT"))
    headers = {"host": "sts.amazonaws.com"}
    cscope = now[:8] + "/us-east-1/sts/aws4_request"
    qs = (f"Action=GetCallerIdentity&Version=2011-06-15&X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Algorithm=AWS5-FOO-BAR&"
          f"X-Amz-Credential={urlencode(keys[0] + '/' + cscope)}&X-Amz-Date={now}&"
          "X-Amz-SignedHeaders=host")
    if keys[2] is not None:
        qs += f"X-Amz-Security-Token={urlencode(keys[2])}"
    sr = SignedRequest("GET", "/", "us-east-1", "sts", qs, headers)
    sr._credential_scope = cscope
    sr._date = now
    sr._signed_headers = "host"
    signature = sr.get_signature(keys[1])
    qs += f"&X-Amz-Signature={signature}"

    req = Request(f"https://sts.amazonaws.com/?{qs}", headers=headers)
    try:
        resp = urlopen(req)
        print(resp.read().decode("utf-8"))
    except HTTPError as e:
        print(e)
        print(e.read())

@responsetest
def test_missing_signed_header(keys: Tuple[str, str, Optional[str]]):
    now = get_current_time()
    headers = {"x-amz-date": now, "host": "sts.amazonaws.com", "hello": ""}
    if keys[2] is not None:
        headers["x-amz-security-token"] = keys[2]
    qs = "Action=GetCallerIdentity&Version=2011-06-15"
    sr = SignedRequest("GET", "/", "us-east-1", "sts", qs, headers)
    auth = sr.get_authorization_header(keys[0], keys[1])
    headers["authorization"] = auth
    del headers["hello"]
    print(headers)

    req = Request(f"https://sts.amazonaws.com/?{qs}", headers=headers)
    try:
        resp = urlopen(req)
        print(resp.read().decode("utf-8"))
    except HTTPError as e:
        print(e)
        print(e.read())

@responsetest
def test_signed_header_missing_host(keys: Tuple[str, str, Optional[str]]):
    now = get_current_time()
    headers = {"x-amz-date": now, "host": "sts.amazonaws.com", "hello": "world"}
    if keys[2] is not None:
        headers["x-amz-security-token"] = keys[2]
    qs = "Action=GetCallerIdentity&Version=2011-06-15"
    sr = SignedRequest("GET", "/", "us-east-1", "sts", qs, headers)
    sr._signed_headers = "hello;host;x-amz-date"
    auth = sr.get_authorization_header(keys[0], keys[1])
    headers["authorization"] = auth
    print(headers)

    req = Request(f"https://sts.amazonaws.com/?{qs}", headers=headers)
    try:
        resp = urlopen(req)
        print(resp.read().decode("utf-8"))
    except HTTPError as e:
        print(e)
        print(e.read())

@responsetest
def test_signed_header_qs_missing_host(keys: Tuple[str, str, Optional[str]]):
    now = get_current_time()
    headers = {"host": "sts.amazonaws.com", "hello": "world"}
    cscope = now[:8] + "/us-east-1/sts/aws4_request"
    qs = (f"Action=GetCallerIdentity&Version=2011-06-15&X-Amz-Algorithm=AWS4-HMAC-SHA256&"
          f"X-Amz-Credential={urlencode(keys[0] + '/' + cscope)}&"
          f"X-Amz-Date={now}&"
          f"X-Amz-SignedHeaders={urlencode('hello')}")
    if keys[2] is not None:
        qs += f"X-Amz-Security-Token={urlencode(keys[2])}"
    sr = SignedRequest("GET", "/", "us-east-1", "sts", qs, headers)
    sr._credential_scope = cscope
    sr._date = now
    sr._signed_headers = "hello"
    signature = sr.get_signature(keys[1])
    qs += f"&X-Amz-Signature={signature}"

    req = Request(f"https://sts.amazonaws.com/?{qs}", headers=headers)
    try:
        resp = urlopen(req)
        print(resp.read().decode("utf-8"))
    except HTTPError as e:
        print(e)
        print(e.read())

if __name__ == "__main__":
    main(argv[1:])
