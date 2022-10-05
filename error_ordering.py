#!/usr/bin/env python3
from configparser import ConfigParser
from datetime import datetime, timedelta
from hashlib import sha256
import hmac
from io import BytesIO
from os import environ
from re import compile as re_compile
from socket import create_connection, SHUT_WR
import ssl
from sys import stdout
from typing import Dict, List, Optional, Sequence, Tuple, Union

MULTISPACE = re_compile(rb" {2,}")
ssl_context = ssl.create_default_context()

class SignedRequest:
    s3 = False
    allow_bad_url = False

    def __init__(
        self,
        method: str,
        path: str,
        region: str,
        service: str,
        access_key: str,
        timestamp: Union[datetime, str],
        query: Sequence[Tuple[str, str]] = (),
        headers: Dict[str, Union[bytes, str]] = None,
        body: Optional[bytes] = None,
    ):
        super(SignedRequest, self).__init__()
        self.method = method
        self.path = path
        self.query = list(query)
        self.region = region
        self.service = service
        self.headers = headers if headers is not None else {}
        self.body = body
        self.access_key = access_key
        self.s3 = False
        self.allow_bad_url = True
        self.expires = 300
        self.timestamp = (
            timestamp
            if isinstance(timestamp, str)
            else timestamp.strftime("%Y%m%dT%H%M%SZ")
        )
        self.credential_scope = (
            f"{self.timestamp[:8]}/{self.region}/{self.service}/aws4_request"
        )
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

    @property
    def query_string(self):
        result = []
        for item in self.query:
            if len(item) > 1:
                result.append(f"{item[0]}={item[1]}")
            else:
                result.append(item[0])
        return "&".join(result)

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
                    del parts[i - 1 : i + 1]
                    i -= 1
                else:
                    del parts[0]
                    i = 0
            else:
                parts[i] = url_encode(parts[i])
                i += 1

        if len(parts) == 1:
            result = b"/"
        else:
            result = b"/".join(parts)
        return result

    def get_string_to_sign(self) -> bytes:
        result = BytesIO()
        result.write(b"AWS4-HMAC-SHA256\n")

        result.write(self.timestamp.encode("utf-8"))
        result.write(b"\n")

        result.write(self.credential_scope.encode("utf-8"))
        result.write(b"\n")

        creq = self.get_canonical_request()
        creq_debug = creq.decode("utf-8", errors="replace").split("\n")        
        print("Canonical Request" + "-" * (72 - 17))
        print(f"METHOD>>>>>>>>>>{creq_debug[0]}")
        print(f"URI>>>>>>>>>>>>>{creq_debug[1]}")
        print(f"QUERY STRING>>>>{creq_debug[2]}")
        for i in range(3, len(creq_debug)-3):
            print(f"HEADER>>>>>>>>>>{creq_debug[i]}")
        print(f">>>>>>>>>>>>>>>>{creq_debug[-3]}")
        print(f"SIGNED HEADERS>>{creq_debug[-2]}")
        print(f"HASHED PAYLOAD>>{creq_debug[-1]}")
        print("-" * 72)
        creq_hash = sha256(creq).hexdigest().encode("utf-8")
        result.write(creq_hash)
        return result.getvalue()

    def get_canonical_query_string(self) -> bytes:
        if not self.query:
            return b""

        result: List[bytes] = []

        for el in self.query:
            values = []

            if isinstance(el, (list, tuple)):
                if not el:
                    continue
                key = el[0]
                values = el[1:]
            elif isinstance(el, str):
                parts = el.split("=")
                key = parts[0]
                if len(parts) > 1:
                    values = [parts[1]]
            elif isinstance(el, bytes):
                parts = el.split(b"=")
                key = parts[0]
                if len(parts) > 0:
                    values = [parts[1]]
            else:
                raise TypeError(f"Invalid query string element: {type(el).__name__}")

            if isinstance(key, str):
                key = key.encode("utf-8")

            if not values:
                values = [b""]

            for value in values:
                if isinstance(value, str):
                    value = value.encode("utf-8")
                result.append(key + b"=" + value)

        result.sort()
        return b"&".join(result)

    def get_canonical_headers(self) -> bytes:
        result = BytesIO()

        signed_headers = self.get_signed_headers().split(";")
        headers = {header.lower(): value for header, value in self.headers.items()}
        for key_str, value_str in sorted(headers.items()):
            if key_str not in signed_headers:
                continue
            result.write(key_str.encode("utf-8"))
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

                value = value[: m.start() + 1] + value[m.end() :]

            result.write(value)
            result.write(b"\n")

        return result.getvalue()

    def get_signed_headers(self) -> str:
        if self._signed_headers is None:
            print("Computing signed headers")
            self._signed_headers = ";".join(
                sorted([header.lower() for header in self.headers.keys() if header.lower() not in ["connection"]])
            )
        return self._signed_headers

    def get_payload_hash(self) -> bytes:
        hasher = sha256()
        if self.body is not None:
            hasher.update(self.body)

        return hasher.hexdigest().encode("utf-8")

    def get_signing_key(self, secret_key: str) -> bytes:
        k_secret = secret_key.encode("utf-8")
        k_date = hmac.digest(
            b"AWS4" + k_secret, self.timestamp[:8].encode("utf-8"), "sha256"
        )
        k_region = hmac.digest(k_date, self.region.encode("utf-8"), "sha256")
        k_service = hmac.digest(k_region, self.service.encode("utf-8"), "sha256")
        k_signing = hmac.digest(k_service, b"aws4_request", "sha256")
        return k_signing

    def get_signature(self, secret_key: str) -> str:
        sts = self.get_string_to_sign()
        print("String to Sign" + "-" * (72 - 14))
        sts_debug = sts.decode("utf-8", errors="replace").split("\n")
        print(f"ALGORITHM>>>>>>>>{sts_debug[0]}")
        print(f"TIMESTAMP>>>>>>>>{sts_debug[1]}")
        print(f"CREDENTIAL SCOPE>{sts_debug[2]}")
        print(f"HASHED REQUEST>>>{sts_debug[3]}")
        print("-" * 72)
        return hmac.new(self.get_signing_key(secret_key), sts, "sha256").hexdigest()

    def get_authorization_header(self, access_key: str, secret_key: str) -> str:
        return (
            f"AWS4-HMAC-SHA256 Credential={access_key}/{self.credential_scope}, "
            f"SignedHeaders={self.get_signed_headers()}, Signature={self.get_signature(secret_key)}"
        )

    def get_authorization_pre_query_string(
        self, access_key: str
    ) -> Tuple[Tuple[str, str]]:
        return (
            (
                "X-Amz-Algorithm",
                "AWS4-HMAC-SHA256",
            ),
            (
                "X-Amz-Credential",
                url_encode(f"{access_key}/{self.credential_scope}"),
            ),
            (
                "X-Amz-Date",
                url_encode(f"{self.timestamp}"),
            ),
            (
                "X-Amz-Expires",
                url_encode(f"{self.expires}"),
            ),
            (
                "X-Amz-SignedHeaders",
                url_encode(f"{self.get_signed_headers()}"),
            ),
        )

    def get_authorization_signature_query_string(
        self, secret_key: str
    ) -> Tuple[str, str]:
        return (
            "X-Amz-Signature",
            f"{self.get_signature(secret_key)}",
        )


def is_rfc3986_unreserved(c: int) -> bool:
    # c must be numeric (48-57), ASCII upper (65-90), ASCII lower (97-122), or '-' (45), '.' (46), '_' (95), '~' (126).
    return (
        (48 <= c <= 57) or (65 <= c <= 90) or (97 <= c <= 122) or c in (45, 46, 95, 126)
    )


def url_encode(url: bytes) -> bytes:
    if isinstance(url, str):
        return_string = True
        url = url.encode("utf-8")
    elif isinstance(url, bytes):
        return_string = False
    else:
        raise TypeError(f"Invalid type for url: {type(url).__name__}")

    result = BytesIO()

    for c in url:
        if is_rfc3986_unreserved(c):
            result.write(bytes((c,)))
        else:
            result.write(b"%" + b"%02X" % c)
    
    if return_string:
        return result.getvalue().decode("utf-8")

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


def main():
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

    run(keys)


def run(keys: Tuple[str, str, Optional[str]]) -> None:
    now = get_current_time()
    body = b"Action=GetCallerIdentity&Version=2011-06-15"
    headers = {
        # "x-amz-date": now,
        "host": "sts.amazonaws.com",
        "content-type": "application/x-www-form-urlencoded",
        "content-length": str(len(body)),
        "x-amz-date": now,
    }
    access_key, secret_key = keys[:2]
    request = SignedRequest("POST", "/", "us-east-1", "sts", access_key=access_key, timestamp=now, query=[], headers=headers, body=body)
    auth_pre_qs = request.get_authorization_pre_query_string(access_key)
    request.query += auth_pre_qs
    request.query.append(("X-Amz-Date", get_time_delta(timedelta(hours=1))))
    request.query.append(("X-Amz-Algorithm", get_time_delta(timedelta(hours=1))))
    auth_sig_qs = request.get_authorization_signature_query_string(secret_key)
    request.query.append(auth_sig_qs)
    # auth_header = request.get_authorization_header(access_key, secret_key)
    # request.headers["Authorization"] = "Basic asdoifjwoaqeijfwoief"
    print(request.query_string)

    http_request = b"POST /?" + request.query_string.encode("utf-8") + b" HTTP/1.1\r\n"
    for key, value in request.headers.items():
        http_request += f"{key}: {value}\r\n".encode("utf-8")
    http_request += b"Connection: close\r\n"
    http_request += b"\r\n"
    http_request += request.body
    http_request += b"\r\n"
    stdout.write(http_request.decode("utf-8", errors="replace"))

    raw = create_connection(("sts.amazonaws.com", 443))
    with ssl_context.wrap_socket(raw, server_hostname="sts.amazonaws.com") as s:
        s.sendall(http_request)

        buffer = BytesIO()
        while True:
            data = s.recv(65536)
            if not data:
                break
        
            buffer.write(data)
    
    print(buffer.getvalue().decode("utf-8", errors="replace"))

if __name__ == "__main__":
    main()
