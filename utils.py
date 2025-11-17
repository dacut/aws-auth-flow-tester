import hashlib
import hmac
import io
import re
import socket
import ssl
import unittest
from configparser import ConfigParser
from contextlib import contextmanager
from datetime import datetime, timezone
from functools import cache, wraps
from logging import DEBUG, NOTSET
from logging import Formatter as BaseLogFormatter
from logging import Handler as LogHandler
from logging import StreamHandler, getLogger
from os import environ
from os.path import exists
from random import randint
from sys import stderr
from time import strftime
from types import NoneType

# The default SSL context for secure connections
SSL_CONTEXT = ssl.create_default_context()

# Algorithm for AWS SigV4
ALGORITHM_AWS_SIGV4 = b"AWS4-HMAC-SHA256"

# Algorithm for AWS SigV4a
ALGORITHM_AWS_SIGV4A = b"AWS4-ECDSA-P256-SHA256"

# The default AWS region
DEFAULT_REGION = "us-west-2"

# The default AWS service
DEFAULT_SERVICE = "sts"

# Default AWS access key ID
DEFAULT_AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"

# Default AWS secret access key
DEFAULT_AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

# Default path to use
DEFAULT_PATH = "/"


def create_ssl_socket(
    hostname, port=443, *, context=SSL_CONTEXT, server_hostname=None, **kwargs
):
    """Creates an SSL socket connected to the specified hostname and port."""

    if server_hostname is None:
        server_hostname = hostname

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s = context.wrap_socket(s, server_hostname=server_hostname, **kwargs)
    s.connect((hostname, port))
    return s


class Request:
    """A possibly malformed AWS SigV4 HTTP request."""

    def __init__(
        self,
        method=b"GET",
        path=b"/",
        version=b"HTTP/1.1",
        headers=None,
        body=None,
        timestamp=None,
        config=None,
    ):
        self.method = method
        self.path = path
        self.version = version
        self._headers = {} if headers is None else dict(headers)
        self.body = body
        self.timestamp = (
            timestamp if timestamp is not None else datetime.now(timezone.utc)
        )
        self.set_header(b"x-amz-date", self.timestamp.strftime("%Y%m%dT%H%M%SZ"))
        self.config = config
        if self.body is not None and self.method in (b"POST", b"PUT", b"PATCH"):
            self.set_header(b"content-length", str(len(self.body)).encode("utf-8"))

    @property
    def method(self):
        return self._method

    @method.setter
    def method(self, value):
        if isinstance(value, str):
            value = value.encode("utf-8")
        elif not isinstance(value, bytes):
            raise TypeError("HTTP method must be str or bytes")
        self._method = value

    @property
    def path(self):
        return self._path

    @path.setter
    def path(self, value):
        if isinstance(value, str):
            value = value.encode("utf-8")
        elif not isinstance(value, bytes):
            raise TypeError("HTTP path must be str or bytes")
        self._path = value

    @property
    def version(self):
        return self._version

    @version.setter
    def version(self, value):
        if isinstance(value, str):
            value = value.encode("utf-8")
        elif not isinstance(value, bytes):
            raise TypeError("HTTP version must be str or bytes")
        self._version = value

    @property
    def headers(self):
        return self._headers

    @headers.setter
    def headers(self, value):
        if not isinstance(value, dict):
            raise TypeError("HTTP headers must be a dict")
        new_headers = {}
        for k, v in value.items():
            if isinstance(k, str):
                k = k.encode("utf-8")
            elif not isinstance(k, bytes):
                raise TypeError("HTTP header names must be str or bytes")
            if isinstance(v, str):
                v = v.encode("utf-8")
            elif not isinstance(v, bytes):
                raise TypeError("HTTP header values must be str or bytes")
            new_headers[k] = v

        self._headers = new_headers

    def set_header(self, key, value):
        """Sets a header for the request."""
        if isinstance(key, str):
            key = key.encode("utf-8")
        elif not isinstance(key, bytes):
            raise TypeError("HTTP header names must be str or bytes")
        if isinstance(value, str):
            value = value.encode("utf-8")
        elif not isinstance(value, bytes):
            raise TypeError("HTTP header values must be str or bytes")
        self._headers[key] = value

    @property
    def body(self):
        return self._body

    @body.setter
    def body(self, value):
        if isinstance(value, str):
            value = value.encode("utf-8")
        elif not isinstance(value, (bytes, NoneType)):
            raise TypeError("HTTP body must be str, bytes, or None")
        self._body = value

    @property
    def canonical_uri(self):
        """Returns the canonical URI for the request."""
        return self.path.split(b"?", 1)[0]

    @property
    def query_string(self):
        """Returns the query string, if any, for the request"""
        if b"?" in self.path:
            return self.path.split(b"?", 1)[1]
        else:
            return b""

    @property
    def get_canonical_query_string(self):
        """Returns the canonical query string for the request."""
        qs = self.query_string
        if not qs:
            return b""
        pairs = qs.split(b"&")
        pairs.sort()
        result = []
        for pair in pairs:
            parts = pair.split(b"=", 1)
            if len(parts) == 2:
                key, value = parts
            else:
                key = parts[0]
                value = b""
            result.append(key + b"=" + value)
        return b"&".join(result)

    def add_sigv4_auth(self, signed_headers=None, payload_hash=None):
        """Adds a default SigV4 Authorization header to the request."""

        if signed_headers is None:
            signed_headers = (b"content-type", b"host", b"x-amz-date")
        canonical_request = self.get_canonical_request(signed_headers=signed_headers, payload_hash=payload_hash)
        signing_key = self.get_signing_key()
        string_to_sign = self.get_string_to_sign(canonical_request)
        signature = self.get_signature(string_to_sign, signing_key)
        credential = (
            self.config.get("aws_access_key_id").encode("utf-8")
            + b"/"
            + self.timestamp.strftime("%Y%m%d").encode("utf-8")
            + b"/"
            + self.config.get("region").encode("utf-8")
            + b"/"
            + self.config.get("service").encode("utf-8")
            + b"/aws4_request"
        )
        authorization_header = (
            b"AWS4-HMAC-SHA256 "
            + b"Credential="
            + credential
            + b", SignedHeaders="
            + b";".join(signed_headers)
            + b", Signature="
            + signature.encode("utf-8")
        )
        self.set_header(b"authorization", authorization_header)

    def get_canonical_headers(self, signed_headers):
        """Returns the canonical headers for the request."""
        result = []
        for header in signed_headers:
            if isinstance(header, str):
                header = header.encode("utf-8")
            try:
                value = self.headers[header].strip()
            except KeyError:
                raise KeyError(f"Header {header.decode('utf-8')} not found in request")

            result.append(header.lower() + b":" + value)
        result.sort()
        return b"\n".join(result) + b"\n"

    def get_canonical_request(self, signed_headers, payload_hash=None):
        """Returns the canonical request for the HTTP request."""
        signed_headers = [
            h.encode("utf-8") if isinstance(h, str) else h for h in signed_headers
        ]
        signed_headers = [h.lower() for h in signed_headers]
        signed_headers.sort()
        canonical_headers = self.get_canonical_headers(signed_headers)

        if payload_hash is None:
            if self.body is None:
                payload_hash = sha256hex(b"").encode("utf-8")
            else:
                payload_hash = sha256hex(self.body).encode("utf-8")
        elif isinstance(payload_hash, str):
            payload_hash = payload_hash.encode("utf-8")
        elif not isinstance(payload_hash, bytes):
            raise TypeError("Payload hash must be str or bytes")

        canonical_request = (
            self.method
            + b"\n"
            + self.canonical_uri
            + b"\n"
            + self.get_canonical_query_string
            + b"\n"
            + canonical_headers
            + b"\n"
            + b";".join(signed_headers)
            + b"\n"
            + payload_hash
        )
        return canonical_request

    def get_string_to_sign(self, canonical_request, algorithm=ALGORITHM_AWS_SIGV4):
        """Returns the string to sign for the HTTP request."""
        timestamp = self.timestamp.strftime("%Y%m%dT%H%M%SZ").encode("utf-8")

        if not isinstance(canonical_request, bytes):
            raise TypeError("Canonical request must be bytes")

        if isinstance(algorithm, str):
            algorithm = algorithm.encode("utf-8")
        elif not isinstance(algorithm, bytes):
            raise TypeError("Algorithm must be str or bytes")

        if algorithm == ALGORITHM_AWS_SIGV4:
            credential_scope = (
                timestamp[:8]
                + b"/"
                + self.config.get("region").encode("utf-8")
                + b"/"
                + self.config.get("service").encode("utf-8")
                + b"/aws4_request"
            )
        elif algorithm == ALGORITHM_AWS_SIGV4A:
            credential_scope = (
                timestamp[:8] + b"/" + self.config.get("service").encode("utf-8") + b"/aws4_request"
            )
        else:
            raise ValueError("Unsupported algorithm: " + algorithm.decode("utf-8"))

        return (
            algorithm
            + b"\n"
            + timestamp
            + b"\n"
            + credential_scope
            + b"\n"
            + hashlib.sha256(canonical_request).hexdigest().encode("utf-8")
        )

    def get_signing_key(self, algorithm=ALGORITHM_AWS_SIGV4):
        """Returns the signing key given an AWS secret key."""
        if algorithm == ALGORITHM_AWS_SIGV4:
            date_key = hmac.new(
                b"AWS4" + self.config.get("aws_secret_access_key").encode("utf-8"),
                self.timestamp.strftime("%Y%m%d").encode("utf-8"),
                hashlib.sha256,
            ).digest()
            region_key = hmac.new(date_key, self.config.get("region").encode("utf-8"), hashlib.sha256).digest()
            service_key = hmac.new(
                region_key, self.config.get("service").encode("utf-8"), hashlib.sha256
            ).digest()
            signing_key = hmac.new(
                service_key, b"aws4_request", hashlib.sha256
            ).digest()
            return signing_key

        if algorithm == ALGORITHM_AWS_SIGV4A:
            raise NotImplementedError(
                "SigV4a signing key generation is not yet implemented"
            )

        raise ValueError("Unsupported algorithm: " + algorithm.decode("utf-8"))

    def get_signature(self, string_to_sign, signing_key, algorithm=ALGORITHM_AWS_SIGV4):
        """Returns the signature for the HTTP request."""

        if not isinstance(string_to_sign, bytes):
            raise TypeError("String to sign must be bytes")
        if not isinstance(signing_key, bytes):
            raise TypeError("Signing key must be bytes")

        if algorithm == ALGORITHM_AWS_SIGV4:
            return hmac.new(signing_key, string_to_sign, hashlib.sha256).hexdigest()
        if algorithm == ALGORITHM_AWS_SIGV4A:
            raise NotImplementedError(
                "SigV4a signature generation is not yet implemented"
            )
        raise ValueError("Unsupported algorithm: " + algorithm.decode("utf-8"))

    def to_bytes(self):
        """Converts the HTTP request to bytes."""
        result = io.BytesIO()
        result.write(self.method + b" " + self.path + b" " + self.version + b"\r\n")
        for k, v in self.headers.items():
            result.write(k + b": " + v + b"\r\n")
        result.write(b"\r\n")
        if self.body is not None:
            result.write(self.body)
        return result.getvalue()


@cache
def get_config():
    if not exists("test-config.ini"):
        raise FileNotFoundError("Configuration file 'test-config.ini' not found.")
    config = ConfigParser()
    config.read("test-config.ini")
    return config


def sha256hex(content):
    """Returns the SHA256 hex digest of the given content."""
    if isinstance(content, str):
        content = content.encode("utf-8")
    elif not isinstance(content, bytes):
        raise TypeError("Content must be str or bytes")

    sha256 = hashlib.sha256(content)
    return sha256.hexdigest()


class RecordingLogHandler(LogHandler):
    """Log handler that just records the log events that have happened."""
    def __init__(self, wrapped, level=NOTSET):
        super().__init__(level)
        self.wrapped = wrapped
        self.do_write = False
        self.records = []
    
    def emit(self, record):
        self.records.append(record)

    def flush(self):
        """Flushes all recorded log events to the wrapped handler."""
        if self.do_write:
            for record in self.records:
                self.wrapped.emit(record)
        self.records.clear()

class Formatter(BaseLogFormatter):
    """A log formatter that logs times in ISO 8601 using English style decimals."""
    def formatTime(self, record, datefmt=None):
        ct = self.converter(record.created)
        return strftime("%Y-%m-%dT%H:%M:%S", ct) + f".{int(record.msecs):03d}Z"


@contextmanager
def elog():
    """Context manager that logs only if an exception leaks out of this context."""
    base_handler = StreamHandler(stderr)
    base_handler.setFormatter(Formatter("%(asctime)s [%(levelname)s] %(filename)s %(lineno)d: %(message)s"))
    handler = RecordingLogHandler(base_handler)

    logger_name = "elog.%08x" % randint(0, 0xFFFFFFFF)
    logger = getLogger(logger_name)

    handlers = logger.handlers[:]
    for h in handlers:
        logger.removeHandler(h)

    logger.propagate = False
    logger.parent = None
    logger.addHandler(handler)
    logger.setLevel(DEBUG)
    try:
        yield logger
    except Exception as e:
        handler.do_write = True
        handler.flush()
        raise


_MULTISPACE = re.compile(r" +")

class TestCase(unittest.TestCase):
    """A test case that fixes how short descriptions are returned."""
    
    def shortDescription(self):
        """
        Returns a one-line description of the test, or None if no description has been provided.

        This implementation returns the docstring with newlines and leading spaces removed.
        """
        doc = self._testMethodDoc
        if doc:
            return _MULTISPACE.sub(" ", doc.strip().replace("\n", " "))
        return None


def hexdump(data, fd=stderr):
    """Prints a hex dump of the given data to the specified file descriptor."""
    for i in range(0, len(data), 16):
        chunk = data[i:i+16]
        hex_bytes = ' '.join(f"{b:02x}" for b in chunk)
        ascii_bytes = ''.join((chr(b) if 32 <= b < 127 else '.') for b in chunk)
        fd.write(f"{i:08x}: {hex_bytes:<48}  {ascii_bytes}\n")
