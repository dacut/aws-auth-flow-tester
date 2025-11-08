from configparser import ConfigParser
from datetime import datetime, timezone
from functools import cache
from hashlib import sha256
from os import environ
from unittest import TestCase
from unittest import main as unittest_main

from utils import Request, create_ssl_socket, get_config


def non_root_path(request):
    """Corrupt the request by adding a non-root path."""
    request.path = b"bad-path"


def bad_percent_encoding(request):
    """Corrupt the request by adding a bad percent-encoded path."""
    request.path = b"/%G3"


def navigate_above_root(request):
    """Corrupt the request by adding a path that navigates above root."""
    request.path = b"/test/../../bar"


def invalid_method(request):
    """Corrupt the request by changing the method to DELETE."""
    request.method = b"DELETE"


def invalid_content_type(request):
    """Corrupt the request by changing the content-type header to an invalid value."""
    request.headers[b"content-type"] = b"invalid/content-type"


def invalid_query_hex_escape(request):
    """Corrupt the request by adding an invalid hex escape in a query string."""
    if b"?" in request.path:
        request.path += b"&query=%G3"
    else:
        request.path += b"?query=%G3"


def invalid_query_hex_truncated(request):
    """Corrupt the request by adding a truncated hex escape in a query string."""
    if b"?" in request.path:
        request.path += b"&query=%A"
    else:
        request.path += b"?query=%A"


class TestStsOrdering(TestCase):
    """Test how STS behaves with various malformed requests."""

    def setUp(self):
        self.config = get_config()["sts"]

    def test_good(self):
        """Test a well-formed AWS sts:GetCallerIdentity request."""
        body = b"Action=GetCallerIdentity&Version=2011-06-15"
        body_hash = sha256(body).hexdigest()
        request = Request(
            method="POST",
            path=self.config.get("path", "/").encode("utf-8"),
            headers={
                b"host": self.config.get("host").encode("utf-8"),
                b"x-amz-content-sha256": body_hash.encode("utf-8"),
                b"content-type": b"application/x-www-form-urlencoded",
            },
            body=body,
            config=self.config,
        )
        request.add_sigv4_auth(signed_headers=(b"host", b"x-amz-date", b"x-amz-content-sha256"))

        with create_ssl_socket(self.config.get("host"), 443) as ssl_socket:
            request_bytes = request.to_bytes()
            ssl_socket.sendall(request_bytes)
            response = ssl_socket.read(4096)
            self.assertStartsWith(response, b"HTTP/1.1 200 OK\r\n")

    def test_malformed_uri(self):
        """Test malformed URIs and verify they take precedence over other errors."""
        for base_corruptor in (
            non_root_path,
            bad_percent_encoding,
            navigate_above_root,
        ):
            for corruptor in (
                invalid_method,
                invalid_content_type,
                invalid_query_hex_escape,
                invalid_query_hex_truncated,
            ):

                with self.subTest(
                    base_corruptor=base_corruptor.__name__, corruptor=corruptor.__name__
                ):
                    body = b"Action=GetCallerIdentity&Version=2011-06-15"
                    body_hash = sha256(body).hexdigest()
                    request = Request(
                        method="POST",
                        path=self.config.get("path").encode("utf-8"),
                        headers={
                            b"host": self.config.get("host").encode("utf-8"),
                            b"x-amz-content-sha256": body_hash.encode("utf-8"),
                            b"content-type": b"application/x-www-form-urlencoded",
                        },
                        body=body,
                        config=self.config,
                    )
                    request.add_sigv4_auth(
                        signed_headers=(
                            b"host",
                            b"x-amz-date",
                            b"x-amz-content-sha256",
                        ),
                    )

                    # Apply the corruptors to the request
                    base_corruptor(request)
                    corruptor(request)

                    with create_ssl_socket(self.config.get("host"), 443) as ssl_socket:
                        request_bytes = request.to_bytes()
                        ssl_socket.sendall(request_bytes)
                        response = ssl_socket.read(4096)
                        self.assertStartsWith(response, b"HTTP/1.1 400 Bad Request\r\n")

    def test_bad_request_method(self):
        """
        Test requests with invalid methods and verify they take precedence over content-type
        and query string errors.
        """
        for corruptor in (
            invalid_content_type,
            invalid_query_hex_escape,
            invalid_query_hex_truncated,
        ):
            with self.subTest(corruptor=corruptor.__name__):
                body = b"Action=GetCallerIdentity&Version=2011-06-15"
                body_hash = sha256(body).hexdigest()
                request = Request(
                    method="POST",
                    path=self.config.get("path").encode("utf-8"),
                    headers={
                        b"host": self.config.get("host").encode("utf-8"),
                        b"x-amz-content-sha256": body_hash.encode("utf-8"),
                        b"content-type": b"application/x-www-form-urlencoded",
                    },
                    body=body,
                    config=self.config,
                )
                request.add_sigv4_auth(
                    signed_headers=(b"host", b"x-amz-date", b"x-amz-content-sha256"),
                )

                # Apply the corruptor to the request
                invalid_method(request)
                corruptor(request)

                with create_ssl_socket(self.config.get("host"), 443) as ssl_socket:
                    request_bytes = request.to_bytes()
                    ssl_socket.sendall(request_bytes)
                    response = ssl_socket.read(4096)
                    self.assertStartsWith(response, b"HTTP/1.1 302 Found\r\n")


if __name__ == "__main__":
    unittest_main()
