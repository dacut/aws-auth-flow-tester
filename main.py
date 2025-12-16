import socket
from base64 import b64encode
from configparser import ConfigParser
from datetime import datetime, timezone
from functools import cache
from hashlib import sha256
from io import BytesIO
from os import environ
from sys import stdout
from unittest import main as unittest_main
from zlib import crc32

from utils import Request, TestCase, create_ssl_socket, elog, get_config, hexdump


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


def remove_auth_parameters(request):
    """Corrupt the request by removing all auth parameters."""
    path_parts = request.path.split(b"?", 1)

    # Remove query parameters related to SigV4 authentication
    if len(path_parts) == 2:
        path = path_parts[0]
        query = path_parts[1]
        query_keep = []
        for param in query.split(b"&", 1):
            lparam = param.lower()
            key = lparam.split(b"=", 1)[0]

            if key not in (
                b"x-amz-algorithm",
                b"x-amz-credential",
                b"x-amz-signature",
                b"x-amz-date",
                b"x-amz-signedheaders",
            ):
                query_keep.append(param)

        request.path = path + b"?" + b"&".join(query_keep)

    # Remove any authorization header
    for header in list(request.headers.keys()):
        if header.lower() == b"authorization":
            del request.headers[header]


class Sts(TestCase):
    """Test how STS behaves with various malformed requests."""

    def setUp(self):
        self.config = get_config()["sts"]

    def test_good(self):
        """Test a well-formed AWS sts:GetCallerIdentity request."""
        with elog() as log:
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
            request.add_sigv4_auth(
                signed_headers=(b"host", b"x-amz-date", b"x-amz-content-sha256")
            )

            with create_ssl_socket(self.config.get("host"), 443) as ssl_socket:
                request_bytes = request.to_bytes()
                log.debug(
                    "Request:\n%s", request_bytes.decode("utf-8", errors="ignore")
                )
                ssl_socket.sendall(request_bytes)
                response = ssl_socket.read(4096)
                log.debug("Response:\n%s", response.decode("utf-8", errors="ignore"))
                self.assertStartsWith(response, b"HTTP/1.1 200 OK\r\n")

    def test_good_query_parameters(self):
        """Test a well-formed AWS sts:GetCallerIdentity request with extra query parameters."""
        with elog() as log:
            body = b"Action=GetCallerIdentity&Version=2011-06-15"
            body_hash = sha256(body).hexdigest()
            request = Request(
                method="POST",
                path=(self.config.get("path", "/") + "?X=30").encode("utf-8"),
                headers={
                    b"host": self.config.get("host").encode("utf-8"),
                    b"x-amz-content-sha256": body_hash.encode("utf-8"),
                    b"content-type": b"application/x-www-form-urlencoded",
                },
                body=body,
                config=self.config,
            )
            request.add_sigv4_auth(
                signed_headers=(b"host", b"x-amz-date", b"x-amz-content-sha256")
            )

            with create_ssl_socket(self.config.get("host"), 443) as ssl_socket:
                request_bytes = request.to_bytes()
                log.debug(
                    "Request:\n%s", request_bytes.decode("utf-8", errors="ignore")
                )
                ssl_socket.sendall(request_bytes)
                response = ssl_socket.read(4096)
                log.debug("Response:\n%s", response.decode("utf-8", errors="ignore"))
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
                remove_auth_parameters,
            ):

                with self.subTest(
                    base_corruptor=base_corruptor.__name__, corruptor=corruptor.__name__
                ):
                    with elog() as log:
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

                        with create_ssl_socket(
                            self.config.get("host"), 443
                        ) as ssl_socket:
                            request_bytes = request.to_bytes()
                            log.debug(
                                "Request:\n%s",
                                request_bytes.decode("utf-8", errors="ignore"),
                            )
                            ssl_socket.sendall(request_bytes)
                            response = ssl_socket.read(4096)
                            log.debug(
                                "Response:\n%s",
                                response.decode("utf-8", errors="ignore"),
                            )
                            self.assertStartsWith(
                                response, b"HTTP/1.1 400 Bad Request\r\n"
                            )

    def test_bad_request_method(self):
        """
        Test requests with invalid methods and verify they take precedence over content-type \
        and query string errors.
        """
        for corruptor in (
            invalid_content_type,
            invalid_query_hex_escape,
            invalid_query_hex_truncated,
            remove_auth_parameters,
        ):
            with self.subTest(corruptor=corruptor.__name__):
                with elog() as log:
                    body = b"Action=GetCallerIdentity&Version=2011-06-15"
                    request = Request(
                        method="POST",
                        path=self.config.get("path").encode("utf-8"),
                        headers={
                            b"host": self.config.get("host").encode("utf-8"),
                            b"content-type": b"application/x-www-form-urlencoded",
                        },
                        body=body,
                        config=self.config,
                    )
                    request.add_sigv4_auth(signed_headers=(b"host", b"x-amz-date"))

                    # Apply the corruptor to the request
                    invalid_method(request)
                    corruptor(request)

                    with create_ssl_socket(self.config.get("host"), 443) as ssl_socket:
                        request_bytes = request.to_bytes()
                        log.debug(
                            "Request:\n%s",
                            request_bytes.decode("utf-8", errors="ignore"),
                        )
                        ssl_socket.sendall(request_bytes)
                        response = ssl_socket.read(4096)
                        log.debug(
                            "Response:\n%s",
                            response.decode("utf-8", errors="ignore"),
                        )
                        self.assertStartsWith(response, b"HTTP/1.1 302 Found\r\n")

    def test_missing_auth_parameters(self):
        """Test requests with missing authentication parameters."""
        with elog() as log:
            body = b"Action=GetCallerIdentity&Version=2011-06-15"
            body_hash = sha256(body).hexdigest()
            request = Request(
                method="POST",
                path=self.config.get("path").encode("utf-8"),
                headers={
                    b"host": self.config.get("host").encode("utf-8"),
                    b"content-type": b"application/x-www-form-urlencoded; charset=utf-8",
                },
                body=body,
                config=self.config,
            )
            request.add_sigv4_auth(signed_headers=(b"host", b"x-amz-date"))

            # Remove auth parameters
            remove_auth_parameters(request)

            with create_ssl_socket(self.config.get("host"), 443) as ssl_socket:
                request_bytes = request.to_bytes()
                log.debug(
                    "Request:\n%s", request_bytes.decode("utf-8", errors="ignore")
                )
                ssl_socket.sendall(request_bytes)
                response = ssl_socket.read(65536)
                log.debug("Response:\n%s", response.decode("utf-8", errors="ignore"))
                self.assertStartsWith(response, b"HTTP/1.1 403 Forbidden\r\n")

    def test_duplicate_auth_parameters(self):
        """Test requests with duplicate authentication parameters."""
        with elog() as log:
            body = b"Action=GetCallerIdentity&Version=2011-06-15"
            request = Request(
                method="POST",
                path=self.config.get("path").encode("utf-8"),
                headers={
                    b"host": self.config.get("host").encode("utf-8"),
                    b"content-type": b"application/x-www-form-urlencoded",
                },
                body=body,
                config=self.config,
            )
            request.add_sigv4_auth(signed_headers=(b"host", b"x-amz-date"))
            auth = request.headers.get(b"authorization")
            auth_parts = auth.split(b" ", 1)[1].split(b", ")
            request.path += b"?X-Amz-Algorithm=AWS4-HMAC-SHA256"

            for part in auth_parts:
                key, value = part.split(b"=", 1)
                key = key.lower()
                if key == b"credential":
                    request.path += b"&X-Amz-Credential=" + value
                elif key == b"signature":
                    request.path += b"&X-Amz-Signature=" + value
                elif key == b"signedheaders":
                    request.path += b"&X-Amz-SignedHeaders=" + value

            with create_ssl_socket(self.config.get("host"), 443) as ssl_socket:
                request_bytes = request.to_bytes()
                log.debug(
                    "Request:\n%s", request_bytes.decode("utf-8", errors="ignore")
                )
                ssl_socket.sendall(request_bytes)
                response = ssl_socket.read(4096)
                log.debug("Response:\n%s", response.decode("utf-8", errors="ignore"))
                self.assertStartsWith(response, b"HTTP/1.1 403 Forbidden\r\n")


class S3(TestCase):
    """Test how S3 behaves with various malformed requests."""

    def setUp(self):
        self.config = get_config()["s3"]

    def test_good_signed_single(self):
        """
        Test a well-formed PUT request to S3 that places the actual payload checksum value into \
        the x-amz-content-sha256 header and uploads the payload in a single chunk.
        """
        with elog() as log:
            body = b"This is the contents of the test object"
            signed_headers = (
                b"content-length",
                b"content-type",
                b"host",
                b"x-amz-content-sha256",
                b"x-amz-date",
            )
            request = Request(
                method="PUT",
                path=self.config.get("prefix").encode("utf-8") + b"good-signed-single",
                headers={
                    b"host": self.config.get("host").encode("utf-8"),
                    b"content-type": b"application/octet-stream",
                    b"content-length": str(len(body)).encode("utf-8"),
                    b"x-amz-content-sha256": sha256(body).hexdigest().encode("utf-8"),
                    b"Expect": b"100-continue",
                },
                body=body,
                config=self.config,
            )
            request.add_sigv4_auth(signed_headers=signed_headers)
            request.body = None

            with create_ssl_socket(self.config.get("host"), 443) as ssl_socket:
                request_bytes = request.to_bytes()
                log.debug(
                    "Request:\n%s", request_bytes.decode("utf-8", errors="ignore")
                )
                ssl_socket.sendall(request_bytes)
                response = ssl_socket.read(4096)
                log.debug("Response:\n%s", response.decode("utf-8", errors="ignore"))
                self.assertStartsWith(response, b"HTTP/1.1 100 Continue\r\n")

                log.debug("Sending body:\n%s", body.decode("utf-8", errors="ignore"))
                ssl_socket.sendall(body)
                response = ssl_socket.read(4096)
                log.debug("Response:\n%s", response.decode("utf-8", errors="ignore"))
                self.assertStartsWith(response, b"HTTP/1.1 200 OK\r\n")

    def test_good_unsigned_single(self):
        """
        Test a well-formed PUT request to S3 that sets x-amz-content-sha256 to UNSIGNED-PAYLOAD \
        and uploads the payload in a single chunk.
        """
        with elog() as log:
            body = b"This is the contents of the test object"
            signed_headers = (
                b"content-length",
                b"content-type",
                b"host",
                b"x-amz-content-sha256",
                b"x-amz-date",
            )
            request = Request(
                method="PUT",
                path=self.config.get("prefix").encode("utf-8")
                + b"good-unsigned-single",
                headers={
                    b"host": self.config.get("host").encode("utf-8"),
                    b"content-type": b"application/octet-stream",
                    b"content-length": str(len(body)).encode("utf-8"),
                    b"x-amz-content-sha256": b"UNSIGNED-PAYLOAD",
                    b"Expect": b"100-continue",
                },
                body=None,
                config=self.config,
            )
            request.add_sigv4_auth(
                signed_headers=signed_headers, payload_hash=b"UNSIGNED-PAYLOAD"
            )
            request.body = None

            with create_ssl_socket(self.config.get("host"), 443) as ssl_socket:
                request_bytes = request.to_bytes()
                log.debug(
                    "Request:\n%s", request_bytes.decode("utf-8", errors="ignore")
                )
                ssl_socket.sendall(request_bytes)
                response = ssl_socket.read(4096)
                log.debug("Response:\n%s", response.decode("utf-8", errors="ignore"))
                self.assertStartsWith(response, b"HTTP/1.1 100 Continue\r\n")

                ssl_socket.sendall(body)
                response = ssl_socket.read(4096)
                self.assertStartsWith(response, b"HTTP/1.1 200 OK\r\n")

    def test_good_streaming_unsigned(self):
        """
        Test a well-formed PUT request to S3 that sets x-amz-content-sha256 to
        STREAMING-UNSIGNED-PAYLOAD-TRAILER and uses chunked transfer encoding.
        """
        with elog() as log:
            raw_chunk_size = 65536
            http_chunk_size = 16384
            n_chunks = 10
            decoded_length = raw_chunk_size * n_chunks

            # Create the AWS chunked encoded body
            body = BytesIO()
            raw_chunk = b"A" * raw_chunk_size
            hasher = sha256()

            for i in range(n_chunks):
                body.write(f"{len(raw_chunk):x}".encode("utf-8") + b"\r\n")
                body.write(raw_chunk)
                body.write(b"\r\n")
                hasher.update(raw_chunk)

            # Terminate the aws-chunked body
            body.write(b"0\r\n")

            # Add the checksum trailer
            body.write(
                b"x-amz-checksum-sha256:" + b64encode(hasher.digest()) + b"\r\n\r\n\r\n"
            )

            signed_headers = (
                b"content-type",
                b"host",
                b"transfer-encoding",
                b"x-amz-content-sha256",
                b"x-amz-date",
                b"x-amz-decoded-content-length",
                b"x-amz-sdk-checksum-algorithm",
                b"x-amz-trailer",
            )
            request = Request(
                method="PUT",
                path=self.config.get("prefix").encode("utf-8")
                + b"good-streaming-unsigned",
                headers={
                    b"host": self.config.get("host").encode("utf-8"),
                    b"content-encoding": b"aws-chunked",
                    b"content-type": b"application/octet-stream",
                    b"expect": b"100-continue",
                    b"transfer-encoding": b"chunked",
                    b"x-amz-content-sha256": b"STREAMING-UNSIGNED-PAYLOAD-TRAILER",
                    b"x-amz-decoded-content-length": str(decoded_length).encode(
                        "utf-8"
                    ),
                    b"x-amz-sdk-checksum-algorithm": b"SHA256",
                    b"x-amz-trailer": b"x-amz-checksum-sha256",
                },
                body=None,
                config=self.config,
            )
            request.add_sigv4_auth(
                signed_headers=signed_headers,
                payload_hash=b"STREAMING-UNSIGNED-PAYLOAD-TRAILER",
            )
            request.body = None

            with create_ssl_socket(self.config.get("host"), 443) as ssl_socket:
                request_bytes = request.to_bytes()
                log.debug(
                    "Request:\n%s", request_bytes.decode("utf-8", errors="ignore")
                )
                ssl_socket.sendall(request_bytes)
                response = ssl_socket.read(4096)
                log.debug("Response:\n%s", response.decode("utf-8", errors="ignore"))
                self.assertStartsWith(response, b"HTTP/1.1 100 Continue\r\n")

                body_length = body.tell()
                body.seek(0)

                chunk_id = 1
                while True:
                    chunk = body.read(http_chunk_size)
                    if not chunk:
                        break
                    log.debug("Sending chunk %d of size %d bytes", chunk_id, len(chunk))
                    chunk_id += 1
                    ssl_socket.sendall(
                        f"{len(chunk):x}".encode("utf-8") + b"\r\n" + chunk + b"\r\n"
                    )

                log.debug("Sending terminating chunk")
                ssl_socket.sendall(b"0\r\n\r\n")
                response = ssl_socket.read(4096)
                log.debug("Response:\n%s", response.decode("utf-8", errors="ignore"))
                self.assertStartsWith(response, b"HTTP/1.1 200 OK\r\n")


if __name__ == "__main__":
    unittest_main()
