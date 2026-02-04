import socket
from base64 import b64encode
from configparser import ConfigParser
from crc32c import crc32c, CRC32CHash
from datetime import datetime, timezone
from functools import cache
from hashlib import sha256
from io import BytesIO
from os import environ
from struct import pack
from sys import stdout
from unittest import main as unittest_main
from zlib import crc32

from utils import (
    Request,
    TestCase,
    create_ssl_socket,
    elog,
    get_config,
    ALGORITHM_AWS4_HMAC_SHA256_TRAILER,
    SHA256_EMPTY_STRING_HEXBYTES,
)


EXAMPLE_CONFIG = {
    "aws_access_key_id": "AKIAIOSFODNN7EXAMPLE",
    "aws_secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    "host": "s3.amazonaws.com",
    "prefix": "/examplebucket/",
    "region": "us-east-1",
    "service": "s3",
}


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

    def test_bad_single_no_x_amz_content_sha256(self):
        """
        Test a malformed PUT request to S3 that does not use aws-chunked encoding and omits the
        x-amz-content-sha256 header.
        """
        with elog() as log:
            body = b"This is the contents of the test object"
            signed_headers = (
                b"content-length",
                b"content-type",
                b"host",
                b"x-amz-date",
            )
            request = Request(
                method="PUT",
                path=self.config.get("prefix").encode("utf-8") + b"good-signed-single",
                headers={
                    b"host": self.config.get("host").encode("utf-8"),
                    b"content-type": b"application/octet-stream",
                    b"content-length": str(len(body)).encode("utf-8"),
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
                self.assertStartsWith(response, b"HTTP/1.1 400 Bad Request\r\n")

    def test_good_unsigned_single(self):
        """
        Test a well-formed PUT request to S3 that sets the x-amz-content-sha256 header to \
        UNSIGNED-PAYLOAD and uploads the payload in a single chunk.
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
                    log.debug(
                        "Sending HTTP chunk %d of size %d bytes", chunk_id, len(chunk)
                    )
                    chunk_id += 1
                    ssl_socket.sendall(
                        f"{len(chunk):x}".encode("utf-8") + b"\r\n" + chunk + b"\r\n"
                    )

                log.debug("Sending terminating chunk")
                ssl_socket.sendall(b"0\r\n\r\n")
                response = ssl_socket.read(4096)
                log.debug("Response:\n%s", response.decode("utf-8", errors="ignore"))
                self.assertStartsWith(response, b"HTTP/1.1 200 OK\r\n")

    def test_good_streaming_signed(self):
        """
        Test a well-formed PUT request to S3 that sets x-amz-content-sha256 to
        STREAMING-AWS4-HMAC-SHA256-PAYLOAD and uses chunked transfer encoding.
        """
        with elog() as log:
            raw_chunk_size = 65536
            http_chunk_size = (
                65536
                + len(f"{raw_chunk_size:x}")
                + len(";chunk-signature=")
                + 64
                + 2
                + 2
            )
            n_chunks = 10
            decoded_length = raw_chunk_size * n_chunks

            signed_headers = (
                b"content-type",
                b"host",
                b"transfer-encoding",
                b"x-amz-content-sha256",
                b"x-amz-date",
                b"x-amz-decoded-content-length",
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
                    b"x-amz-content-sha256": b"STREAMING-AWS4-HMAC-SHA256-PAYLOAD",
                    b"x-amz-decoded-content-length": str(decoded_length).encode(
                        "utf-8"
                    ),
                },
                body=None,
                config=self.config,
            )
            request.add_sigv4_auth(
                signed_headers=signed_headers,
                payload_hash=b"STREAMING-AWS4-HMAC-SHA256-PAYLOAD",
            )

            with create_ssl_socket(self.config.get("host"), 443) as ssl_socket:
                request_bytes = request.to_bytes()
                log.debug(
                    "Request:\n%s", request_bytes.decode("utf-8", errors="ignore")
                )
                ssl_socket.sendall(request_bytes)
                response = ssl_socket.read(4096)
                log.debug("Response:\n%s", response.decode("utf-8", errors="ignore"))
                self.assertStartsWith(response, b"HTTP/1.1 100 Continue\r\n")

                # Get the seed signature from the headers.
                # See https://docs.aws.amazon.com/AmazonS3/latest/API/sigv4-streaming.html#sigv4-chunked-upload-sig-calculation-chunk0
                prev_signature = request.seed_signature

                # Create the AWS chunked encoded body
                body = BytesIO()
                raw_chunk = b"A" * raw_chunk_size
                raw_chunk_hash = sha256(raw_chunk).hexdigest().encode("utf-8")
                hasher = sha256()

                for i in range(n_chunks):
                    if ssl_socket.pending() > 0:
                        response = ssl_socket.read(4096)
                        self.fail(
                            "Received unexpected response while still sending data: "
                            + response.decode("utf-8", errors="ignore")
                        )

                    # Calculate the next chunk signature
                    signature = request.get_chunk_sigv4_auth(
                        prev_signature, raw_chunk_hash
                    )

                    body.write(
                        f"{len(raw_chunk):x};chunk-signature={signature}".encode(
                            "utf-8"
                        )
                        + b"\r\n"
                    )
                    body.write(raw_chunk)
                    body.write(b"\r\n")
                    hasher.update(raw_chunk)
                    prev_signature = signature

                # Terminate the aws-chunked body
                signature = request.get_chunk_sigv4_auth(
                    prev_signature, SHA256_EMPTY_STRING_HEXBYTES
                )
                body.write(f"0;chunk-signature={signature}\r\n\r\n".encode("utf-8"))
                body.seek(0)

                chunk_id = 1
                while True:
                    chunk = body.read(http_chunk_size)
                    if not chunk:
                        break
                    log.debug(
                        "Sending HTTP chunk %d of size %d bytes", chunk_id, len(chunk)
                    )
                    chunk_nl = chunk.find(b"\r\n")
                    if chunk_nl >= 0:
                        chunk_print = chunk[:chunk_nl]
                    else:
                        chunk_print = chunk

                    log.debug(
                        "Chunk start: %s", chunk_print.decode("utf-8", errors="ignore")
                    )
                    chunk_id += 1
                    ssl_socket.sendall(
                        f"{len(chunk):x}".encode("utf-8") + b"\r\n" + chunk + b"\r\n"
                    )

                log.debug("Sending terminating chunk")
                ssl_socket.sendall(b"0\r\n\r\n")
                response = ssl_socket.read(4096)
                log.debug("Response:\n%s", response.decode("utf-8", errors="ignore"))
                self.assertStartsWith(response, b"HTTP/1.1 200 OK\r\n")

    def test_good_streaming_signed_trailer(self):
        """
        Test a well-formed PUT request to S3 that sets x-amz-content-sha256 to
        STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER and uses chunked transfer encoding.
        """
        with elog() as log:
            raw_chunk_size = 65536
            http_chunk_size = (
                65536
                + len(f"{raw_chunk_size:x}")
                + len(";chunk-signature=")
                + 64
                + 2
                + 2
            )
            n_chunks = 10
            decoded_length = raw_chunk_size * n_chunks

            signed_headers = (
                b"content-type",
                b"host",
                b"transfer-encoding",
                b"x-amz-content-sha256",
                b"x-amz-date",
                b"x-amz-decoded-content-length",
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
                    b"x-amz-content-sha256": b"STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER",
                    b"x-amz-decoded-content-length": str(decoded_length).encode(
                        "utf-8"
                    ),
                    b"x-amz-trailer": b"x-amz-checksum-sha256",
                },
                body=None,
                config=self.config,
            )
            request.add_sigv4_auth(
                signed_headers=signed_headers,
                payload_hash=b"STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER",
            )

            with create_ssl_socket(self.config.get("host"), 443) as ssl_socket:
                request_bytes = request.to_bytes()
                log.debug(
                    "Request:\n%s", request_bytes.decode("utf-8", errors="ignore")
                )
                ssl_socket.sendall(request_bytes)
                response = ssl_socket.read(4096)
                log.debug("Response:\n%s", response.decode("utf-8", errors="ignore"))
                self.assertStartsWith(response, b"HTTP/1.1 100 Continue\r\n")

                # Get the seed signature from the headers.
                # See https://docs.aws.amazon.com/AmazonS3/latest/API/sigv4-streaming.html#sigv4-chunked-upload-sig-calculation-chunk0
                prev_signature = request.seed_signature

                # Create the AWS chunked encoded body
                body = BytesIO()
                raw_chunk = b"A" * raw_chunk_size
                raw_chunk_hash = sha256(raw_chunk).hexdigest().encode("utf-8")
                hasher = sha256()

                for i in range(n_chunks):
                    if ssl_socket.pending() > 0:
                        response = ssl_socket.read(4096)
                        self.fail(
                            "Received unexpected response while still sending data: "
                            + response.decode("utf-8", errors="ignore")
                        )

                    # Calculate the next chunk signature
                    signature = request.get_chunk_sigv4_auth(
                        prev_signature, raw_chunk_hash
                    )

                    body.write(
                        f"{len(raw_chunk):x};chunk-signature={signature}".encode(
                            "utf-8"
                        )
                        + b"\r\n"
                    )
                    body.write(raw_chunk)
                    body.write(b"\r\n")
                    hasher.update(raw_chunk)
                    prev_signature = signature

                # Terminate the aws-chunked body
                signature = request.get_chunk_sigv4_auth(
                    prev_signature, SHA256_EMPTY_STRING_HEXBYTES
                )
                body.write(f"0;chunk-signature={signature}\r\n".encode("utf-8"))
                trailer = b"x-amz-checksum-sha256:" + b64encode(hasher.digest())
                trailer_sig = request.get_trailer_sigv4_auth(
                    signature, sha256(trailer + b"\n").hexdigest().encode("utf-8")
                ).encode("utf-8")
                body.write(
                    trailer
                    + b"\r\nx-amz-trailer-signature:"
                    + trailer_sig
                    + b"\r\n\r\n"
                )
                body.seek(0)

                chunk_id = 1
                while True:
                    chunk = body.read(http_chunk_size)
                    if not chunk:
                        break
                    log.debug(
                        "Sending HTTP chunk %d of size %d bytes", chunk_id, len(chunk)
                    )
                    chunk_nl = chunk.find(b"\r\n")
                    if chunk_nl >= 0 and len(chunk) >= 512:
                        chunk_print = chunk[:chunk_nl]
                    else:
                        chunk_print = chunk

                    log.debug(
                        "Chunk start: %s", chunk_print.decode("utf-8", errors="ignore")
                    )
                    chunk_id += 1
                    ssl_socket.sendall(
                        f"{len(chunk):x}".encode("utf-8") + b"\r\n" + chunk + b"\r\n"
                    )

                log.debug("Sending terminating chunk")
                ssl_socket.sendall(b"0\r\n\r\n")
                response = ssl_socket.read(4096)
                log.debug("Response:\n%s", response.decode("utf-8", errors="ignore"))
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
                    log.debug(
                        "Sending HTTP chunk %d of size %d bytes", chunk_id, len(chunk)
                    )
                    chunk_id += 1
                    ssl_socket.sendall(
                        f"{len(chunk):x}".encode("utf-8") + b"\r\n" + chunk + b"\r\n"
                    )

                log.debug("Sending terminating chunk")
                ssl_socket.sendall(b"0\r\n\r\n")
                response = ssl_socket.read(4096)
                log.debug("Response:\n%s", response.decode("utf-8", errors="ignore"))
                self.assertStartsWith(response, b"HTTP/1.1 200 OK\r\n")

    def test_bad_streaming_signed_missing_decoded_content_length(self):
        """
        Test a malformed PUT request to S3 that sets x-amz-content-sha256 to
        STREAMING-AWS4-HMAC-SHA256-PAYLOAD and uses chunked transfer encoding,
        but is missing the x-amz-decoded-content-length header.
        """
        with elog() as log:
            signed_headers = (
                b"content-type",
                b"host",
                b"transfer-encoding",
                b"x-amz-content-sha256",
                b"x-amz-date",
            )
            request = Request(
                method="PUT",
                path=self.config.get("prefix").encode("utf-8")
                + b"bad-streaming-signed-missing-x-amz-decoded-content-length",
                headers={
                    b"host": self.config.get("host").encode("utf-8"),
                    b"content-encoding": b"aws-chunked",
                    b"content-type": b"application/octet-stream",
                    b"expect": b"100-continue",
                    b"transfer-encoding": b"chunked",
                    b"x-amz-content-sha256": b"STREAMING-AWS4-HMAC-SHA256-PAYLOAD",
                },
                body=None,
                config=self.config,
            )
            request.add_sigv4_auth(
                signed_headers=signed_headers,
                payload_hash=b"STREAMING-AWS4-HMAC-SHA256-PAYLOAD",
            )

            with create_ssl_socket(self.config.get("host"), 443) as ssl_socket:
                request_bytes = request.to_bytes()
                log.debug(
                    "Request:\n%s", request_bytes.decode("utf-8", errors="ignore")
                )
                ssl_socket.sendall(request_bytes)
                response = ssl_socket.read(4096)
                log.debug("Response:\n%s", response.decode("utf-8", errors="ignore"))
                self.assertStartsWith(response, b"HTTP/1.1 411 Length Required\r\n")

    def test_bad_streaming_signed_missing_amz_content_sha256_header(self):
        """
        Test a malformed streaming PUT request to S3 that omits the
        x-amz-content-sha256 header.
        """
        with elog() as log:
            signed_headers = (
                b"content-type",
                b"host",
                b"transfer-encoding",
                b"x-amz-date",
            )
            request = Request(
                method="PUT",
                path=self.config.get("prefix").encode("utf-8")
                + b"bad-streaming-signed-missing-amz-content-sha256",
                headers={
                    b"host": self.config.get("host").encode("utf-8"),
                    b"content-encoding": b"aws-chunked",
                    b"content-type": b"application/octet-stream",
                    b"expect": b"100-continue",
                    b"transfer-encoding": b"chunked",
                    b"x-amz-decoded-content-length": b"655360",
                },
                body=None,
                config=self.config,
            )
            request.add_sigv4_auth(
                signed_headers=signed_headers,
                payload_hash=b"STREAMING-AWS4-HMAC-SHA256-PAYLOAD",
            )

            with create_ssl_socket(self.config.get("host"), 443) as ssl_socket:
                request_bytes = request.to_bytes()
                log.debug(
                    "Request:\n%s", request_bytes.decode("utf-8", errors="ignore")
                )
                ssl_socket.sendall(request_bytes)
                response = ssl_socket.read(4096)
                log.debug("Response:\n%s", response.decode("utf-8", errors="ignore"))
                self.assertStartsWith(response, b"HTTP/1.1 400 Bad Request\r\n")

    def test_bad_streaming_malformed_amz_content_sha256_header(self):
        """
        Test a malformed streaming PUT request to S3 that sets x-amz-content-sha256 to
        invalid bytes (\xff\xff).
        """
        with elog() as log:
            signed_headers = (
                b"content-type",
                b"host",
                b"transfer-encoding",
                b"x-amz-content-sha256",
                b"x-amz-date",
            )
            request = Request(
                method="PUT",
                path=self.config.get("prefix").encode("utf-8")
                + b"bad-streaming-malformed-amz-content-sha256",
                headers={
                    b"host": self.config.get("host").encode("utf-8"),
                    b"content-encoding": b"aws-chunked",
                    b"content-type": b"application/octet-stream",
                    b"expect": b"100-continue",
                    b"transfer-encoding": b"chunked",
                    b"x-amz-content-sha256": b"\xff\xff",
                    b"x-amz-decoded-content-length": b"655360",
                },
                body=None,
                config=self.config,
            )
            request.add_sigv4_auth(
                signed_headers=signed_headers,
                payload_hash=b"STREAMING-AWS4-HMAC-SHA256-PAYLOAD",
            )

            with create_ssl_socket(self.config.get("host"), 443) as ssl_socket:
                request_bytes = request.to_bytes()
                log.debug(
                    "Request:\n%s", request_bytes.decode("utf-8", errors="ignore")
                )
                ssl_socket.sendall(request_bytes)
                response = ssl_socket.read(4096)
                log.debug("Response:\n%s", response.decode("utf-8", errors="ignore"))
                self.assertStartsWith(response, b"HTTP/1.1 400 Bad Request\r\n")

    def test_bad_streaming_signed_missing_multiple_headers(self):
        """
        Test a malformed streaming PUT request to S3 that omits both the
        x-amz-content-sha256 and x-amz-decoded-content-length headers.
        """
        with elog() as log:
            signed_headers = (
                b"content-type",
                b"host",
                b"transfer-encoding",
                b"x-amz-date",
            )
            request = Request(
                method="PUT",
                path=self.config.get("prefix").encode("utf-8")
                + b"bad-streaming-signed-missing-amz-content-sha256",
                headers={
                    b"host": self.config.get("host").encode("utf-8"),
                    b"content-encoding": b"aws-chunked",
                    b"content-type": b"application/octet-stream",
                    b"expect": b"100-continue",
                    b"transfer-encoding": b"chunked",
                },
                body=None,
                config=self.config,
            )
            request.add_sigv4_auth(
                signed_headers=signed_headers,
                payload_hash=b"STREAMING-AWS4-HMAC-SHA256-PAYLOAD",
            )

            with create_ssl_socket(self.config.get("host"), 443) as ssl_socket:
                request_bytes = request.to_bytes()
                log.debug(
                    "Request:\n%s", request_bytes.decode("utf-8", errors="ignore")
                )
                ssl_socket.sendall(request_bytes)
                response = ssl_socket.read(4096)
                log.debug("Response:\n%s", response.decode("utf-8", errors="ignore"))
                self.assertStartsWith(response, b"HTTP/1.1 400 Bad Request\r\n")

    def test_streaming_signed_setup(self):
        """
        Test that well-formed PUT request to S3 that sets x-amz-content-sha256 to
        STREAMING-AWS4-HMAC-SHA256-PAYLOAD using AWS chunked encoding matches the documentation
        example code.
        """
        with elog() as log:
            decoded_length = 1024 * 65  # 65 kiB to match the documentation example.
            content_length = 66824
            timestamp = datetime(2013, 5, 24, 0, 0, 0, tzinfo=timezone.utc)

            signed_headers = (
                b"content-encoding",
                b"content-length",
                b"host",
                b"x-amz-content-sha256",
                b"x-amz-date",
                b"x-amz-decoded-content-length",
                b"x-amz-storage-class",
            )
            request = Request(
                method="PUT",
                path=EXAMPLE_CONFIG.get("prefix").encode("utf-8") + b"chunkObject.txt",
                headers={
                    b"host": EXAMPLE_CONFIG.get("host").encode("utf-8"),
                    b"content-encoding": b"aws-chunked",
                    b"content-length": str(content_length).encode("utf-8"),
                    b"x-amz-content-sha256": b"STREAMING-AWS4-HMAC-SHA256-PAYLOAD",
                    b"x-amz-decoded-content-length": str(decoded_length).encode(
                        "utf-8"
                    ),
                    b"x-amz-storage-class": b"REDUCED_REDUNDANCY",
                },
                body=None,
                config=EXAMPLE_CONFIG,
                timestamp=timestamp,
            )
            creq = request.get_canonical_request(
                signed_headers, b"STREAMING-AWS4-HMAC-SHA256-PAYLOAD"
            )
            self.assertEqual(
                creq,
                b"""\
PUT
/examplebucket/chunkObject.txt

content-encoding:aws-chunked
content-length:66824
host:s3.amazonaws.com
x-amz-content-sha256:STREAMING-AWS4-HMAC-SHA256-PAYLOAD
x-amz-date:20130524T000000Z
x-amz-decoded-content-length:66560
x-amz-storage-class:REDUCED_REDUNDANCY

content-encoding;content-length;host;x-amz-content-sha256;x-amz-date;x-amz-decoded-content-length;x-amz-storage-class
STREAMING-AWS4-HMAC-SHA256-PAYLOAD""",
                "Canonical request does not match expected value.",
            )
            signing_key = request.get_signing_key()
            string_to_sign = request.get_string_to_sign(creq)
            self.assertEqual(
                string_to_sign,
                b"""\
AWS4-HMAC-SHA256
20130524T000000Z
20130524/us-east-1/s3/aws4_request
cee3fed04b70f867d036f722359b0b1f2f0e5dc0efadbc082b76c4c60e316455""",
                "String to sign does not match expected value.",
            )
            request.add_sigv4_auth(
                signed_headers=signed_headers,
                payload_hash=b"STREAMING-AWS4-HMAC-SHA256-PAYLOAD",
            )
            request.body = None

            request_bytes = request.to_bytes()
            log.debug("Request:\n%s", request_bytes.decode("utf-8", errors="ignore"))

            self.assertEqual(
                request.seed_signature,
                "4f232c4386841ef735655705268965c44a0e4690baa4adea153f7db9fa80a0a9",
                "Seed signature does not match expected value.",
            )

            body = BytesIO()

            # Create the AWS chunked encoded body
            chunk1 = b"a" * 65536
            chunk2 = b"a" * 1024

            chunk1_string_to_sign = request.get_chunk_string_to_sign(
                request.seed_signature, sha256(chunk1).hexdigest().encode("utf-8")
            )
            self.assertEqual(
                chunk1_string_to_sign,
                b"""\
AWS4-HMAC-SHA256-PAYLOAD
20130524T000000Z
20130524/us-east-1/s3/aws4_request
4f232c4386841ef735655705268965c44a0e4690baa4adea153f7db9fa80a0a9
e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
bf718b6f653bebc184e1479f1935b8da974d701b893afcf49e701f3e2f9f9c5a""",
                "Chunk 1 string to sign does not match expected value.",
            )

            chunk1_sig = request.get_chunk_sigv4_auth(
                request.seed_signature, sha256(chunk1).hexdigest().encode("utf-8")
            )
            self.assertEqual(
                chunk1_sig,
                "ad80c730a21e5b8d04586a2213dd63b9a0e99e0e2307b0ade35a65485a288648",
                "Chunk 1 signature does not match expected value.",
            )
            body.write(
                f"{len(chunk1):x};chunk-signature={chunk1_sig}".encode("utf-8")
                + b"\r\n"
            )
            body.write(chunk1)
            body.write(b"\r\n")

            chunk2_sig = request.get_chunk_sigv4_auth(
                chunk1_sig, sha256(chunk2).hexdigest().encode("utf-8")
            )
            self.assertEqual(
                chunk2_sig,
                "0055627c9e194cb4542bae2aa5492e3c1575bbb81b612b7d234b86a503ef5497",
                "Chunk 2 signature does not match expected value.",
            )
            body.write(
                f"{len(chunk2):x};chunk-signature={chunk2_sig}".encode("utf-8")
                + b"\r\n"
            )
            body.write(chunk2)
            body.write(b"\r\n")

            chunk3_sig = request.get_chunk_sigv4_auth(
                chunk2_sig, SHA256_EMPTY_STRING_HEXBYTES
            )
            self.assertEqual(
                chunk3_sig,
                "b6c6ea8a5354eaf15b3cb7646744f4275b71ea724fed81ceb9323e279d449df9",
                "Chunk 3 signature does not match expected value.",
            )
            body.write(f"0;chunk-signature={chunk3_sig}\r\n".encode("utf-8"))
            body.write(b"\r\n")
            self.assertEqual(
                body.tell(),
                content_length,
                "Total body length does not match expected value.",
            )

    def test_streaming_signed_trailer_setup(self):
        """
        Test that well-formed PUT request to S3 that sets x-amz-content-sha256 to
        STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER using AWS chunked encoding matches the
        documentation example code.
        """
        with elog() as log:
            decoded_length = 1024 * 65  # 65 kiB to match the documentation example.
            content_length = 66824
            timestamp = datetime(2013, 5, 24, 0, 0, 0, tzinfo=timezone.utc)

            signed_headers = (
                b"content-encoding",
                b"host",
                b"x-amz-content-sha256",
                b"x-amz-date",
                b"x-amz-decoded-content-length",
                b"x-amz-storage-class",
                b"x-amz-trailer",
            )
            request = Request(
                method="PUT",
                path=EXAMPLE_CONFIG.get("prefix").encode("utf-8") + b"chunkObject.txt",
                headers={
                    b"host": EXAMPLE_CONFIG.get("host").encode("utf-8"),
                    b"content-encoding": b"aws-chunked",
                    b"content-length": str(content_length).encode("utf-8"),
                    b"x-amz-content-sha256": b"STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER",
                    b"x-amz-decoded-content-length": str(decoded_length).encode(
                        "utf-8"
                    ),
                    b"x-amz-storage-class": b"REDUCED_REDUNDANCY",
                    b"x-amz-trailer": b"x-amz-checksum-crc32c",
                },
                body=None,
                config=EXAMPLE_CONFIG,
                timestamp=timestamp,
            )
            creq = request.get_canonical_request(
                signed_headers, b"STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER"
            )
            self.assertEqual(
                creq,
                b"""\
PUT
/examplebucket/chunkObject.txt

content-encoding:aws-chunked
host:s3.amazonaws.com
x-amz-content-sha256:STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER
x-amz-date:20130524T000000Z
x-amz-decoded-content-length:66560
x-amz-storage-class:REDUCED_REDUNDANCY
x-amz-trailer:x-amz-checksum-crc32c

content-encoding;host;x-amz-content-sha256;x-amz-date;x-amz-decoded-content-length;x-amz-storage-class;x-amz-trailer
STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER""",
                "Canonical request does not match expected value.",
            )
            string_to_sign = request.get_string_to_sign(creq)
            self.assertEqual(
                string_to_sign,
                b"""\
AWS4-HMAC-SHA256
20130524T000000Z
20130524/us-east-1/s3/aws4_request
44d48b8c2f70eae815a0198cc73d7a546a73a93359c070abbaa5e6c7de112559""",
                "String to sign does not match expected value.",
            )
            request.add_sigv4_auth(
                signed_headers=signed_headers,
                payload_hash=b"STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER",
            )
            request.body = None

            request_bytes = request.to_bytes()
            log.debug("Request:\n%s", request_bytes.decode("utf-8", errors="ignore"))

            self.assertEqual(
                request.seed_signature,
                "106e2a8a18243abcf37539882f36619c00e2dfc72633413f02d3b74544bfeb8e",
                "Seed signature does not match expected value.",
            )

            body = BytesIO()

            # Create the AWS chunked encoded body
            chunk1 = b"a" * 65536
            chunk2 = b"a" * 1024
            crc_result = b64encode(pack(">I", crc32c(chunk1 + chunk2)))
            self.assertEqual(
                crc_result, b"sOO8/Q==", "CRC32C value does not match expected."
            )

            chunk1_string_to_sign = request.get_chunk_string_to_sign(
                request.seed_signature, sha256(chunk1).hexdigest().encode("utf-8")
            )
            self.assertEqual(
                chunk1_string_to_sign,
                b"""\
AWS4-HMAC-SHA256-PAYLOAD
20130524T000000Z
20130524/us-east-1/s3/aws4_request
106e2a8a18243abcf37539882f36619c00e2dfc72633413f02d3b74544bfeb8e
e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
bf718b6f653bebc184e1479f1935b8da974d701b893afcf49e701f3e2f9f9c5a""",
                "Chunk 1 string to sign does not match expected value.",
            )

            chunk1_sig = request.get_chunk_sigv4_auth(
                request.seed_signature, sha256(chunk1).hexdigest().encode("utf-8")
            )
            self.assertEqual(
                chunk1_sig,
                "b474d8862b1487a5145d686f57f013e54db672cee1c953b3010fb58501ef5aa2",
                "Chunk 1 signature does not match expected value.",
            )
            body.write(
                f"{len(chunk1):x};chunk-signature={chunk1_sig}".encode("utf-8")
                + b"\r\n"
            )
            body.write(chunk1)
            body.write(b"\r\n")

            chunk2_sig = request.get_chunk_sigv4_auth(
                chunk1_sig, sha256(chunk2).hexdigest().encode("utf-8")
            )
            self.assertEqual(
                chunk2_sig,
                "1c1344b170168f8e65b41376b44b20fe354e373826ccbbe2c1d40a8cae51e5c7",
                "Chunk 2 signature does not match expected value.",
            )
            body.write(
                f"{len(chunk2):x};chunk-signature={chunk2_sig}".encode("utf-8")
                + b"\r\n"
            )
            body.write(chunk2)
            body.write(b"\r\n")

            chunk3_sig = request.get_chunk_sigv4_auth(
                chunk2_sig, SHA256_EMPTY_STRING_HEXBYTES
            )
            self.assertEqual(
                chunk3_sig,
                "2ca2aba2005185cf7159c6277faf83795951dd77a3a99e6e65d5c9f85863f992",
                "Chunk 3 signature does not match expected value.",
            )

            body.write(f"0;chunk-signature={chunk3_sig}\r\n".encode("utf-8"))
            trailer = b"x-amz-checksum-crc32c:" + crc_result
            body.write(trailer + b"\n")
            trailer_sts = request.get_trailer_string_to_sign(
                chunk3_sig, sha256(trailer + b"\n").hexdigest().encode("utf-8")
            )
            self.assertEqual(
                trailer_sts,
                b"""\
AWS4-HMAC-SHA256-TRAILER
20130524T000000Z
20130524/us-east-1/s3/aws4_request
2ca2aba2005185cf7159c6277faf83795951dd77a3a99e6e65d5c9f85863f992
1e376db7e1a34a8ef1c4bcee131a2d60a1cb62503747488624e10995f448d774""",
                "Trailer string to sign does not match expected value.",
            )
            trailer_sig = request.get_trailer_sigv4_auth(
                chunk3_sig,
                sha256(trailer + b"\n").hexdigest().encode("utf-8"),
            )
            self.assertEqual(
                trailer_sig,
                "d81f82fc3505edab99d459891051a732e8730629a2e4a59689829ca17fe2e435",
                "Trailer signature does not match expected value.",
            )
            body.write(
                b"x-amz-trailer-signature:" + trailer_sig.encode("utf-8") + b"\r\n"
            )
            body.write(b"\r\n")

            # The AWS-documented content-length is incorrect.
            # self.assertEqual(
            #     body.tell(),
            #     content_length,
            #     "Total body length does not match expected value.",
            # )


if __name__ == "__main__":
    unittest_main()
