"""
interface-partition/grpc_request_handler/grpc_request_handler.py

Sends VoR requests to the intermediate-vor-partition via mTLS gRPC.

A persistent GrpcRequestSender is module-level so the TLS handshake and
channel setup happen once per process lifetime, not once per request.
The previous implementation opened a new grpc.secure_channel() inside a
'with' block on every call, incurring a full TLS negotiation round-trip
for every submitted request.
"""

from __future__ import annotations
import logging
import threading
from pathlib import Path
from typing import Any, Optional
import grpc
import request_pb2, request_pb2_grpc

from config_loader import GrpcClientConfig

_logger = logging.getLogger(__name__)


class GrpcRequestSender:
    """
    Persistent mTLS gRPC sender for VoR request submissions.

    Reuses the channel and stub across calls. Thread-safe via RLock.
    The channel is created lazily on the first send() call so that import-time
    certificate errors surface at call time rather than at module load.
    """

    def __init__(self, config: GrpcClientConfig) -> None:
        self._config = config
        self._lock = threading.RLock()
        self._channel: Optional[grpc.Channel] = None
        self._stub: Optional[request_pb2_grpc.RequestServiceStub] = None

    def _load_credentials(self) -> grpc.ChannelCredentials:
        certs = self._config.certs
        try:
            client_key  = Path(certs.client_key).read_bytes()
            client_cert = Path(certs.client_cert).read_bytes()
            ca_cert     = Path(certs.ca_cert).read_bytes()
        except Exception as e:
            _logger.error("Error reading TLS files: %s", e)
            raise
        return grpc.ssl_channel_credentials(
            root_certificates=ca_cert,
            private_key=client_key,
            certificate_chain=client_cert,
        )

    def _ensure_connected(self) -> request_pb2_grpc.RequestServiceStub:
        with self._lock:
            if self._stub is not None:
                return self._stub
            target = f"{self._config.target_host}:{self._config.port}"
            creds = self._load_credentials()
            self._channel = grpc.secure_channel(target, creds)
            self._stub = request_pb2_grpc.RequestServiceStub(self._channel)
            _logger.info("gRPC request channel established to %s", target)
            return self._stub

    def _reset(self) -> None:
        with self._lock:
            ch, self._channel, self._stub = self._channel, None, None
        if ch is not None:
            try:
                ch.close()
            except Exception:
                pass

    def send(self, request: dict[str, Any]) -> None:
        try:
            stub = self._ensure_connected()
        except Exception:
            _logger.error("Cannot send request: channel setup failed.")
            return

        req = request_pb2.SubmitRequest(
            issuer_id              = request["issuer_id"],
            issuer_characteristics = request["issuer_characteristics"],
            timestamp              = request["timestamp"],
            description            = request["description"],
            impact                 = request["impact"],
            parameters             = request["parameters"],
            modification           = request["modification"],
            priority               = int(request["prio"]),
            request_id             = request["request_id"],
        )
        try:
            _logger.debug("Sending request via gRPC: %s", request)
            resp = stub.Submit(req, timeout=self._config.timeout_seconds)
            _logger.info("ACK: %s  server_ts: %s", resp.ack, resp.server_timestamp)
        except grpc.RpcError as e:
            _logger.error("RPC failed (%s): %s", e.code().name, e.details())
            self._reset()
        except Exception as e:
            _logger.error("Unexpected gRPC send error: %s", e)
            self._reset()


# Module-level singleton — initialised by interface_setup.py when it calls
# init_grpc_request_sender(config). send_request_as_grpc() is the public API
# kept for backward compatibility with server_methods.py.
_sender: Optional[GrpcRequestSender] = None


def init_grpc_request_sender(config: GrpcClientConfig) -> None:
    """
    Initialise the module-level sender. Call this once from interface_setup
    before any submit_request() calls are made.
    """
    global _sender
    _sender = GrpcRequestSender(config)


def send_request_as_grpc(request: dict[str, Any], config: GrpcClientConfig) -> None:
    """
    Backward-compatible entry point used by server_methods.submit_request().

    On first call (or if the sender was not pre-initialised), a new sender is
    created from config. Subsequent calls reuse the existing channel.
    """
    global _sender
    if _sender is None:
        _sender = GrpcRequestSender(config)
    _sender.send(request)