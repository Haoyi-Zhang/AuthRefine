import logging
from typing import Optional, Sequence

from request import Request
from request_verification import RequestVerifier, RuleSet
from mapping_verification import RequestMapper, Mapping_RuleSets
from feedback_system import FeedbackSystem
from db_manager import DatabaseManager

_logger = logging.getLogger(__name__)

class RequestMessageHandler:
    """
    Synchronous request processor for use inside the gRPC server.
    It performs:
      - input normalization from the proto message
      - verification via RequestVerifier
      - mapping via RequestMapper
    """
    def __init__(
        self,
        verification_ruleset: RuleSet,
        mapping_ruleset: Mapping_RuleSets,
        feedback_system: FeedbackSystem,
        db_manager: DatabaseManager,          # ← was db_path: str
    ) -> None:
        self._verification_ruleset = verification_ruleset
        self._mapping_ruleset = mapping_ruleset
        self._feedback_system = feedback_system
        self._db_manager = db_manager         # ← was self._db_path

        self._verifier = RequestVerifier(self._verification_ruleset, self._feedback_system)
        if self._mapping_ruleset.rulesets is not None:
            self._mapper = RequestMapper(self._mapping_ruleset.rulesets, self._feedback_system, self._db_manager)
            # ← passes DatabaseManager, matching RequestMapper.__init__(db_manager: DatabaseManager)
        else:
            _logger.error("INIT: Mapping ruleset is None")
            self._mapper = None

    @staticmethod
    def _as_list_str(items: Sequence[str] | None) -> list[str]:
        if items is None:
            return []
        # Items from protobuf are already strings; cast defensively
        return [str(x) for x in items]

    def handle_grpc_submit(self, req_pb):
        """
        Convert proto SubmitRequest -> internal Request,
        run verification + mapping synchronously.
        Returns the verified/mapped Request (or raises on failure).

        Raises:
            ValueError or any exception from verifier/mapper for the server to convert to gRPC status.
        """
        # Normalize repeated-string fields
        issuer_characteristics = self._as_list_str(req_pb.issuer_characteristics)
        description            = self._as_list_str(req_pb.description)
        #impact                 = self._as_list_str(req_pb.impact)

        # Build internal Request. Adjust to your Request(...) signature.
        rq = Request(
            issuer_id=req_pb.issuer_id,
            issuer_characteristics=issuer_characteristics,
            request_id=getattr(req_pb, "request_id", ""),  # if your proto defines it
            timestamp=req_pb.timestamp,
            description=description,   # if your Request expects dict, adapt here
            #impact=impact,
            impact=req_pb.impact,
            parameters=str(req_pb.parameters),
            modification=str(req_pb.modification),
            priority=int(req_pb.priority),
        )

        _logger.debug("Built internal Request: %s", rq)

        # Verify
        verified_rq = self._verifier.process_requests(rq)
        _logger.info("Verified request: %s", verified_rq)

        # Map
        if self._mapper is None:
            raise RuntimeError("Mapping ruleset not available (None)")
        self._mapper.map_requests(verified_rq)
        _logger.info("Mapped request successfully")