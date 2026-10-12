from typing import Dict, List
from core.schemas import TrustLevel, IngestSource

class SessionTaintGraph:
    """Tracks causal lineage of data entering an agent's execution context."""
    def __init__(self, session_id: str):
        self.session_id: str = session_id
        self.nodes: List[IngestSource] = []
        self.is_tainted: bool = False

    def record_ingest(self, source_id: str, trust_level: TrustLevel, content_summary: str) -> None:
        node = IngestSource(
            source_id=source_id,
            trust_level=trust_level,
            content_summary=content_summary
        )
        self.nodes.append(node)
        if trust_level == TrustLevel.EXTERNAL_UNTRUSTED:
            self.is_tainted = True

    def get_taint_status(self) -> bool:
        return self.is_tainted

    def get_lineage(self) -> List[Dict[str, str]]:
        return [
            {"source_id": n.source_id, "trust_level": n.trust_level.value, "summary": n.content_summary}
            for n in self.nodes
        ]