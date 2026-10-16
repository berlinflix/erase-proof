from dataclasses import asdict, dataclass, field


class EraseProofError(Exception):
    """An operational failure that can be shown to an operator."""


class Cancelled(EraseProofError):
    pass


@dataclass
class Candidate:
    offset: int
    length: int
    file_type: str
    confidence: int
    evidence: list[str] = field(default_factory=list)
    name: str = ""
    method: str = "signature-carving"
    inode: str = ""
    output: str = ""
    sha256: str = ""
    segments: list[list[int]] = field(default_factory=list)
    confidence_details: dict = field(default_factory=dict)

    def to_dict(self):
        return asdict(self)
