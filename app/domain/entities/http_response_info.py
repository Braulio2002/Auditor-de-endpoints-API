from dataclasses import dataclass, field


@dataclass
class HttpResponseInfo:
    url: str
    metodo: str
    status_code: int | None = None
    headers: dict[str, str] = field(default_factory=dict)
    body_sample: str = ""
    content_type: str = ""
    response_time_ms: float = 0.0
    error: str | None = None
