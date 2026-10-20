from dataclasses import dataclass, field
from typing import Any


class PageState:
    READY = "ready"
    CLOAKED = "cloaked"


# Field-for-field the walker's wire element (extract.rs SEMANTIC_WALKER).
@dataclass
class Element:
    id: int
    selector: str = ""
    kind: str = "other"
    ref: str = ""
    node_uid: int | None = None
    label: str | None = None
    name: str | None = None
    value: str | None = None
    placeholder: str | None = None
    href: str | None = None
    input_type: str | None = None
    autocomplete: str | None = None
    disabled: bool = False
    form_index: int | None = None
    context: str | None = None
    hint: str | None = None
    checked: bool | None = None
    options: list[str] | None = None
    frame_index: int | None = None
    frame_id: str | None = None
    is_visible: bool = True


@dataclass
class FormMeta:
    index: int
    action: str | None = None
    method: str | None = None
    has_password: bool = False
    has_search: bool = False


@dataclass
class Card:
    id: str
    title: str
    metadata: dict[str, str] = field(default_factory=dict)


@dataclass
class SemanticView:
    url: str = ""
    title: str = ""
    page_hint: str = ""
    doc_gen: str = ""
    elements: list[Element] = field(default_factory=list)
    forms: list[FormMeta] = field(default_factory=list)
    visible_text: str = ""
    text_blocks: list[str] = field(default_factory=list)
    state: str = "ready"
    http_status: int | None = None
    element_cap: str | None = None
    blocked_reason: str | None = None
    session_context: str | None = None
    cards: list[Card] | None = None
    cards_truncated: bool | None = None
    frames_truncated: bool | None = None
    interactive_total: int = 0
    readable_length: int = 0
    shell_markers: dict[str, Any] = field(default_factory=dict)
    webmcp: dict[str, Any] | None = None
