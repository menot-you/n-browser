import enum
from dataclasses import dataclass


class EffectOperation(str, enum.Enum):
    click = "click"
    type = "type"
    select = "select"
    fill_form = "fill_form"
    press_key = "press_key"
    submit = "submit"
    scroll = "scroll"
    hover = "hover"
    focus = "focus"
    drag = "drag"
    clear = "clear"
    back = "back"
    refresh = "refresh"
    dialog = "dialog"
    touch = "touch"
    navigate = "navigate"
    upload = "upload"
    download = "download"
    github_structured_source = "github_structured_source"
    persist = "persist"
    provider_read = "provider_read"
    provider_monitor = "provider_monitor"
    auth_login = "auth_login"


@dataclass(frozen=True)
class HostTarget:
    url: str
