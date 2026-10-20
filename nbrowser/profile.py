from .private_root import PrivateRootContext


class BrowserProfile:
    def __init__(self) -> None:
        self.root = PrivateRootContext()

    @property
    def path(self) -> str:
        return self.root.get_profile_path()

    def close(self) -> None:
        self.root.close()
