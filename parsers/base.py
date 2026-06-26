class BaseParser:
    """Base interface for all parser modules."""
    def parse(self, command: str, stdout: str, stderr: str = "") -> list:
        raise NotImplementedError
