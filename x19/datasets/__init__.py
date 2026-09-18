"""X19 Bug Bounty Datasets — structured data with provenance."""

from .base import BugBountyDatasets, DatasetMetadata

# Global instance
_ds_instance = None


def get_datasets(datasets_dir: str = None) -> BugBountyDatasets:
    """Get global datasets instance."""
    global _ds_instance
    if _ds_instance is None:
        _ds_instance = BugBountyDatasets(datasets_dir=datasets_dir)
        _ds_instance.load()
    return _ds_instance


__all__ = ["BugBountyDatasets", "DatasetMetadata", "get_datasets"]
