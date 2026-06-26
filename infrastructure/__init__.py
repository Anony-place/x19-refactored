"""Infrastructure subsystem interfaces for X19.

Wraps legacy config, storage, plugin, and runtime modules during migration.
"""

from config import (
    CONFIG,
    CONFIG_DIR,
    CONFIG_FILE,
    load_config,
    save_config,
    set_data,
    SCRIPTS_DIR,
    PAYLOADS_DIR,
    WORDLISTS_DIR,
)

__all__ = [
    "CONFIG",
    "CONFIG_DIR",
    "CONFIG_FILE",
    "load_config",
    "save_config",
    "set_data",
    "SCRIPTS_DIR",
    "PAYLOADS_DIR",
    "WORDLISTS_DIR",
]
