"""Runtime integration for X19 native tools.

The refactored agent still contains legacy phase tool allowlists. Native
reconnaissance tools are safe observation primitives, so expose them to every
phase without changing the existing execution policy.
"""

BUILTIN_NAMES = {
    "x19_net_scan",
    "x19_http_probe",
    "x19_dns",
    "x19_tls",
    "x19_web_links",
}


def install_phase_access() -> None:
    from agent import X19
    for phase_tools in X19._PHASE_TOOLS.values():
        phase_tools.update(BUILTIN_NAMES)
