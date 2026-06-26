"""
x19 package — refactored from the monolithic x19.py.

Each module contains a cohesive group of classes/functions.
Re-exports all public symbols for backward compatibility.
"""

# flake8: noqa: F401, F403

from constants import (
    C, ICO, BANNER, PROVIDERS, PROVIDER_PRIORITY,
    TOOL_FAMILIES, _TOOL_TO_FAMILY, SERVICE_ATTACKS, SCOPE_TOOL_SUGGESTIONS,
    _failover_disabled, _provider_has_key,
)
from storage import (
    DataManager, SQLDatabase, Session,
    StateDatabase, FailureMemory, JsonFileStore, LoopSignal,
)
from memory import (
    ChromaMemory, PGVectorMemory, BackgroundLearner,
    _memory_disabled, is_actionable_technique, technique_metadata,
    is_bug_bounty_mode, is_ctf_mode, is_fast_mode,
)
from network import (
    TrafficEntry, TrafficCollector, ProxyManager,
)
from providers import (
    AIBackend, OpenAICompatBackend, AnthropicBackend,
    GoogleBackend, OllamaBackend, FailoverRouter,
    make_ai, jwt_auto_scan, endpoints_from_collector,
    ai_max_tokens, ai_request_timeout,
)
from attacks import (
    InteractsClient, get_oob, oob_inject,
    AuthzDifferentialTester, JWTAttacker,
    CloudProber, CveMapper, GraphQLAttacker,
    _ver_lt, _ver_in_range, _cvss_from_severity,
)
from tools import (
    TOOLS, ToolResult, BrowserAutomation, BrowserCrawler, ToolExecutor,
)
from reporting import (
    ReportWriter, Finding, TargetModel,
    ThreatIntel, OTX,
    prioritize_findings, build_report, crtsh_subdomains, nessus_scan,
    remediation_for,
)
from mission import (
    GoalNode, GoalTree, ConfidenceScorer,
    LoopDetector, AutonomyProfile,
    MissionTask, VerificationVerdict, TaskGraph,
    Verifier, AutoReplanner, MissionManager,
)
from loop import (
    HypothesisState, StructuredHypothesis,
    GateResult, ValidationResult,
    AntiLoopState, AntiLoopEngine, get_antiloop,
)
from self_improve import (
    SelfAwareness, PerformanceAnalyzer, CodeSurgeon,
    CodePatch, PatchResult, ImprovementSuggestion, Bottleneck,
)
from tool_distributions import (
    TOOLSETS, PHASE_DISTRIBUTIONS,
    get_distribution, list_distributions,
    sample_tools_from_distribution, get_tools_for_phase,
)
from context_compressor import (
    ContextCompressor, CompressionConfig, CompressMetrics,
)
from tool_scanner import (
    scan_available_tools, scan_missing_critical,
    build_tool_context, DiscoveredTool, INSTALL_MAP,
)
from telegram import TelegramBot, _maybe_start_telegram, _print_ai_chain_banner
from utils import (
    live_type, fingerprint_output, signature_command,
    classify_progress, validate_target, _parse_ints,
    decision_system_prompt, SYSTEM_PROMPT, FAST_DECISION_PROMPT,
    LEAN_SYSTEM_PROMPT, LEAN_FAST_PROMPT,
)
from planning import (
    Planner, ToolChain, ChainStep, ToolIO, TOOL_IO,
    METHODOLOGIES, detect_target_type,
)
from agent import X19
from cli import main, _extract_longcat_commands, _extract_exec_commands, _parse_target_from_user_line, _android_device_id
from config import CONFIG, CONFIG_DIR, CONFIG_FILE, load_config, save_config, set_data, SCRIPTS_DIR, PAYLOADS_DIR, WORDLISTS_DIR
