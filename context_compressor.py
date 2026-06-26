import json
import re
import time
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Optional, Tuple
from dataclasses import dataclass, field

from constants import C
from logging_utils import log


@dataclass
class CompressionConfig:
    target_max_chars: int = 24000
    summary_target_chars: int = 1500
    protect_first_system: bool = True
    protect_first_human: bool = True
    protect_first_gpt: bool = True
    protect_first_tool: bool = True
    protect_last_n_turns: int = 4
    summary_notice: str = ""
    max_turns: int = 100


@dataclass
class CompressMetrics:
    original_chars: int = 0
    compressed_chars: int = 0
    chars_saved: int = 0
    compression_ratio: float = 1.0
    original_turns: int = 0
    compressed_turns: int = 0
    turns_removed: int = 0
    was_compressed: bool = False


class ContextCompressor:
    def __init__(self, config: Optional[CompressionConfig] = None):
        self.config = config or CompressionConfig()

    def _find_protected_indices(self, turns: List[Dict]) -> Tuple[set, int, int]:
        n = len(turns)
        protected = set()
        first_system = first_human = first_gpt = first_tool = None

        for i, turn in enumerate(turns):
            role = turn.get("role", "")
            if role == "system" and first_system is None:
                first_system = i
            elif role == "user" and first_human is None:
                first_human = i
            elif role == "assistant" and first_gpt is None:
                first_gpt = i
            elif role == "tool" and first_tool is None:
                first_tool = i

        if self.config.protect_first_system and first_system is not None:
            protected.add(first_system)
        if self.config.protect_first_human and first_human is not None:
            protected.add(first_human)
        if self.config.protect_first_gpt and first_gpt is not None:
            protected.add(first_gpt)
        if self.config.protect_first_tool and first_tool is not None:
            protected.add(first_tool)

        for i in range(max(0, n - self.config.protect_last_n_turns), n):
            protected.add(i)

        head_protected = [i for i in protected if i < n // 2]
        tail_protected = [i for i in protected if i >= n // 2]

        compress_start = max(head_protected) + 1 if head_protected else 0
        compress_end = min(tail_protected) if tail_protected else n

        return protected, compress_start, compress_end

    def _count_chars(self, text: str) -> int:
        return len(text) if text else 0

    def _estimate_turns_chars(self, turns: List[Dict]) -> List[int]:
        return [
            self._count_chars(turn.get("content", ""))
            + self._count_chars(json.dumps(turn.get("tool_calls", "")))
            for turn in turns
        ]

    def _generate_summary(self, content: str) -> str:
        lines = content.split("\n")
        important = []
        for line in lines:
            stripped = line.strip()
            if not stripped:
                continue
            if any(kw in stripped.lower() for kw in
                   ("vulnerab", "exploit", "cve-", "open port", "found",
                    "password", "token", "key", "admin", "http", "https",
                    "nmap", "nuclei", "curl", "gobuster", "ffuf")):
                important.append(stripped)
        if not important:
            important = lines[:20]
        summary = "\n".join(important[:30])
        if len(summary) > self.config.summary_target_chars:
            summary = summary[:self.config.summary_target_chars] + "..."
        prefix = "[CONTEXT SUMMARY]:"
        return f"{prefix}\n{summary}" if summary else prefix

    def compress_context(self, turns: List[Dict]) -> Tuple[List[Dict], CompressMetrics]:
        metrics = CompressMetrics()
        metrics.original_turns = len(turns)

        turn_chars = self._estimate_turns_chars(turns)
        total_chars = sum(turn_chars)
        metrics.original_chars = total_chars

        if total_chars <= self.config.target_max_chars or len(turns) <= self.config.protect_last_n_turns + 4:
            metrics.compressed_chars = total_chars
            metrics.compressed_turns = len(turns)
            return turns, metrics

        if len(turns) > self.config.max_turns:
            keep = turns[:1] + turns[-(self.config.max_turns - 1):]
            m = CompressMetrics()
            m.original_turns = len(turns)
            m.compressed_turns = len(keep)
            m.was_compressed = True
            return keep, m

        protected, compress_start, compress_end = self._find_protected_indices(turns)

        if compress_start >= compress_end:
            metrics.compressed_chars = total_chars
            metrics.compressed_turns = len(turns)
            return turns, metrics

        chars_to_save = total_chars - self.config.target_max_chars
        target_chars_to_compress = chars_to_save + self.config.summary_target_chars

        accumulated_chars = 0
        compress_until = compress_start

        for i in range(compress_start, compress_end):
            accumulated_chars += turn_chars[i]
            compress_until = i + 1
            if accumulated_chars >= target_chars_to_compress:
                break

        if accumulated_chars < target_chars_to_compress and compress_until < compress_end:
            compress_until = compress_end

        content_to_summarize = "\n".join(
            f"[{turns[i].get('role','?')}]: {turns[i].get('content','')[:2000]}"
            for i in range(compress_start, compress_until)
        )

        summary = self._generate_summary(content_to_summarize)

        compressed = []
        for i in range(compress_start):
            turn = dict(turns[i])
            if turn.get("role") == "system" and self.config.summary_notice:
                turn["content"] = (turn.get("content") or "") + self.config.summary_notice
            compressed.append(turn)

        compressed.append({
            "role": "user",
            "content": summary
        })

        for i in range(compress_until, len(turns)):
            compressed.append(dict(turns[i]))

        metrics.compressed_turns = len(compressed)
        metrics.compressed_chars = sum(
            self._count_chars(t.get("content", "")) for t in compressed
        )
        metrics.turns_removed = metrics.original_turns - metrics.compressed_turns
        metrics.chars_saved = metrics.original_chars - metrics.compressed_chars
        metrics.compression_ratio = metrics.compressed_chars / max(metrics.original_chars, 1)
        metrics.was_compressed = True

        return compressed, metrics

    def compress_messages(self, messages: List[Dict]) -> List[Dict]:
        compressed, metrics = self.compress_context(messages)
        if metrics.was_compressed:
            log(f"[Compressor] {metrics.original_turns}->{metrics.compressed_turns} turns "
                f"({metrics.original_chars}->{metrics.compressed_chars} chars, "
                f"{metrics.compression_ratio:.1%} ratio)")
        return compressed
