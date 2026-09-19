"""Phantom tool references: system-prompt blocks must not name tools the
session can't call (Blank Slate audit, Aug 2026).

Covers:
  * X19_AGENT_HELP_GUIDANCE names no tool at all — it reaches every session,
    including leaf workers whose toolsets exclude delegation.
  * execution_guidance_text() never names a web tool (guidance is toolset-neutral).
  * The coding operating brief drops the `todo` sentence when the todo tool
    isn't loaded.
  * ESSENTIAL_SKILLS can't be disabled via config, and the CLI writer strips
    them from persisted disabled lists.
"""

from pathlib import Path


def _all_tool_names() -> set[str]:
    """Every tool any toolset can resolve to, `includes` followed transitively."""
    from toolsets import TOOLSETS

    def resolve(name: str, seen: set[str] | None = None) -> set[str]:
        seen = seen if seen is not None else set()
        if name in seen or name not in TOOLSETS:
            return set()
        seen.add(name)
        spec = TOOLSETS[name]
        out = set(spec.get("tools") or ())
        for included in spec.get("includes") or ():
            out |= resolve(included, seen)

        return out

    return set().union(*(resolve(n) for n in TOOLSETS))


def _tool_names_mentioned(text: str) -> set[str]:
    """Backticked identifiers in guidance that are actually tool names."""
    import re

    return {tok for tok in re.findall(r"`([a-z0-9_]+)`", text) if tok in _all_tool_names()}


class TestX19AgentHelpGuidance:
    def test_guidance_names_no_tool_a_session_might_lack(self):
        """This block is appended to EVERY session's stable tier.

        Leaf workers are dispatched with toolsets that deliberately exclude
        delegation (`DELEGATE_BLOCKED_TOOLS`), so naming `delegate_task` here
        pointed at a tool those prompts cannot call — the phantom reference this
        module exists to catch.
        """
        from agent.prompt_builder import X19_AGENT_HELP_GUIDANCE

        assert _tool_names_mentioned(X19_AGENT_HELP_GUIDANCE) == set()

    def test_both_imported_names_are_the_same_neutral_text(self):
        """The variant split is historical: there is nothing left to degrade."""
        from agent.prompt_builder import X19_AGENT_HELP_GUIDANCE, X19_AGENT_HELP_GUIDANCE_NO_SKILLS

        assert X19_AGENT_HELP_GUIDANCE_NO_SKILLS == X19_AGENT_HELP_GUIDANCE
        assert "skill_view" not in X19_AGENT_HELP_GUIDANCE_NO_SKILLS

    def test_guidance_points_at_the_real_sources_of_truth(self):
        from agent.prompt_builder import X19_AGENT_HELP_GUIDANCE

        text = X19_AGENT_HELP_GUIDANCE
        assert "X22" in text, "the manager layer is named"
        assert "runtime state" in text, "state, not narration, is authoritative"
        assert "never invent" in text

    def test_the_guidance_actually_reaches_the_rendered_prompt(self):
        """Guard the invariant that makes neutrality necessary: every session."""
        import agent.system_prompt as system_prompt
        from agent.prompt_builder import X19_AGENT_HELP_GUIDANCE_NO_SKILLS

        src = Path(system_prompt.__file__).read_text()
        assert "stable_parts.append(X19_AGENT_HELP_GUIDANCE_NO_SKILLS)" in src
        assert X19_AGENT_HELP_GUIDANCE_NO_SKILLS


class TestExecutionGuidanceText:
    def test_no_web_tool_named_without_web_tools(self):
        # #39797: naming web_search here overrode SOUL.md and dangled when the web toolset was off.
        from agent.prompt_builder import OPENAI_MODEL_EXECUTION_GUIDANCE, execution_guidance_text
        text = execution_guidance_text()
        assert text == OPENAI_MODEL_EXECUTION_GUIDANCE
        assert "web_search" not in text and "web_extract" not in text
        # The surrounding structure survives.
        assert "<mandatory_tool_use>" in text
        assert "<missing_context>" in text


class TestCodingBriefTodoGating:
    def _brief(self, valid_tool_names):
        from agent.coding_context import CODING_PROFILE, RuntimeMode
        mode = RuntimeMode(
            profile=CODING_PROFILE, surface="cli", cwd=Path.cwd(),
        )
        prefix, _ws, _tr = mode.system_prompt_parts(
            valid_tool_names=valid_tool_names
        )
        assert prefix, "coding profile must emit an operating brief"
        return prefix[0]

    def test_todo_kept_when_tool_available(self):
        brief = self._brief({"todo_list", "terminal", "read_file"})
        assert "Track multi-step work with `todo_list`" in brief

    def test_todo_dropped_when_tool_missing(self):
        brief = self._brief({"terminal", "read_file"})
        assert "`todo`" not in brief
        # The path:line half of the merged bullet survives.
        assert "path:line" in brief

    def test_unknown_toolset_keeps_full_brief(self):
        brief = self._brief(None)
        assert "Track multi-step work with `todo_list`" in brief


class TestEssentialSkillsUndisableable:
    def test_agent_side_reader_strips_essential(self, monkeypatch, tmp_path):
        import agent.skill_utils as su
        cfg = tmp_path / "config.yaml"
        cfg.write_text(
            "skills:\n  disabled:\n    - x19\n    - some-other-skill\n",
            encoding="utf-8",
        )
        monkeypatch.setattr(su, "get_config_path", lambda: cfg)
        su._RAW_CONFIG_CACHE.clear()
        disabled = su.get_disabled_skill_names(platform="cli")
        assert "x19" not in disabled
        assert "some-other-skill" in disabled

    def test_cli_side_reader_strips_essential(self):
        from x19_cli.skills_config import get_disabled_skills
        cfg = {"skills": {"disabled": ["x19", "other"]}}
        disabled = get_disabled_skills(cfg)
        assert "x19" not in disabled
        assert "other" in disabled

    def test_cli_side_writer_strips_essential(self, monkeypatch):
        import x19_cli.skills_config as sc
        saved = {}
        monkeypatch.setattr(sc, "save_config", lambda cfg: saved.update(cfg))
        cfg = {}
        sc.save_disabled_skills(cfg, {"x19", "other"})
        assert cfg["skills"]["disabled"] == ["other"]

    def test_skill_manage_delete_refused(self):
        from tools.skill_manager_guards import _pinned_guard
        msg = _pinned_guard("x19")
        assert msg is not None
        assert "essential" in msg.lower()


class TestEssentialOnlySync:
    def test_opted_out_sync_seeds_only_essential(self, monkeypatch, tmp_path):
        """A profile with .no-bundled-skills still gets the x19 skill."""
        import tools.skills_sync as ss

        home = tmp_path / ".x19"
        home.mkdir()
        (home / ss.NO_BUNDLED_SKILLS_MARKER).write_text("", encoding="utf-8")

        bundled = tmp_path / "bundled"
        for cat, name in [
            ("autonomous-ai-agents", "x19"),
            ("media", "gif-search"),
        ]:
            d = bundled / cat / name
            d.mkdir(parents=True)
            (d / "SKILL.md").write_text(
                f"---\nname: {name}\ndescription: x\n---\nbody\n",
                encoding="utf-8",
            )

        monkeypatch.setattr(ss, "_x19_home", lambda: home)
        monkeypatch.setattr(ss, "_get_bundled_dir", lambda: bundled)
        monkeypatch.setattr(ss, "_build_external_skill_index", lambda: set())

        result = ss.sync_skills(quiet=True)

        assert result["skipped_opt_out"] is True
        assert result["copied"] == ["x19"]
        assert (home / "skills" / "autonomous-ai-agents" / "x19" / "SKILL.md").exists()
        assert not (home / "skills" / "media").exists()
