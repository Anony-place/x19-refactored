"""Tests for X19 learning loop with provenance — FACT, OBSERVATION, LESSON, SKILL, HYPOTHESIS."""

import sys
sys.path.insert(0, '.')

from x19.learning import (
    ProvenanceType,
    Confidence,
    LearnedItem,
    LearningStore,
    create_fact,
    create_observation,
    create_lesson,
    create_skill,
    create_hypothesis,
)


def test_provenance_types():
    """Provenance types must be FACT, OBSERVATION, LESSON, SKILL, HYPOTHESIS."""
    assert ProvenanceType.FACT.value == "FACT"
    assert ProvenanceType.OBSERVATION.value == "OBSERVATION"
    assert ProvenanceType.LESSON.value == "LESSON"
    assert ProvenanceType.SKILL.value == "SKILL"
    assert ProvenanceType.HYPOTHESIS.value == "HYPOTHESIS"


def test_create_fact():
    """FACT must be verified, high confidence, with evidence."""
    fact = create_fact(
        content="Target uses nginx",
        provenance="Tool output: Server header",
        evidence=["Server: nginx/1.18"],
        source="M-123",
        confidence=Confidence.HIGH,
    )

    assert fact.type == ProvenanceType.FACT
    assert fact.content == "Target uses nginx"
    assert fact.verified
    assert fact.confidence == Confidence.HIGH
    assert len(fact.evidence) > 0
    assert fact.can_become_permanent()


def test_create_observation():
    """OBSERVATION from tool output, not verified, should not become permanent automatically."""
    obs = create_observation(
        content="Endpoint /api/users returns 200",
        provenance="curl output",
        source="M-123",
    )

    assert obs.type == ProvenanceType.OBSERVATION
    assert not obs.verified
    assert not obs.can_become_permanent()


def test_create_lesson():
    """LESSON from success/failure with evidence."""
    lesson = create_lesson(
        content="BOLA testing requires auth, failed without auth",
        provenance="Failed without auth, succeeded with auth",
        evidence=["Without auth: 401, with auth: 200 with other user data"],
        source="M-123",
    )

    assert lesson.type == ProvenanceType.LESSON
    assert len(lesson.evidence) > 0


def test_create_skill():
    """SKILL — procedural knowledge that worked, can become permanent."""
    skill = create_skill(
        content="Test BOLA by changing ID by 1 with auth token",
        provenance="Successful BOLA test in mission M-123",
        evidence=["Test with ID 123 to 124 returned other user data"],
        source="M-123",
        applicable_to=["bola", "idor"],
    )

    assert skill.type == ProvenanceType.SKILL
    assert skill.verified
    assert skill.confidence == Confidence.HIGH
    assert "bola" in skill.applicable_to
    assert skill.can_become_permanent()


def test_create_hypothesis():
    """HYPOTHESIS — unverified idea, low confidence, should not become permanent."""
    hyp = create_hypothesis(
        content="Endpoint /search might have XSS via q param",
        provenance="Observation: q param reflected",
        source="M-123",
    )

    assert hyp.type == ProvenanceType.HYPOTHESIS
    assert not hyp.verified
    assert hyp.confidence == Confidence.LOW
    assert not hyp.can_become_permanent()


def test_learning_store():
    """Learning store must track by type, confidence, verified, permanent candidates."""
    store = LearningStore()

    fact = create_fact("Fact", "Provenance", ["Evidence"], "M-123")
    obs = create_observation("Observation", "Provenance", "M-123")
    lesson = create_lesson("Lesson", "Provenance", ["Evidence"], "M-123")
    skill = create_skill("Skill", "Provenance", ["Evidence"], "M-123", ["xss"])
    hyp = create_hypothesis("Hypothesis", "Provenance", "M-123")

    store.add(fact)
    store.add(obs)
    store.add(lesson)
    store.add(skill)
    store.add(hyp)

    assert len(store.list_by_type(ProvenanceType.FACT)) == 1
    assert len(store.list_by_type(ProvenanceType.OBSERVATION)) == 1
    assert len(store.list_by_type(ProvenanceType.LESSON)) == 1
    assert len(store.list_by_type(ProvenanceType.SKILL)) == 1
    assert len(store.list_by_type(ProvenanceType.HYPOTHESIS)) == 1

    assert len(store.list_verified()) == 2  # FACT and SKILL
    assert len(store.list_permanent_candidates()) >= 2  # FACT and SKILL

    stats = store.get_stats()
    assert stats["total"] == 5
    assert stats["by_type"]["FACT"] == 1
    assert stats["verified"] == 2


def test_prevent_unverified_becoming_permanent():
    """Never allow unverified model-generated claims to become permanent knowledge automatically."""
    store = LearningStore()

    # Unverified hypothesis should not become permanent
    hyp = create_hypothesis("Might be vulnerable", "Model guess", "M-123")
    store.add(hyp)
    assert not hyp.can_become_permanent()
    assert len(store.list_permanent_candidates()) == 0

    # Unverified observation should not become permanent
    obs = create_observation("Tool saw something", "Tool output", "M-123")
    store.add(obs)
    assert not obs.can_become_permanent()

    # Only verified FACT/SKILL with high confidence and evidence can become permanent
    fact_unverified = LearnedItem(
        type=ProvenanceType.FACT,
        content="Unverified fact",
        provenance="Model claim",
        confidence=Confidence.LOW,
        verified=False,
    )
    assert not fact_unverified.can_become_permanent()
