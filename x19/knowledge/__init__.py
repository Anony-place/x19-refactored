"""X19 Knowledge Base — public security knowledge with metadata."""

from .base import KnowledgeBase, KnowledgeEntry, KnowledgeMetadata

# Global instance
_kb_instance = None


def get_knowledge_base(knowledge_dir: str = None) -> KnowledgeBase:
    """Get global knowledge base instance."""
    global _kb_instance
    if _kb_instance is None:
        _kb_instance = KnowledgeBase(knowledge_dir=knowledge_dir)
        _kb_instance.load()
    return _kb_instance


__all__ = ["KnowledgeBase", "KnowledgeEntry", "KnowledgeMetadata", "get_knowledge_base"]
