"""bugbounty_research specialist wrapper."""
from .base import build_specialist_goal, build_specialist_context, create_specialist_config, get_specialist_prompt
ROLE_ID = "bugbounty_research"
def get_prompt(): return get_specialist_prompt(ROLE_ID)
def build_goal(objective, target, scope, **kwargs): return build_specialist_goal(ROLE_ID, objective, target, scope, **kwargs)
def build_context(mission_id, task_id, **kwargs): return build_specialist_context(ROLE_ID, mission_id, task_id, **kwargs)
