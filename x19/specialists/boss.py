"""Boss/Commander specialist wrapper."""
from .base import build_specialist_goal, build_specialist_context, create_specialist_config, get_specialist_prompt
from x19.team.roles import BOSS_COMMANDER

ROLE_ID = "boss"

def get_prompt() -> str:
    return get_specialist_prompt(ROLE_ID)

def build_goal(objective: str, target: str, scope: dict, **kwargs) -> str:
    return build_specialist_goal(ROLE_ID, objective, target, scope, **kwargs)

def build_context(mission_id: str, task_id: str, **kwargs) -> str:
    return build_specialist_context(ROLE_ID, mission_id, task_id, **kwargs)
