from __future__ import annotations
from db.llm_repository import LLMAnalysisRepository
from db.models import AnalysisResult

DEFAULT_RISK_LEVELS = ["critical", "high"]

def get_candidate_results(
    repo : LLMAnalysisRepository ,
    risk_level:list[str] = DEFAULT_RISK_LEVELS, 
    limit: int | None = None):
    return repo.select_skill_by_risk_level(risk_level,limit)    