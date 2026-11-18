from db.session import build_engine, build_session_factory
from llm_config import get_llm_settings

def get_llm_engine():
    settings = get_llm_settings()
    return build_engine(settings)

def get_llm_session_factory():
    engine = get_llm_engine()
    return build_session_factory(engine)