# import pytest
# from sqlalchemy import create_engine,BigInteger
# from sqlalchemy.orm import sessionmaker
# from sqlalchemy.dialects.postgresql import JSONB
# from sqlalchemy.ext.compiler import compiles
# from sqlalchemy.pool import StaticPool

# from db.llm_models import LLMAnalysisRun, LLMAnalysisResult, Base
# from db.llm_repository import LLMAnalysisRepository

# @compiles(JSONB, "sqlite")
# def compile_jsonb_sqlite(type_, compiler, **kw):
#     return "JSON"

# @compiles(BigInteger, "sqlite")
# def compile_biginteger_sqlite(type_, compiler, **kw):
#     return "INTEGER"

# @pytest.fixture
# def engine():
#     # engine = create_engine("sqlite:///:memory:")
#     # engine = create_engine("sqlite:///:memory:", echo=True)
#     engine = create_engine(
#         "sqlite:///:memory:",
#         connect_args={"check_same_thread": False},
#         poolclass=StaticPool,
#     )
#     Base.metadata.create_all(engine)
#     yield engine
#     engine.dispose()

# @pytest.fixture
# def session(engine):
#     Session = sessionmaker(bind=engine)
#     session = Session()
#     yield session
#     session.close()

# @pytest.fixture
# def repo(session):
#     return LLMAnalysisRepository(session=session)

# def test_select_skill_by_risk_level_only_returns_latest_run(session, repo):
#     result_a = LLMAnalysisResult(
#         skill_id=1,
#         analyzer_name="reliable_static_analyzer",
#         analyzer_version="1.0.0",
#         llm_analysis_run_id=100,
#         rule_based_result_id=LLMAnalysisResult.id,  
#         status="success",
#         risk_level="CRITICAL",
#         rule_based_risk_level="CRITICAL",
#         confidence=0.9,
#         false_positives_json={},
#         result_json={},
#     )
#     result_b = LLMAnalysisResult(
#         skill_id=1,
#         analyzer_name="other_analyzer",
#         analyzer_version="2.0.0",
#         llm_analysis_run_id=200,
#         rule_based_result_id=LLMAnalysisResult.id, 
#         status="success",
#         risk_level="CRITICAL",
#         rule_based_risk_level="CRITICAL",
#         confidence=0.9,
#         false_positives_json={},
#         result_json={},
#     )
#     session.add_all([result_a, result_b])
#     session.commit()

#     results = repo.select_skill_by_risk_level(
#         risk_level=["CRITICAL"],
#         analyzer_name="reliable_static_analyzer",
#         analyzer_version="1.0.0",
#     )

#     assert len(results) == 1
#     assert results[0].id == result_a.id
    
