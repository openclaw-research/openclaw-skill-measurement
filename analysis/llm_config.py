from config import Settings, get_settings
import os
from dataclasses import dataclass
from dotenv import load_dotenv


RELIABLE_STATIC_ANALYZER_NAME = "static"
RELIABLE_STATIC_ANALYZER_VERSION = "4"

@dataclass(frozen = True)
class LLMSettings(Settings):
    api_key : str

def get_llm_settings(env_file) -> LLMSettings:
    load_dotenv(env_file, override=True)
    base = get_settings(env_file)
    return LLMSettings(
        database_url = base.database_url,
        s3_bucket = base.s3_bucket,
        aws_region = base.aws_region,
        artifact_tmp_dir =  base.artifact_tmp_dir,
        api_key = os.getenv("API_KEY","")
    )
    
