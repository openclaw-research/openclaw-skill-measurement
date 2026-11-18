from __future__ import annotations
from pathlib import Path
from analyzers.static.analyzer import COLLECTOR_METADATA_FILES


def get_flagged_files(result_json) -> list[str] :
    path_list = []
    indicators = result_json.get("indicators", {})
    for category in indicators:
        for evidence in indicators[category].get("evidence", []):
            path = evidence["path"]
            if path not in path_list:
                path_list.append(path)
    return path_list
        
        
def filter_files(root_path: Path, result_json: dict) -> list[Path]:
    flagged = get_flagged_files(result_json)
    result = []
    # for path_str in flagged:
    #     if "_detail.json" in path_str: continue
    #     full_path = root_path/path_str
    #     if full_path.exists():
    #         result.append(full_path)
    for path_str in flagged:
        filename = path_str.split("/")[-1]  
        if filename in COLLECTOR_METADATA_FILES: continue  
        full_path = root_path / path_str
        if full_path.exists():
            result.append(full_path)
    return result
    