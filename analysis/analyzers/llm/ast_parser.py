from __future__ import annotations
from pathlib import Path
import ast


def parse_file(file_path: Path) -> dict:
    if file_path.suffix == ".py":
        imports = []
        function_calls = []
        strings = []
        code = open(file_path).read()
        tree = ast.parse(code)  

        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    imports.append(alias.name)
            if isinstance(node, ast.ImportFrom):  
                if node.module:
                    imports.append(node.module)
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Attribute):
                    
                    name = f"{getattr(node.func.value, 'id', '?')}.{node.func.attr}"
                    function_calls.append(name)
                elif isinstance(node.func, ast.Name):
                    
                    function_calls.append(node.func.id)
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                if len(node.value) > 4:  
                    strings.append(node.value)

        return {
            "filename": file_path.name,
            "type": "python_code",
            "imports": imports,
            "function_calls": function_calls,
            "strings": strings,
            # "raw_content": code
        }
    elif file_path.suffix in [".md", ".txt"]:
        return {
            "filename": file_path.name,
            "type": "documentation",
            # "raw_content": file_path.read_text(errors="ignore")
        }
    else:
        return {
            "filename": file_path.name,
            "type": "code",
            # "raw_content": file_path.read_text(errors="ignore")
        }