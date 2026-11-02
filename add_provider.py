#!/usr/bin/env python3
"""Insert a 'custom' (LLM Server / SiliconFlow) provider into the providers table."""
import json
import subprocess

# Role→model config matching custom-llm-config.yml
config = {
    "primary_agent": {"max_tokens": 16384, "model": "deepseek-ai/DeepSeek-V4-Pro", "n": 1},
    "assistant":     {"max_tokens": 16384, "model": "deepseek-ai/DeepSeek-V4-Pro", "n": 1},
    "generator":     {"max_tokens": 32768, "model": "deepseek-ai/DeepSeek-V4-Pro", "n": 1},
    "refiner":       {"max_tokens": 32768, "model": "deepseek-ai/DeepSeek-V4-Pro", "n": 1},
    "adviser":       {"max_tokens": 16384, "model": "deepseek-ai/DeepSeek-V4-Pro", "n": 1},
    "coder":         {"max_tokens": 20480, "model": "deepseek-ai/DeepSeek-V4-Pro", "n": 1},
    "pentester":     {"max_tokens": 16384, "model": "deepseek-ai/DeepSeek-V4-Pro", "n": 1},
    "installer":     {"max_tokens": 12288, "model": "deepseek-ai/DeepSeek-V4-Flash", "n": 1},
    "searcher":      {"max_tokens": 4096, "model": "Qwen/Qwen3.6-35B-A3B", "n": 1, "temperature": 0.5, "top_p": 0.9},
    "enricher":      {"max_tokens": 4096, "model": "Qwen/Qwen3.6-35B-A3B", "n": 1, "temperature": 0.5, "top_p": 0.9},
    "reflector":     {"max_tokens": 8192, "model": "Qwen/Qwen3.6-35B-A3B", "n": 1, "temperature": 0.5, "top_p": 0.9},
    "simple_json":   {"max_tokens": 4096, "model": "Qwen/Qwen3.6-35B-A3B", "n": 1, "temperature": 0.3, "top_p": 0.9, "json": True},
    "simple":        {"max_tokens": 16384, "model": "zai-org/GLM-5.2", "n": 1, "temperature": 0.6, "top_p": 0.9},
}

config_json = json.dumps(config, separators=(",", ":"))

# Insert into providers table (id auto-generated, user_id=1 for admin)
sql = (
    f"INSERT INTO providers (user_id, type, name, config) "
    f"VALUES (1, 'custom', 'LLM Server', '{config_json}') "
    f"RETURNING id, type, name;"
)

result = subprocess.run(
    ["docker", "exec", "pgvector", "psql", "-U", "postgres", "-d", "pentagidb", "-c", sql],
    capture_output=True, text=True
)
print("Insert result:", result.stdout.strip())
if result.stderr.strip():
    print("Error:", result.stderr.strip())

# Verify
result2 = subprocess.run(
    ["docker", "exec", "pgvector", "psql", "-U", "postgres", "-d", "pentagidb", "-c",
     "SELECT id, type, name FROM providers ORDER BY id;"],
    capture_output=True, text=True
)
print("\nAll providers:")
print(result2.stdout)
