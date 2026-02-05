LLM fixtures for offline, deterministic tests.

Files:
- env_bridge_vectors.json: provider env bridge cases (canonical + aliases, env vs .env precedence).
- model_selection_vectors.json: model selection fallback cases based on available provider keys.
- summarize_thread_refine_single.json: sample single-thread LLM refinement payload.
- summarize_thread_refine_multi.json: sample multi-thread refinement payload (threads + aggregate).
- summarize_thread_refine_invalid.txt: invalid JSON payload for failure-path tests.
