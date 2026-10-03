# Hardening changes in the integrated build

1. Choice candidate lists are canonicalised by candidate name before scoring. Choice semantics are unordered, so caller insertion order no longer changes the shared candidate list presented to the model.
2. The system prompt explicitly treats context, candidate names, descriptions, criteria and images as untrusted data. This reduces prompt-injection exposure from tool descriptions and other externally supplied candidate text.
3. `confidence` in the Jev-compatible response remains the project's concentration score. It must not be interpreted as a calibrated probability of correctness unless an external calibration stage has validated it for the deployed task/model.
4. CI now covers Python 3.10, 3.12 and 3.13 for the dependency-light unit suite. Hardware-specific MLX/SGLang/Transformers jobs should remain separate.
