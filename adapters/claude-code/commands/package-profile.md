# /package-profile

Profile a source package and select audit recipes.

Arguments:
- `source_path` default `.`
- `output_dir` default `audit-output`

Dispatch `package-profiler` with read-only tools. The output must conform to `schemas/package-profile.schema.json` and include package type, language, build system, input surfaces, high-risk modules, selected recipes, and confidence.
