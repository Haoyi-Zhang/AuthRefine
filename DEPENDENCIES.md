# Dependency Envelope

The scientific implementation is designed to run with the Python standard library. The release verifier records import candidates and executes the test suite with warnings promoted to errors and with `python -OO`. LaTeX, BibTeX, `pdfinfo`, and rasterization tools are build/inspection dependencies for the manuscript, not runtime dependencies of the checker.

Static import discovery identified the following names for manual classification: `cases`, `checker`, `compiler`, `exhaustive_audit`, `experiments`, `extensions`, `language`, `oracle`, `policy`, `public_inputs`, `reference_check`, `symbolic`. Their presence must not be interpreted automatically as PyPI dependencies; local packages and optional tooling can appear in this list.
