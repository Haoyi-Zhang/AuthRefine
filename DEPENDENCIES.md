# Dependency Envelope

The finite checker and core campaign use only the Python standard library, but their supported runtime is deliberately narrower than “all standard-library platforms.” The campaign and several measurement modules import the POSIX `resource` module unconditionally for CPU and high-water RSS accounting. The supported environment is therefore:

- CPython on Linux;
- a working POSIX `resource` module;
- a filesystem that supports ordinary temporary directories;
- `C.UTF-8` for the four-configuration release campaign.

The retained earlier release-entry record was produced with CPython 3.13 on Linux. The four retained CPython 3.13 Linux runs in `results/current` cover the then-current 56-method unit suite, seven documented commands, and 10,000 primary records per configuration with scientific-field agreement. That historical count is not the current test inventory; see the README for later focused regressions and their recorded execution scope. Earlier portable Windows checks have a narrower scope. Native Windows is not supported for full reproduction because its Python standard library does not provide `resource`. Use WSL with a Linux distribution, or a Linux container with this directory mounted as the working directory. The artifact does not claim full native Windows or macOS reproduction. A future port would need to isolate resource measurement and normalize platform-specific `ru_maxrss` units without changing any semantic verdict.

On the supported Linux environment, `peak_rss_kib` records `ru_maxrss` in KiB. CPU time and wall time are reported in seconds. These values are removed from scientific-record comparisons; they are not used to decide policy equivalence.

A runtime preflight is:

The complete expanded unit suite additionally exercises the selected native
engine, request objects, YAML decoding, SQL expressions and wire records.
Install `requirements-test.txt` in an isolated environment before running
`verify_release.py`; it is not a standard-library-only test suite. The finite
compiler/checker and generated core campaign remain standard-library programs.
Do not install `casbin` and `pycasbin` in the same environment: both provide
the same import name. The requirements select the default recorded Casbin
profile; other explicit profiles need separate environments.

```sh
python -m venv /tmp/authrefine-checks
/tmp/authrefine-checks/bin/python -m pip install -r requirements-test.txt
/tmp/authrefine-checks/bin/python -B verify_release.py --json
```

```bash
python -c "import resource, sys; assert sys.platform.startswith('linux')"
```

LaTeX, BibTeX, `pdfinfo`, and rasterization tools are build or visual-inspection dependencies for the manuscript, not runtime dependencies of the checker. Static import discovery can list local module names such as `cases`, `checker`, `compiler`, `experiments`, or `symbolic`; those names are part of this repository and must not be interpreted automatically as PyPI dependencies.
# Source-bound credential replay

The portable `source_study` table verifier uses the Python standard library and
the existing owned finite checker. Native credential replay requires non-root
Linux, Python 3.12+, bubblewrap and prlimit. It uses the source-pinned Django
6.1.2 profile with asgiref 3.9.1 and sqlparse 0.5.3. The explicit preparation
command downloads and checks pure wheels without executing installation hooks.
This is not the full target application's requirements or deployment lock.
