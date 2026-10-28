"""Explicitly selected and isolated, reviewed native engine distributions."""
from __future__ import annotations

from importlib import metadata
import os
from pathlib import Path


PROFILES = {"casbin-1.43.0": ("casbin", "1.43.0"), "pycasbin-2.8.0": ("pycasbin", "2.8.0"),
            "casbin-1.41.0": ("casbin", "1.41.0"), "casbin-1.37.0": ("casbin", "1.37.0")}


def engine_identity():
    # Imported lazily to avoid a module cycle with the native admission code.
    from native_casbin import AdmissionError
    selected = os.environ.get("AUTHREFINE_RUNTIME", "casbin-1.43.0")
    if selected not in PROFILES:
        raise AdmissionError("select a reviewed native runtime profile", "dependency_missing")
    package, expected = PROFILES[selected]
    try:
        import casbin
        distribution = metadata.distribution(package)
    except ImportError as error:
        raise AdmissionError("selected native runtime is not installed in this interpreter", "dependency_missing") from error
    if distribution.version != expected:
        raise AdmissionError("selected native distribution has an unreviewed release", "dependency_missing")
    imported = Path(casbin.__file__).resolve()
    declared = Path(distribution.locate_file("casbin/__init__.py")).resolve()
    if imported != declared:
        raise AdmissionError("imported casbin module does not belong to the selected distribution", "dependency_missing")
    for other, _ in PROFILES.values():
        if other == package:
            continue
        try:
            alternative = metadata.distribution(other)
        except metadata.PackageNotFoundError:
            continue
        if Path(alternative.locate_file("casbin/__init__.py")).resolve() == imported:
            raise AdmissionError("two distributions claim the same casbin import; isolate their runtimes", "dependency_missing")
    return {"profile": selected, "distribution": package, "release": expected,
            "imported_module": str(imported)}
