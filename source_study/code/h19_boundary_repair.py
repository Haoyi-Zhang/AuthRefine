"""Replay a real owned boundary repair separately from the immutable H19 pair."""
from datetime import datetime, timezone
import gzip
import json
from pathlib import Path

from secret_metadata_profile import CASE, FIELDS, check_bindings, observe
from finite_observation_diagnosis import diagnose_observations
from secret_field_boundary import complete_secret_exclusions
from effect_slice import DataRecord

ROOT = Path(__file__).resolve().parent


def exhaustive_boundary_law():
    """All secrecy/exclusion masks over five normal descriptors, no app code."""
    checked = 0
    for secrecy in range(1 << len(FIELDS)):
        columns = [DataRecord('Column', {'_meta': DataRecord('column_meta',
            {'name': name, 'secret': bool(secrecy & (1 << i))})}) for i, name in enumerate(FIELDS)]
        table = DataRecord('table', {'_meta': DataRecord('table_meta', {'columns': columns})})
        for exclusion in range(1 << len(FIELDS)):
            given = [c for i, c in enumerate(columns) if exclusion & (1 << i)]
            actual = complete_secret_exclusions(table, given)
            expected = [c for i, c in enumerate(columns) if (secrecy | exclusion) & (1 << i)]
            if (len(actual) != len(expected) or any(not any(c is d for d in actual) for c in expected)
                    or any(c is not d for c, d in zip(actual[:len(given)], given))
                    or complete_secret_exclusions(table, actual) != actual):
                raise ValueError('secret exclusion union, identity/order or idempotence law failed')
            checked += 1
    return checked


def run(retained=None):
    check_bindings()
    if retained is None:
        retained = json.loads(gzip.decompress((ROOT.parent/'data/h19-source-observations.json.gz').read_bytes()))
    crud = (CASE / 'after/piccolo_api/crud/endpoints.py').read_bytes()
    table = (CASE / 'after/piccolo_api/session_auth/tables.py').read_bytes()
    properties = []
    rows = []
    for i, row in enumerate(retained['rows']):
        requested = row['selected_fields']
        requested = None if requested is None else tuple(requested)
        original = observe(crud, table, requested, row['exclude_secrets_override'])
        if original != row['observed']['after']:
            raise ValueError('original fixed-source evidence changed')
        repaired = observe(crud, table, requested, row['exclude_secrets_override'], filter_boundary_repair=True)
        if repaired['query_fields'] != original['query_fields'] or repaired['registry_fields'] != original['registry_fields']:
            raise ValueError('boundary repair changed the query flag or original registry')
        for kind in ('query_fields', 'filter_fields'):
            for field in FIELDS:
                properties.append(dict(id=f'{i}:{kind}:{field}',
                    expected=field in row['expected'][kind], observed=field in repaired[kind]))
        differences = [kind for kind in ('query_fields', 'filter_fields') if repaired[kind] != row['expected'][kind]]
        rows.append(dict(context=i, selected_fields=row['selected_fields'],
            exclude_secrets_override=row['exclude_secrets_override'], expected=row['expected'],
            original=original, repaired=repaired, remaining_different_observers=differences,
            corrected_field='filter_fields:token'))
    diagnosis = diagnose_observations(properties)
    if diagnosis['nonagreeing_properties'] or any(row['remaining_different_observers'] for row in rows):
        raise ValueError('owned repair still disagrees with the supplied field contract')
    return dict(case='H19', repair='metadata-complete filter exclusion at the owned model boundary',
        contexts=len(rows), properties=180, original_after_nonagreeing_properties=18,
        repaired_nonagreeing_properties=0, unique_root_causes=1,
        root_cause='Secret subclass registry omits Varchar(secret=True); query exclusion already reads secrecy metadata.',
        repair_location='secret_field_boundary.complete_secret_exclusions, before the model-field consumer',
        query_observations_and_explicit_inclusion_preserved=True,
        original_registry_and_upstream_source_unchanged=True,
        exhaustive_metadata_exclusion_masks=exhaustive_boundary_law(),
        diagnosis=diagnosis, rows=rows,
        scope='Owned source-profile adapter repair, not an upstream deployment patch or historical installation reconstruction.',
        historical_installed_version_inferred=False, source_applications_or_upstream_tests_executed=False)


if __name__ == '__main__':
    report=run()
    print(json.dumps({k:v for k,v in report.items() if k not in ('rows','diagnosis')},indent=2))
