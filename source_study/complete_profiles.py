"""Replay the fixed Pretix and H19 source interfaces, including negative output."""
import json
from pathlib import Path
import sys

ROOT=Path(__file__).resolve().parent
sys.path[:0]=[str(ROOT/'code'),str(ROOT.parent/'src')]
from replay import data_bytes
from pretix_event_profile import run as pretix
from secret_metadata_profile import evaluate
from finite_observation_diagnosis import diagnose_observations
from h19_boundary_repair import run as repair_h19


def canonical(value):return json.loads(json.dumps(value))
def read(name):return json.loads(data_bytes(ROOT/'data'/name))


def verify():
    actual=canonical(pretix())
    if actual!=read('pretix-event-profile.json'):raise ValueError('complete source token/event observations differ')
    h19=canonical(evaluate());retained=read('h19-source-observations.json')
    h19.pop('completed_utc');retained.pop('completed_utc')
    if h19!=retained:raise ValueError('fixed H19 source profile differs')
    expected=read('h19-field-diagnosis.json')
    totals={}
    for label in ('before','after'):
        props=[dict(id=f'{i}:{kind}:{field}',expected=field in row['expected'][kind],
            observed=field in row['observed'][label][kind]) for i,row in enumerate(h19['rows'])
            for kind in ('query_fields','filter_fields') for field in ('id','token','user_id','expiry_date','max_expiry_date')]
        result=canonical(diagnose_observations(props))
        if result!=expected['diagnosis'][label]:raise ValueError('H19 field countermodel/shortest witness differs')
        totals[label]=result['nonagreeing_properties']
    repaired=canonical(repair_h19(h19))
    if repaired!=read('h19-boundary-repair.json'):
        raise ValueError('owned H19 boundary repair or exhaustive identity checks differ')
    return dict(pretix_token_event_contexts=actual['contexts'],pretix_actual_SELECTs=actual['actual_SELECTs'],pretix_differences=0,
        other_Pretix_authentication_profiles='not admitted',given_team_grant_set_not_plugin_inference=True,
        H19_fixed_contexts=18,H19_source_replay_and_checker_agree=True,H19_nonagreeing_properties=totals,
        H19_classification='nonmatching contract with shortest field witnesses,not unknown',
        H19_owned_boundary_repair=dict(contexts=repaired['contexts'],
            nonagreeing_properties=repaired['repaired_nonagreeing_properties'],
            exhaustive_metadata_exclusion_masks=repaired['exhaustive_metadata_exclusion_masks'],
            original_pair_unchanged=repaired['original_registry_and_upstream_source_unchanged']),
        historical_installed_version_not_inferred=True,source_applications_or_upstream_tests_executed=False)


if __name__=='__main__':print(json.dumps(verify(),indent=2))
