"""Check adjudicated label coverage and its exact selected-source crosswalk.

This checks the returned review workflow and source bindings, not the truth of
unobserved business requirements or the identities of the reviewers.
"""
import base64
from collections import Counter
import gzip
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent
LABELS = {
    'concrete_source_contract': '可建立具体行为契约',
    'conditional_source_contract': '仅能建立条件性契约',
    'interface_obligation': '仅接口义务',
}


def compressed(path):
    with gzip.open(path, 'rb') as stream:
        raw = stream.read(64000001)
    if len(raw) > 64000000:
        raise ValueError('review source envelope')
    return json.loads(raw)


def bindings(root=ROOT):
    root = Path(root)
    references = compressed(root.parent / 'reference_completion/inputs.json.gz')
    selected = [c for c in references['references']['contracts']
                if c['source_distribution'] == 'included']
    if len(selected) != 59:
        raise ValueError('review entry population changed')
    rows = []
    for number, contract in enumerate(selected, 1):
        source = references['sources'][contract['source_key']]
        if (hashlib.sha256(source['text'].encode()).hexdigest() != contract['source_sha256']
                or source['sha256'] != contract['source_sha256']
                or any(source[k] != contract[k] for k in ('repository', 'snapshot', 'path'))):
            raise ValueError('review reference source identity')
        anchor = dict(path=contract['path'], function=contract['function'],
                      line=contract['line'], end_line=contract['end_line'],
                      source_sha256=contract['source_sha256'])
        rows.append(dict(id=f'S{number:03}', scope='selected_entry',
                         repository=contract['repository'], snapshot=contract['snapshot'],
                         reference_id=contract['id'], source_anchors=[anchor],
                         existing_contexts=len(contract['contexts'])))
    inputs = compressed(root / 'data/inputs.json.gz')
    raw_sources = {(s['project'], s['path']): s
                   for s in compressed(root / 'data/sources.json.gz')}
    primary = inputs['primary']['cases']
    delegated = {c['project']: c for c in inputs['delegated']['cases']}
    extensions = {c['project']: c for c in inputs['extensions']['cases']}
    for number, population in enumerate(inputs['population'], 1):
        project = population['project']
        pure = [c for c in primary if c['project'] == project]
        case = delegated.get(project)
        extension = extensions.get(project)
        selected_functions = pure if pure else case['functions']
        selected_functions = selected_functions + (extension['functions'] if extension else [])
        anchors = {}
        for function in selected_functions:
            source = raw_sources[project, function['member']]
            raw = base64.b64decode(source['content_base64'], validate=True)
            if (hashlib.sha256(raw).hexdigest() != function['source_sha256']
                    or any(source[k] != population[k] for k in ('repository', 'snapshot'))):
                raise ValueError('review empirical source identity')
            anchor = dict(path=function['member'], function=function['function'],
                          line=function['line'], end_line=function['end_line'],
                          source_sha256=function['source_sha256'])
            anchors[(anchor['path'], anchor['function'], anchor['line'])] = anchor
        rows.append(dict(id=f'N{number:03}', scope='selected_project_boundary',
                         project=project, repository=population['repository'],
                         snapshot=population['snapshot'],
                         source_anchors=[anchors[k] for k in sorted(anchors)],
                         existing_contexts=sum(len(c['inputs']) for c in pure) if pure
                         else len(case['samples']),
                         existing_extension_contexts=len(extension['samples']) if extension else 0))
    if len(rows) != 99 or len({r['id'] for r in rows}) != 99:
        raise ValueError('review crosswalk population')
    return rows


def verify_review(root=ROOT, methods=None):
    root = Path(root)
    if methods is None:
        methods = json.loads((root / 'methods.json').read_text(encoding='utf-8'))
    review = methods['source_contract_review']
    workflow = review['completed_workflow']
    if (workflow['status'] != 'complete' or workflow['initial_response_files'] != 6
            or workflow['final_response_files'] != 3 or workflow['initial_items'] != 230
            or workflow['final_items'] != 115 or workflow['missing_final_items']
            or not workflow['initial_pairs_and_adjudications_complete']
            or not workflow['raw_responses_preserved_unchanged']):
        raise ValueError('review workflow incomplete')
    expected = bindings(root)
    actual = review['source_binding_crosswalk']
    if len(actual) != 99 or [r['id'] for r in actual] != [r['id'] for r in expected]:
        raise ValueError('review crosswalk missing or duplicate item')
    counts = Counter()
    agreement = Counter()
    for row, bound in zip(actual, expected):
        if {key: row.get(key) for key in bound} != bound:
            raise ValueError('review source binding changed:' + bound['id'])
        if row['final_label'] not in LABELS or row['initial_left_label'] not in LABELS or row['initial_right_label'] not in LABELS:
            raise ValueError('review category')
        if row['resolution'] not in ('adopt_left', 'adopt_right', 'synthesized'):
            raise ValueError('review resolution')
        if (row['resolution'] == 'adopt_left' and row['final_label'] != row['initial_left_label']
                or row['resolution'] == 'adopt_right' and row['final_label'] != row['initial_right_label']):
            raise ValueError('review adoption conflict')
        counts[LABELS[row['final_label']]] += 1
        agreement['same' if row['initial_left_label'] == row['initial_right_label'] else 'different'] += 1
    if dict(counts) != review['final_categories']:
        raise ValueError('review final category total')
    pair = next(x for x in review['initial_judgment_agreement'] if x['pair'] == 'AB')
    if agreement['same'] != pair['same_judgment'] or agreement['different'] != pair['different_judgment']:
        raise ValueError('review initial agreement changed')
    projects = {r['project']: r for r in methods['projects']}
    for row in actual[59:]:
        if projects[row['project']]['submitted_source_contract_category'] != LABELS[row['final_label']]:
            raise ValueError('review/project category mismatch')
    actions = review['method_and_design_dispositions']
    if [r['id'] for r in actions] != [f'M{n:02}' for n in range(1, 9)] + [f'E{n:02}' for n in range(1, 9)]:
        raise ValueError('review method/design omission')
    if any(not r['current_disposition'] or not r['submitted_judgment'] for r in actions):
        raise ValueError('review method/design disposition missing')
    if review['independent_semantic_gold_claimed'] or review['raw_response_text_or_reviewer_identities_distributed']:
        raise ValueError('unsupported review provenance claim')
    return dict(source_contract_items=99,method_topics=8,design_topics=8,
                completed_final_items=115,source_bindings_checked=True,
                initial_same_category=agreement['same'],initial_different_category=agreement['different'],
                selected_source_review_complete=True,independent_business_intent_oracle=False)


if __name__ == '__main__':
    print(json.dumps(verify_review(), indent=2))
