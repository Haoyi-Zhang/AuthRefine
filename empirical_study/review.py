"""Check adjudicated label coverage and its exact selected-source crosswalk.

This checks the returned review workflow and source bindings, not the truth of
unobserved business requirements or the identities of the reviewers.
"""
import ast
import base64
from collections import Counter
from fractions import Fraction
import gzip
import hashlib
import json
import math
from pathlib import Path

ROOT = Path(__file__).resolve().parent
LABELS = {
    'concrete_source_contract': '可建立具体行为契约',
    'conditional_source_contract': '仅能建立条件性契约',
    'interface_obligation': '仅接口义务',
}
METHOD_LABELS = {'发现需修正问题', '未发现需修正问题', '材料不足', '不适用'}


def check_anchor(raw, anchor, cache):
    identity = hashlib.sha256(raw).hexdigest()
    if identity not in cache:
        found = set()
        def walk(nodes, prefix=()):
            for node in nodes:
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                    path = prefix + (node.name,)
                    if not isinstance(node, ast.ClassDef):
                        found.add(('.'.join(path), node.lineno, node.end_lineno))
                    walk(node.body, path)
                else:
                    walk(ast.iter_child_nodes(node), prefix)
        walk(ast.parse(raw).body)
        cache[identity] = found
    if (type(anchor['line']) is not int or type(anchor['end_line']) is not int
            or (anchor['function'], anchor['line'], anchor['end_line']) not in cache[identity]):
        raise ValueError('review anchor does not name the original function')


def check_adoption(resolution, final, left, right):
    if resolution not in ('adopt_left', 'adopt_right', 'synthesized'):
        raise ValueError('review resolution')
    if resolution == 'adopt_left' and final != left or resolution == 'adopt_right' and final != right:
        raise ValueError('review adoption conflict')


def check_agreement(record, rows):
    count = len(rows)
    left = Counter(a for _, a, _ in rows)
    right = Counter(b for _, _, b in rows)
    different = [identifier for identifier, a, b in rows if a != b]
    integers = dict(items=count, same_judgment=count-len(different), different_judgment=len(different))
    if any(type(record.get(key)) is not int or record[key] != value for key, value in integers.items()):
        raise ValueError('review agreement denominator or count')
    if record.get('disagreement_ids') != different:
        raise ValueError('review disagreement identifiers')
    observed = Fraction(count-len(different), count)
    expected = Fraction(sum(left[k]*right[k] for k in left.keys() | right.keys()), count*count)
    kappa = None if expected == 1 else float((observed-expected)/(1-expected))
    for key, value in (('observed_agreement', float(observed)), ('cohen_kappa', kappa)):
        actual = record.get(key)
        if value is None:
            if actual is not None:raise ValueError('undefined review kappa')
        elif type(actual) not in (int, float) or not math.isfinite(actual) or not math.isclose(actual, value, rel_tol=0, abs_tol=1e-12):
            raise ValueError('review agreement statistic:' + key)


def compressed(path):
    with gzip.open(path, 'rb') as stream:
        raw = stream.read(64000001)
    if len(raw) > 64000000:
        raise ValueError('review source envelope')
    return json.loads(raw)


def bindings(root=ROOT):
    root = Path(root)
    definition_cache = {}
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
        check_anchor(source['text'].encode(), anchor, definition_cache)
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
            check_anchor(raw, anchor, definition_cache)
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
    counts = dict(initial_response_files=6, final_response_files=3, initial_items=230, final_items=115)
    if (workflow['status'] != 'complete'
            or any(type(workflow.get(key)) is not int or workflow[key] != value for key, value in counts.items())
            or workflow.get('missing_final_items') != []
            or workflow.get('initial_pairs_and_adjudications_complete') is not True
            or workflow.get('raw_responses_preserved_unchanged') is not True):
        raise ValueError('review workflow incomplete')
    totals = dict(items=99, method_topics=8, design_topics=8, initial_response_items=230, final_response_items=115)
    if any(type(review.get(key)) is not int or review[key] != value for key,value in totals.items()):
        raise ValueError('review topic totals')
    expected = bindings(root)
    actual = review['source_binding_crosswalk']
    if len(actual) != 99 or [r['id'] for r in actual] != [r['id'] for r in expected]:
        raise ValueError('review crosswalk missing or duplicate item')
    counts = Counter()
    agreement = Counter()
    for row, bound in zip(actual, expected):
        if json.dumps({key: row.get(key) for key in bound},sort_keys=True,allow_nan=False) != json.dumps(bound,sort_keys=True,allow_nan=False):
            raise ValueError('review source binding changed:' + bound['id'])
        if row['final_label'] not in LABELS or row['initial_left_label'] not in LABELS or row['initial_right_label'] not in LABELS:
            raise ValueError('review category')
        check_adoption(row['resolution'], row['final_label'], row['initial_left_label'], row['initial_right_label'])
        counts[LABELS[row['final_label']]] += 1
        agreement['same' if row['initial_left_label'] == row['initial_right_label'] else 'different'] += 1
    if dict(counts) != review['final_categories']:
        raise ValueError('review final category total')
    projects = {r['project']: r for r in methods['projects']}
    for row in actual[59:]:
        if projects[row['project']]['submitted_source_contract_category'] != LABELS[row['final_label']]:
            raise ValueError('review/project category mismatch')
    actions = review['method_and_design_dispositions']
    if [r['id'] for r in actions] != [f'M{n:02}' for n in range(1, 9)] + [f'E{n:02}' for n in range(1, 9)]:
        raise ValueError('review method/design omission')
    if any(not r['current_disposition'] or not r['submitted_judgment'] for r in actions):
        raise ValueError('review method/design disposition missing')
    for row in actions:
        fields = ('submitted_judgment', 'initial_left_judgment', 'initial_right_judgment')
        if any(row.get(key) not in METHOD_LABELS for key in fields):
            raise ValueError('review method/design category')
        check_adoption(row.get('resolution'), row['submitted_judgment'], row['initial_left_judgment'], row['initial_right_judgment'])
    pairs = review['initial_judgment_agreement']
    if len(pairs) != 3 or {r.get('pair') for r in pairs} != {'AB', 'CD', 'EF'}:
        raise ValueError('review agreement pair coverage')
    groups = {'AB':[(r['id'],r['initial_left_label'],r['initial_right_label']) for r in actual],
              'CD':[(r['id'],r['initial_left_judgment'],r['initial_right_judgment']) for r in actions[:8]],
              'EF':[(r['id'],r['initial_left_judgment'],r['initial_right_judgment']) for r in actions[8:]]}
    for pair in pairs:check_agreement(pair,groups[pair['pair']])
    if review['independent_semantic_gold_claimed'] or review['raw_response_text_or_reviewer_identities_distributed']:
        raise ValueError('unsupported review provenance claim')
    return dict(source_contract_items=99,method_topics=8,design_topics=8,
                completed_final_items=115,source_bindings_checked=True,
                original_function_anchors_checked=sum(len(r['source_anchors']) for r in expected),
                initial_agreement_pairs_recomputed=3,
                initial_same_category=agreement['same'],initial_different_category=agreement['different'],
                selected_source_review_complete=True,independent_business_intent_oracle=False)


if __name__ == '__main__':
    print(json.dumps(verify_review(), indent=2))
