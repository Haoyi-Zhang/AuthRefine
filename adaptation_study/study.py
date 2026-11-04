"""Source-anchored adaptation phenotypes on fixed selected function scopes.

Features describe observed source constructs, not permission outcomes, an
independent annotation gold set, complete application coverage or prevalence.
"""
import argparse,ast,gzip,hashlib,json
from collections import Counter
from pathlib import Path
ROOT=Path(__file__).resolve().parent
TAXONOMY={
 'identity_input':'Reference to request/user/auth identity or explicit current-user dependency',
 'credential_processing':'Explicit authentication/credential-validation function name or operation',
 'mutation_call':'Named mutation/persistence call; actual durable effects require case-level observation',
 'identity_handoff':'Reference to tenant/project/owner/organizer identity in the selected body',
 'dynamic_lookup':'Explicit getattr/import-module/dynamic-registry lookup',
 'asynchronous_flow':'Async function or await in selected function',
 'query_dependency':'Explicit object query or filter/lookup primitive',
 'exception_flow':'Explicit exception handler in selected function'}
def name(node):
    if isinstance(node,ast.Name):return node.id
    if isinstance(node,ast.Attribute):return name(node.value)+'.'+node.attr
    return ''
def classify(node):
    tags=set();n=name(node)
    if isinstance(node,(ast.Name,ast.Attribute)):
        if n in ('request.user','request.auth','user.is_authenticated','request.user.is_authenticated'):tags.add('identity_input')
        if isinstance(node,ast.Attribute) and node.attr in ('owner','owner_id','project','project_id','tenant','tenant_id','organizer','organizer_id'):
            tags.add('identity_handoff')
    if isinstance(node,(ast.FunctionDef,ast.AsyncFunctionDef)):
        if any(s in node.name.lower() for s in ('authenticate','validate_token','verify_token','get_current_user')):tags.add('credential_processing')
        if isinstance(node,ast.AsyncFunctionDef):tags.add('asynchronous_flow')
    if isinstance(node,ast.Await):tags.add('asynchronous_flow')
    if isinstance(node,ast.Try):tags.add('exception_flow')
    if isinstance(node,ast.Call):
        called=name(node.func);leaf=called.rsplit('.',1)[-1]
        if leaf in ('get_current_user','get_current_active_user','get_authenticated_user'):tags.add('identity_input')
        if leaf in ('authenticate','authenticate_credentials','decode_token','verify_token','validate_token'):tags.add('credential_processing')
        if isinstance(node.func,ast.Attribute) and leaf in ('save','delete','update','bulk_create','bulk_update','commit','add','remove','upsert','insert'):
            tags.add('mutation_call')
        if leaf in ('getattr','import_module','get_plugin','get_plugins'):tags.add('dynamic_lookup')
        if leaf in ('get_object_or_404','filter','get','select_related','prefetch_related','all','first','exists') and isinstance(node.func,(ast.Name,ast.Attribute)):
            tags.add('query_dependency')
    return tags
def run():
    source=json.loads(gzip.decompress((ROOT/'sources.json.gz').read_bytes()))
    rows=[]
    for r in source['rows']:
        evidence={k:[] for k in TAXONOMY};functions=0;parse_errors=[]
        for m in r['modules']:
            if hashlib.sha256(m['text'].encode('utf-8')).hexdigest()!=m['utf8_text_sha256']:
                raise ValueError('selected source text identity differs: '+m['path'])
            try:tree=ast.parse(m['text'])
            except SyntaxError as error:
                parse_errors.append(dict(path=m['path'],line=error.lineno,reason=error.msg));continue
            lines=m['text'].splitlines()
            selected={(f['line'],f['end_line']):f['name'] for f in m['selected_functions']}
            for fn in ast.walk(tree):
                key=(getattr(fn,'lineno',0),getattr(fn,'end_lineno',0))
                if isinstance(fn,(ast.FunctionDef,ast.AsyncFunctionDef)) and key in selected:
                    functions+=1
                    decorator_nodes={id(n) for d in fn.decorator_list for n in ast.walk(d)}
                    for n in ast.walk(fn):
                        if id(n) in decorator_nodes:continue
                        for tag in sorted(classify(n)):
                            ev=dict(path=m['path'],function=selected[key],line=n.lineno,
                                snippet=lines[n.lineno-1].strip(),node=type(n).__name__)
                            if ev not in evidence[tag]:evidence[tag].append(ev)
        rows.append(dict(repository=r['repository'],repository_id=r['repository_id'],stratum=r['stratum'],
            functions=functions,features={k:('observed' if evidence[k] else 'unassessed_parse_gap' if parse_errors else 'not_observed_in_selected_scope') for k in TAXONOMY},
            parse_errors=parse_errors,
            evidence=evidence,static_frontend_status=r['old_static_status']))
    assert len(rows)==48 and len({r['repository_id'] for r in rows})==48
    counts={k:sum(r['features'][k]=='observed' for r in rows) for k in TAXONOMY}
    return dict(scope=source['scope'],denominator=48,unit='original source snapshot with at least one observed selected-function construct',
        classification='multi-label source constructs; not end-to-end semantic coverage',taxonomy=TAXONOMY,
        counts=counts,percentages={k:round(100*v/48,2) for k,v in counts.items()},
        unresolved_scope_counts={k:sum(r['features'][k]=='unassessed_parse_gap' for r in rows) for k in TAXONOMY},
        negative_scope='non-observation is not proof of absence in the application',
        manual_effort_minutes=None,independent_gold_claimed=False,rows=rows)

def audit_casebook(book=None):
    if book is None:book=json.loads((ROOT/'casebook.json').read_text(encoding='utf-8'))
    sources=json.loads(gzip.decompress((ROOT/'sources.json.gz').read_bytes()))
    lookup={r['repository_id']:r for r in sources['rows']}
    if len(book['cases'])!=8 or len({r['repository_id'] for r in book['cases']})!=8:raise ValueError('case denominator differs')
    if (book['total_cases']!=8 or book['centralized']!=sum(r['stratum']=='centralized' for r in book['cases'])
            or book['cross_component']!=sum(r['stratum']=='cross_component' for r in book['cases'])):
        raise ValueError('case stratum total differs from actual rows')
    counts={axis:Counter() for axis in book['adaptation_axes']}
    modes={axis:Counter() for axis in book['adaptation_axes']}
    anchors=0
    for case in book['cases']:
        original=lookup[case['repository_id']]
        if any(case[k]!=original[k] for k in ('repository','snapshot','stratum')):raise ValueError('case source identity differs')
        if set(case['axis_classification'])!=set(book['adaptation_axes']):raise ValueError('case axis missing')
        modules={m['path']:m['text'] for m in lookup[case['repository_id']]['modules']}
        for a in case['source_anchors']:
            text=(ROOT/a['public_source_path']).read_text() if 'public_source_path' in a else modules[a['path']]
            sliced='\n'.join(text.splitlines()[a['line']-1:a['end_line']])
            if hashlib.sha256(sliced.encode()).hexdigest()!=a['slice_sha256']:raise ValueError('case anchor differs')
            def functions(nodes,prefix=''):
                for node in nodes:
                    if isinstance(node,(ast.FunctionDef,ast.AsyncFunctionDef,ast.ClassDef)):
                        qualified=prefix+node.name
                        if isinstance(node,(ast.FunctionDef,ast.AsyncFunctionDef)):
                            yield qualified,node.lineno,node.end_lineno
                        yield from functions(node.body,qualified+'.')
            if (a['function'],a['line'],a['end_line']) not in set(functions(ast.parse(text).body)):
                raise ValueError('case function name/extent does not bind original AST')
            anchors+=1
        functions={a['function'] for a in case['source_anchors']}
        for axis,record in case['axis_classification'].items():
            if (record['handling'] not in book['resolution_modes'] or not record['label']
                    or not record['evidence_functions'] or set(record['evidence_functions'])-functions):
                raise ValueError('case classification has no admitted source witness')
            counts[axis][record['label']]+=1
            modes[axis][record['handling']]+=1
    counts={axis:dict(sorted(v.items())) for axis,v in counts.items()}
    if counts!=book['axis_counts'] or any(sum(v.values())!=8 for v in counts.values()):raise ValueError('case axis count differs')
    actual_scope={k:sum(r[field]==k for r in book['cases']) for field,allowed in (
        ('identity_resolution',('supplied_identity_context','source_lookup_with_native_primitive')),
        ('effect_boundary',('guard_or_query_before_business_write','selected_business_write_and_native_readback'))) for k in allowed}
    if (actual_scope!=book['case_scope_counts'] or sum(actual_scope[k] for k in ('supplied_identity_context','source_lookup_with_native_primitive'))!=8
            or sum(actual_scope[k] for k in ('guard_or_query_before_business_write','selected_business_write_and_native_readback'))!=8
            or {k:round(100*v/8,2) for k,v in actual_scope.items()}!=book['case_scope_percentages']):
        raise ValueError('case scope counts/proportions do not match actual rows')
    modes={axis:dict(sorted(v.items())) for axis,v in modes.items()}
    totals=dict(sorted(Counter(r['axis_classification'][axis]['handling'] for r in book['cases'] for axis in book['adaptation_axes']).items()))
    lifecycle=dict(Counter(r['credential_lifecycle_profile'] for r in book['cases']))
    if (modes!=book['axis_handling_counts'] or totals!=book['handling_counts'] or sum(totals.values())!=40
            or book['handling_percentage_denominator']!=40
            or {k:round(100*v/40,2) for k,v in totals.items()}!=book['handling_percentages']
            or lifecycle!=book['credential_lifecycle_scope_counts']):raise ValueError('adaptation mode/lifecycle denominator differs')
    return dict(cases=8,axis_assignments=40,source_anchors=anchors,axis_counts=counts,
        case_scope_counts=actual_scope,case_scope_percentages=book['case_scope_percentages'],
        handling_counts=totals,handling_percentages=book['handling_percentages'],axis_handling_counts=modes,
        credential_lifecycle_scope_counts=lifecycle,
        scope='descriptive checked-interface classification, not semantic gold or application prevalence')
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--output',type=Path);p.add_argument('--check',action='store_true');p.add_argument('--check-casebook',action='store_true');a=p.parse_args()
    if a.check_casebook:print(json.dumps(audit_casebook(),indent=2));raise SystemExit(0)
    r=run()
    if a.check:
        if json.loads(gzip.decompress((ROOT/'survey.json.gz').read_bytes()))!=r:raise ValueError('survey differs; use the declared Python3.14 parser, do not hide parse gaps')
    if a.output:
        raw=json.dumps(r,sort_keys=True).encode()
        if a.output.suffix=='.gz':a.output.write_bytes(gzip.compress(raw,mtime=0))
        else:a.output.write_bytes(raw)
    print(json.dumps({k:v for k,v in r.items() if k!='rows'},indent=2))
