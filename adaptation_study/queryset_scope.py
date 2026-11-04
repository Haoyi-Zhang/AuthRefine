"""Source-bound Wger user/trainer/public query scope over an owned SQL table.

Only the selected original function bodies are interpreted as data. Session
identity is an explicit input, not authentication or proof of trainer authority.
"""
import argparse
import ast
from copy import deepcopy
import gzip
import hashlib
import json
from pathlib import Path
import sqlite3
import sys

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT.parent / 'src'))
from effect_slice import Capability, DataRecord, EffectInterpreter, extract_effect_program
from native_casbin import AdmissionError
from source_bindings import require_import_bindings, require_static_class_members, require_static_definitions


class QueryMismatch(ValueError):
    pass


def programs():
    source = json.loads(gzip.decompress((ROOT / 'sources.json.gz').read_bytes()))
    case = next(r for r in source['rows'] if r['repository_id'] == 7705569)
    module = next(m for m in case['modules'] if m['path'] == 'wger/manager/api/views.py')
    raw = module['text'].encode('utf-8')
    if hashlib.sha256(raw).hexdigest() != module['utf8_text_sha256']:
        raise AdmissionError('original Wger query source differs')
    tree = ast.parse(raw)
    require_import_bindings(raw, {'Q': ('django.db.models', 0, 'Q'),
                                  'Routine': ('wger.manager.models', 0, 'Routine')})
    require_static_definitions(tree, ['request_user_or_trainer_q', 'RoutineViewSet'])
    cls = next(n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == 'RoutineViewSet')
    require_static_class_members(cls, ['get_queryset'])
    fn = next(n for n in cls.body if isinstance(n, ast.FunctionDef) and n.name == 'get_queryset')
    helper = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == 'request_user_or_trainer_q')
    selected = ast.Module(body=[ast.ClassDef(name='Selected', bases=[], keywords=[],
        body=[deepcopy(fn)], decorator_list=[]), deepcopy(helper)], type_ignores=[])
    compiled = extract_effect_program(ast.unparse(ast.fix_missing_locations(selected)).encode(),
                                      'Selected', ['get_queryset'], ['request_user_or_trainer_q'])
    return compiled, dict(repository=case['repository'], snapshot=case['snapshot'],
        path=module['path'], source_text_binding=module['utf8_text_sha256'],
        functions={n.name: dict(line=n.lineno, end_line=n.end_lineno) for n in (fn, helper)})


class QueryInterpreter(EffectInterpreter):
    def value(self, node, env):
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.BitOr):
            self.charge()
            left, right = self.value(node.left, env), self.value(node.right, env)
            if not all(isinstance(v, DataRecord) and v.kind == 'OwnedQ' for v in (left, right)):
                raise AdmissionError('query OR needs two explicit predicate records')
            return DataRecord('OwnedQ', {'predicate': ['or', left.fields['predicate'], right.fields['predicate']]})
        return super().value(node, env)


def sql(predicate):
    if predicate == ['false']:
        return '0', []
    if type(predicate) is not list or not predicate:
        raise AdmissionError('unbound predicate')
    if predicate[0] == 'or' and len(predicate) == 3:
        left, lp = sql(predicate[1])
        right, rp = sql(predicate[2])
        return '(' + left + ' OR ' + right + ')', lp + rp
    if len(predicate) == 2 and predicate[0] in ('user_id', 'is_public'):
        value = predicate[1]
        if predicate[0] == 'user_id' and type(value) is int and 1 <= value <= 100:
            return 'user_id = ?', [value]
        if predicate[0] == 'is_public' and type(value) is bool:
            return 'is_public = ?', [int(value)]
    raise AdmissionError('query predicate outside selected typed scope')


def observe(compiled, user_id, trainer, fake_view, control=None):
    user = DataRecord('User', {'pk': user_id})
    session = {} if trainer == 'missing' else {'trainer.identity': trainer}
    request = DataRecord('Request', {'user': user, 'session': session})
    fields = {'request': request}
    if fake_view != 'missing':
        fields['swagger_fake_view'] = fake_view
    if control == 'ignore_fake_view':
        fields['swagger_fake_view'] = False
    receiver = DataRecord('View', fields)
    calls = []

    def q(**kwargs):
        if len(kwargs) != 1 or next(iter(kwargs)) not in ('user', 'user_id', 'is_public'):
            raise AdmissionError('unexpected Q primitive arguments')
        key, value = next(iter(kwargs.items()))
        calls.append(['Q', key])
        if key == 'user':
            if value is not user:
                raise AdmissionError('query owner must be the exact selected request user')
            predicate = ['user_id', 3 - user_id if control == 'wrong_owner' else value.fields['pk']]
        else:
            predicate = [key, value]
        if control == 'omit_trainer' and key == 'user_id' or control == 'omit_public' and key == 'is_public':
            predicate = ['false']
        sql(predicate)
        return DataRecord('OwnedQ', {'predicate': predicate})

    initial = [(1, 1, 0), (2, 2, 0), (3, 3, 0), (4, 1, 1), (5, 2, 1), (6, 3, 1)]
    with sqlite3.connect(':memory:') as db:
        db.execute('CREATE TABLE owned_routine(id INTEGER PRIMARY KEY, user_id INTEGER, is_public INTEGER)')
        db.executemany('INSERT INTO owned_routine VALUES(?,?,?)', initial)

        def select(predicate):
            condition, params = sql(predicate)
            calls.append(['filter', condition])
            return [list(row) for row in db.execute('SELECT id,user_id,is_public FROM owned_routine WHERE ' + condition + ' ORDER BY id', params)]

        def filtered(predicate):
            if not isinstance(predicate, DataRecord) or predicate.kind != 'OwnedQ':
                raise AdmissionError('selected filter needs a typed predicate')
            return select(predicate.fields['predicate'])

        def empty():
            calls.append(['none'])
            return []

        manager = DataRecord('Manager', {'filter': Capability('owned SQL selection', filtered),
                                         'none': Capability('empty queryset', empty)})
        machine = QueryInterpreter(compiled, receiver,
            {'Q': Capability('typed literal Q construction', q),
             'Routine': DataRecord('Model', {'objects': manager})})
        actual = machine.run('get_queryset', [])
        after = [list(row) for row in db.execute('SELECT id,user_id,is_public FROM owned_routine ORDER BY id')]
    wanted = [] if fake_view is True else [list(r) for r in initial if r[1] == user_id or trainer not in ('missing', None, 0, False) and r[1] == trainer or r[2]]
    expected_helper = 0 if fake_view is True else 1
    if (actual != wanted or after != [list(r) for r in initial]
            or machine.function_calls.get('request_user_or_trainer_q', 0) != expected_helper
            or fake_view is True and calls != [['none']]):
        raise QueryMismatch('source user/trainer/public scope or schema-view short circuit differs')
    return dict(user_id=user_id, trainer_identity=trainer, swagger_fake_view=fake_view,
        expected_rows=wanted, observed_rows=actual, source_helper_calls=expected_helper,
        primitive_calls=calls, unchanged_store=True)


def run(control=None):
    compiled, identity = programs()
    rows = [observe(compiled, user, trainer, fake, control)
            for user in (1, 2) for trainer in ('missing', None, 0, 1, 2, 99)
            for fake in ('missing', False, True)]
    return dict(source=identity, contexts=len(rows), rows=rows, differences=0,
        schema_view_empty=sum(r['swagger_fake_view'] is True for r in rows),
        selected_scope_queries=sum(r['swagger_fake_view'] is not True for r in rows),
        original_application_modules_executed=False, new_independent_applications=0,
        boundary='complete selected get_queryset and user-or-trainer helper; owned Q/SQL projection',
        remaining='given session identity and authenticated user; session producer,trainer authority,original ORM and full dispatch not certified')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--check', action='store_true')
    parser.add_argument('--control', choices=['omit_trainer', 'omit_public', 'wrong_owner', 'ignore_fake_view'])
    args = parser.parse_args()
    try:
        report = run(args.control)
    except QueryMismatch as error:
        if not args.control:
            raise
        print(json.dumps(dict(control=args.control, deliberate_fault_detected=True, reason=str(error))))
        return
    if args.control:
        raise ValueError('selected query fault not detected')
    report = json.loads(json.dumps(report, sort_keys=True))
    path = ROOT / 'queryset-scope.json.gz'
    if args.check:
        if json.loads(gzip.decompress(path.read_bytes())) != report:
            raise ValueError('selected query-scope result differs')
    else:
        path.write_bytes(gzip.compress(json.dumps(report, sort_keys=True).encode(), mtime=0))
    print(json.dumps({k: v for k, v in report.items() if k != 'rows'}, indent=2))


if __name__ == '__main__':
    main()
