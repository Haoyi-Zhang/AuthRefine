"""Wger's selected authentication guard to owner-bearing creation primitive.

Source bodies are passive data. The serializer's insert contract is an owned
SQLite projection, not execution of original serializers, routers or ORM code.
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

ROOT=Path(__file__).resolve().parent
ART=ROOT.parent
sys.path.insert(0,str(ART/'src'))
from effect_slice import Capability,DataRecord,EffectInterpreter,extract_effect_program
from native_casbin import AdmissionError
from source_bindings import require_static_class_members


class OwnerMismatch(ValueError):
    pass


def programs():
    source=json.loads(gzip.decompress((ROOT/'sources.json.gz').read_bytes()))
    case=next(r for r in source['rows'] if r['repository_id']==7705569)
    specs=[('wger/manager/api/permissions.py','RoutinePermission','has_permission'),
           ('wger/manager/api/views.py','RoutineViewSet','perform_create')]
    nodes,bindings={},{}
    for path,cls,name in specs:
        m=next(m for m in case['modules'] if m['path']==path)
        if hashlib.sha256(m['text'].encode()).hexdigest()!=m['utf8_text_sha256']:
            raise AdmissionError('original owner-transfer source changed')
        classes=[n for n in ast.parse(m['text']).body if isinstance(n,ast.ClassDef) and n.name==cls]
        if len(classes)!=1:
            raise AdmissionError('ambiguous owner-transfer class')
        require_static_class_members(classes[0],(name,))
        matches=[n for n in classes[0].body if isinstance(n,ast.FunctionDef) and n.name==name]
        if len(matches)!=1:
            raise AdmissionError('ambiguous owner-transfer function')
        nodes[name]=deepcopy(matches[0])
        bindings[path]=m['utf8_text_sha256']
    module=ast.Module(body=[ast.ClassDef(name='Selected',bases=[],keywords=[],body=list(nodes.values()),decorator_list=[])],type_ignores=[])
    compiled=extract_effect_program(ast.unparse(ast.fix_missing_locations(module)).encode(),'Selected',tuple(nodes))
    return compiled,dict(repository=case['repository'],snapshot=case['snapshot'],source_text_bindings=bindings,
        functions={k:dict(line=n.lineno,end_line=n.end_lineno) for k,n in nodes.items()})


def run(control=None):
    compiled,identity=programs()
    rows=[]
    for actor in ('user-1','user-2','unauthenticated-record','absent-record'):
        for supplied_owner in (None,1,2,3):
            users={i:DataRecord('User',dict(pk=i,is_authenticated=i!=3)) for i in (1,2,3)}
            user={'user-1':users[1],'user-2':users[2],'unauthenticated-record':users[3],'absent-record':None}[actor]
            request=DataRecord('Request',dict(user=user))
            receiver=DataRecord('View',dict(request=request))
            machine=EffectInterpreter(compiled,receiver,{})
            allowed=bool(machine.run('has_permission',[request,DataRecord('ViewInput',{})]))
            calls=[]
            with sqlite3.connect(':memory:') as db:
                db.execute('CREATE TABLE owned_routine(id INTEGER PRIMARY KEY,user_id INTEGER,title TEXT)')
                db.execute('INSERT INTO owned_routine VALUES(7,2,?)',('unrelated-row',))
                def save(*,user):
                    calls.append(user)
                    actual=user
                    if control=='client_owner':
                        actual=users[supplied_owner if supplied_owner is not None else 3]
                    if control!='omit_insert':
                        db.execute('INSERT INTO owned_routine VALUES(8,?,?)',(actual.fields['pk'],'owned-new-row'))
                    return DataRecord('Created',dict(user=actual))
                serializer=DataRecord('OwnedSerializer',dict(save=Capability('explicit owner-bearing insert contract',save)))
                if allowed:
                    if control=='wrong_request':
                        receiver.fields['request']=DataRecord('Request',dict(user=users[3-user.fields['pk']]))
                    machine.run('perform_create',[serializer])
                actual=[list(r) for r in db.execute('SELECT id,user_id,title FROM owned_routine ORDER BY id')]
            wanted=[[7,2,'unrelated-row']]
            if actor in ('user-1','user-2'):
                wanted.append([8,int(actor[-1]),'owned-new-row'])
            if (allowed!=(len(wanted)==2) or actual!=wanted or len(calls)!=int(allowed)
                    or allowed and calls[0] is not request.fields['user']):
                raise OwnerMismatch('selected guard / exact owner argument / persisted insert differs')
            rows.append(dict(actor=actor,supplied_owner=supplied_owner,allowed=allowed,save_calls=len(calls),
                exact_request_user_transferred=allowed,expected_rows=wanted,observed_rows=actual))
    return dict(source=identity,contexts=len(rows),successful_inserts=sum(r['allowed'] for r in rows),
        stopped_before_insert=sum(not r['allowed'] for r in rows),rows=rows,differences=0,
        source_bodies_interpreted=True,original_application_modules_executed=False,new_independent_applications=0,
        boundary='selected RoutinePermission guard and complete perform_create body; given same request/view binding and owned serializer insert contract',
        remaining='original serializer validation,ORM implementation,other permission classes,queryset/dispatcher and transactions not certified')


def main():
    p=argparse.ArgumentParser()
    p.add_argument('--check',action='store_true')
    p.add_argument('--control',choices=['omit_insert','client_owner','wrong_request'])
    a=p.parse_args()
    try:
        value=run(a.control)
    except OwnerMismatch as error:
        if not a.control:
            raise
        print(json.dumps(dict(control=a.control,deliberate_fault_detected=True,reason=str(error))))
        return
    if a.control:
        raise ValueError('deliberate owner-transfer fault not detected')
    value=json.loads(json.dumps(value,sort_keys=True))
    path=ROOT/'owner-insert.json.gz'
    if a.check:
        if json.loads(gzip.decompress(path.read_bytes()))!=value:
            raise ValueError('source owner-insert result differs')
    else:
        path.write_bytes(gzip.compress(json.dumps(value,sort_keys=True).encode(),mtime=0))
    print(json.dumps({k:v for k,v in value.items() if k!='rows'},indent=2))


if __name__=='__main__':
    main()
