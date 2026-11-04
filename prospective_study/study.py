"""Project-disjoint source transfer; original application code is passive data.

Primary uses the byte-bound frozen interpreter. Secondary adds declared entry,
superclass,nominal-identity and fixed Taiga component-dispatch interfaces. It
does not turn the same exposed projects into a second blind evaluation.
"""
import argparse
import ast
from copy import deepcopy
import gzip
import hashlib
import json
from pathlib import Path
import sys

ROOT=Path(__file__).resolve().parent
ART=ROOT.parent if (ROOT.parent/'src').is_dir() else next(p/'workspace/artifact' for p in ROOT.parents if (p/'workspace/artifact/src').is_dir())
sys.path[:0]=[str(ART/'src'),str(ART/'source_study/code')]
from effect_slice import (Capability,Closure,DataRecord,EffectInterpreter,RecordType,
                          Return,SliceFault,extract_effect_program)
from policy_slice import Call
from native_casbin import AdmissionError
from source_bindings import require_import_bindings,require_static_class_members
from finite_observation_diagnosis import diagnose_observations

def sha(raw):return hashlib.sha256(raw).hexdigest()
def load():
    data=json.loads(gzip.decompress((ROOT/'inputs.json.gz').read_bytes()))
    required={'src/effect_slice.py','src/policy_slice.py','src/source_bindings.py','src/native_casbin.py',
              'source_study/code/finite_observation_diagnosis.py'}
    if set(data['frozen_method_bindings'])!=required:raise ValueError('frozen kernel inventory differs')
    if any(sha((ART/p).read_bytes())!=h for p,h in data['frozen_method_bindings'].items()):
        raise ValueError('frozen method changed; primary is no longer a fixed-method transfer')
    for f in data['files']:
        if sha(f['text'].encode())!=f['sha256']:raise ValueError('attributed source text changed')
    return data

def module(data,repo,path):return next(f['text'] for f in data['files'] if f['repository']==repo and f['path']==path)
def declaration(text,qualified):
    tree=ast.parse(text)
    if '.' in qualified:
        owner,name=qualified.split('.',1)
        cls=next(n for n in tree.body if isinstance(n,ast.ClassDef) and n.name==owner)
        require_static_class_members(cls,[name])
        node=next(n for n in cls.body if isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef)) and n.name==name)
    else:
        owner='';node=next(n for n in tree.body if isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef)) and n.name==qualified)
    return owner,deepcopy(node)

def prepare(data,ref,adapted=False):
    text=module(data,ref['repository'],ref['path'])
    owner,node=declaration(text,ref['function'])
    if sha(ast.dump(ast.Module(body=node.body,type_ignores=[])).encode())!=ref['body_ast_sha256']:
        raise ValueError('complete reference function body differs')
    nodes=[]
    def append(owner,node):
        node=deepcopy(node);node.name=(owner+'__' if owner else '')+node.name
        node._source_owner=owner;nodes.append(node);return node.name
    entry=append(owner,node)
    if adapted and ref['repository']=='taigaio/taiga-back':
        bases=module(data,ref['repository'],'taiga/base/api/permissions.py')
        users=module(data,ref['repository'],'taiga/users/permissions.py')
        for qualified in ('ResourcePermission.__init__','PermissionComponent.__and__','PermissionComponent.__or__',
                          'PermissionOperator.__init__','Or.check_permissions','And.check_permissions',
                          'AllowAny.check_permissions','DenyAll.check_permissions',
                          'IsAuthenticated.check_permissions','IsSuperUser.check_permissions','IsObjectOwner.check_permissions'):
            own,fn=declaration(bases,qualified)
            if (own+'__'+fn.name)!=entry:append(own,fn)
        own,fn=declaration(users,'IsTheSameUser.check_permissions')
        if own+'__'+fn.name!=entry:append(own,fn)
    if adapted and ref['repository']=='allegro/ralph':
        require_import_bindings(text.encode(),{'BasePermission':('rest_framework.permissions',0,'BasePermission'),
                                               'SAFE_METHODS':('rest_framework.permissions',0,'SAFE_METHODS')})
        cls=next(n for n in ast.parse(text).body if isinstance(n,ast.ClassDef) and n.name==owner)
        if [ast.unparse(b) for b in cls.bases]!=['BasePermission'] or cls.decorator_list:
            raise AdmissionError('superclass profile no longer identifies the selected single base')
        fn=ast.parse(data['reference_input']['native_provider']['base_method_source']).body[0]
        append('BasePermission',fn)
    if adapted and ref['repository']=='open-webui/open-webui':
        if len(nodes[0].args.defaults)!=1 or ast.unparse(nodes[0].args.defaults[0])!='Depends(get_current_user)':
            raise AdmissionError('current-user dependency declaration differs')
        # The complete original body is unchanged. Only function-entry default
        # initialization is outside this explicitly supplied-user profile.
        nodes[0].args.defaults=[]
    validation=deepcopy(nodes)
    if adapted:
        for n in validation:
            class Shape(ast.NodeTransformer):
                def visit_Lambda(self,x):
                    if ast.unparse(x)!='lambda acc, v: acc & v':raise AdmissionError('unknown source reducer')
                    return ast.copy_location(ast.Constant(None),x)
                def visit_keyword(self,x):
                    if x.arg is None:x.arg='owned_expansion'
                    return self.generic_visit(x)
            Shape().visit(n)
    tree=ast.fix_missing_locations(ast.Module(body=validation,type_ignores=[]))
    program=extract_effect_program(ast.unparse(tree).encode(),None,(),tuple(n.name for n in nodes))
    for node in nodes:
        program[node.name].body=deepcopy(node.body)
        program[node.name]._source_owner=node._source_owner
    return program,entry

class AdaptedInterpreter(EffectInterpreter):
    def __init__(self,program,data,ref,control=None):
        self.source_data,self.ref,self.control=data,ref,control
        self.frames=[]
        super().__init__(program,DataRecord('Unused',{}),{})
        self.bindings.update({
            'PermissionComponent':RecordType('Component',()),
            'super':Capability('fixed source single-base receiver',self.source_super),
            'HTTPException':Capability('selected HTTP error representation',self.http_error)})
        for name in ('And','Or','AllowAny','DenyAll','IsAuthenticated','IsSuperUser','IsTheSameUser'):
            self.bindings[name]=Capability('source component '+name,lambda *args,_name=name,**kwargs:self.component(_name,args,kwargs))
    def invoke(self,fn,args,kwargs):
        if not isinstance(fn,Closure):return super().invoke(fn,args,kwargs)
        p=fn.function.args;names=[a.arg for a in p.args]
        if p.posonlyargs or p.kwonlyargs or p.kw_defaults or len(args)>32 or len(kwargs)>8:
            raise AdmissionError('secondary signature outside the bounded positional/variadic interface')
        if len(args)>len(names) and p.vararg is None:raise AdmissionError('too many source arguments')
        bound=dict(zip(names,args));rest={}
        for k,v in kwargs.items():
            if k in bound:raise AdmissionError('duplicate source argument')
            if k in names:bound[k]=v
            elif p.kwarg is not None:rest[k]=v
            else:raise AdmissionError('unknown source argument')
        defaults=dict(zip(names[len(names)-len(p.defaults):],p.defaults))
        for name in names:
            if name not in bound:
                if name not in defaults or not isinstance(defaults[name],ast.Constant):
                    raise AdmissionError('source default requires a separate entry interface')
                bound[name]=defaults[name].value
        if p.vararg:bound[p.vararg.arg]=tuple(args[len(names):])
        if p.kwarg:bound[p.kwarg.arg]=rest
        if self.depth>=12:raise AdmissionError('secondary source depth exhausted','inconclusive')
        self.depth+=1;self.frames.append((getattr(fn.function,'_source_owner',''),bound.get('self')))
        key=fn.function.name;self.function_calls[key]=self.function_calls.get(key,0)+1
        try:
            value=self.statements(fn.function.body,{**fn.environment,**bound})
            return value.value if isinstance(value,Return) else None
        finally:self.depth-=1;self.frames.pop()
    def method(self,owner,name,receiver,args=(),kwargs=None):
        key=owner+'__'+name
        return self.run(key,[receiver,*args],{} if kwargs is None else kwargs)
    def component(self,name,args=(),kwargs=None):
        if kwargs:raise AdmissionError('component constructor keyword outside selected graph')
        value=DataRecord('Component',{'source_class':name},frozenset({'components'}))
        if name in ('And','Or'):
            self.method('PermissionOperator','__init__',value,args)
        elif args:raise AdmissionError('leaf component constructor has no supplied arguments')
        value.fields['check_permissions']=Capability('complete '+name+' consumer',
            lambda *a,**k:self.method(name,'check_permissions',value,a,k))
        return value
    def source_super(self):
        if not self.frames or self.frames[-1][0]!='IsSuperuserOrReadonly':
            raise AdmissionError('super receiver outside the single fixed framework base')
        receiver=self.frames[-1][1]
        return DataRecord('FixedBase',{'has_permission':Capability('complete fixed BasePermission body',
            lambda *a,**k:self.method('BasePermission','has_permission',receiver,a,k))})
    def http_error(self,*,status_code,detail):
        if type(status_code) is not int or status_code!=401 or detail!=self.source_data['webui_access_prohibited_literal']:
            raise AdmissionError('HTTP constructor outside the selected status/detail interface')
        fault=SliceFault('HTTPException',detail);fault.status_code=status_code
        return fault
    def value(self,node,env):
        if isinstance(node,ast.Compare) and len(node.ops)==1 and isinstance(node.ops[0],(ast.Eq,ast.NotEq)):
            left,right=self.value(node.left,env),self.value(node.comparators[0],env)
            if all(isinstance(v,DataRecord) and v.kind=='User' for v in (left,right)):
                ids=[v.fields.get('pk') for v in (left,right)]
                if any(type(v) is not int or v<=0 for v in ids):raise AdmissionError('nominal equality requires persisted same-class positive keys')
                result=ids[0]==ids[1]
                if self.control=='wrong_owner':result=not result
                return result if isinstance(node.ops[0],ast.Eq) else not result
            if type(left) is type(right) and type(left) in (str,bool,int):
                return left==right if isinstance(node.ops[0],ast.Eq) else left!=right
            raise AdmissionError('secondary equality outside the scalar/nominal identity interface')
        if isinstance(node,ast.BinOp) and isinstance(node.op,(ast.BitAnd,ast.BitOr)):
            left,right=self.value(node.left,env),self.value(node.right,env)
            if all(isinstance(v,DataRecord) and v.kind=='Component' for v in (left,right)):
                return self.method('PermissionComponent','__and__' if isinstance(node.op,ast.BitAnd) else '__or__',left,[right])
        if isinstance(node,ast.Call):
            if (isinstance(node.func,ast.Attribute) and node.func.attr=='format'
                    and isinstance(node.func.value,ast.Constant) and node.func.value.value=='{}_perms'
                    and len(node.args)==1 and not node.keywords):
                action=self.value(node.args[0],env)
                if action not in ('list','me','update'):raise AdmissionError('action outside fixed source declarations')
                return action+'_perms'
            fn=self.value(node.func,env);args=[];kwargs={}
            for n in node.args:
                args.extend(self.sequence(self.value(n.value,env))) if isinstance(n,ast.Starred) else args.append(self.value(n,env))
            for n in node.keywords:
                pairs=self.value(n.value,env) if n.arg is None else {n.arg:self.value(n.value,env)}
                if type(pairs) is not dict or any(type(k) is not str or k in kwargs for k in pairs):
                    raise AdmissionError('unknown or duplicate expanded source keywords')
                kwargs.update(pairs)
            if isinstance(fn,(Capability,Closure,RecordType)):return self.invoke(fn,args,kwargs)
            if isinstance(fn,Call):return self.call(fn,args,kwargs,env)
            raise AdmissionError('source call has no declared secondary capability')
        return super().value(node,env)
    def call(self,fn,args,kwargs,env):
        if fn.kind=='effect-builtin' and fn.value=='getattr' and len(args)==2 and not kwargs:
            record,key=args
            if not isinstance(record,DataRecord) or type(key) is not str or key not in record.fields:
                raise AdmissionError('action attribute is not an exact source declaration')
            return record.fields[key]
        if fn.kind=='effect-builtin' and fn.value=='isinstance' and len(args)==2 and type(args[1]) is tuple and not kwargs:
            types=args[1]
            if any(not isinstance(t,Call) or t.kind!='effect-builtin' or t.value not in ('list','tuple') for t in types):
                raise AdmissionError('source type tuple outside list/tuple guards')
            return any(type(args[0]) is {'list':list,'tuple':tuple}[t.value] for t in types)
        return super().call(fn,args,kwargs,env)

def person(value):return DataRecord('User',dict(value))
def setup(data,ref,context,machine,adapted):
    user=person(context['principal']);obj=None
    if 'target_pk' in context and context['target_pk'] is not None:
        obj=DataRecord('User',{'pk':context['target_pk']})
    if 'owner_pk' in context:
        owner=None if context['owner_pk'] is None else DataRecord('User',{'pk':context['owner_pk']})
        obj=DataRecord('Object',{'owner':owner})
    request=DataRecord('Request',{'user':user,'method':context.get('method','GET')})
    view=DataRecord('View',{});receiver=DataRecord('Receiver',{})
    machine.bindings.update(SAFE_METHODS=tuple(data['reference_input']['native_provider']['safe_methods']),
        status=DataRecord('Status',{'HTTP_401_UNAUTHORIZED':401}),
        ERROR_MESSAGES=DataRecord('Messages',{'ACCESS_PROHIBITED':data['webui_access_prohibited_literal']}))
    if ref['function']=='get_admin_user':
        if adapted and machine.control=='wrong_principal':user_arg=person(context['principal'])
        else:user_arg=user
        return [user_arg],user
    if ref['function']=='ResourcePermission.check_permissions':
        receiver=DataRecord('Resource',{},frozenset({'request','view'}))
        if adapted:
            text=module(data,'taigaio/taiga-back','taiga/users/permissions.py')
            cls=next(n for n in ast.parse(text).body if isinstance(n,ast.ClassDef) and n.name=='UserPermission')
            if [ast.unparse(b) for b in cls.bases]!=['TaigaResourcePermission']:raise AdmissionError('resource source base differs')
            declarations={n.targets[0].id:n.value for n in cls.body if isinstance(n,ast.Assign) and len(n.targets)==1 and isinstance(n.targets[0],ast.Name)}
            for key in ('enough_perms','global_perms','list_perms','me_perms','update_perms'):
                value=declarations[key]
                if isinstance(value,ast.Constant) and value.value is None:receiver.fields[key]=None
                elif isinstance(value,ast.Call) and isinstance(value.func,ast.Name) and not value.args and not value.keywords:
                    receiver.fields[key]=machine.component(value.func.id)
                else:raise AdmissionError('source action graph outside literal component declarations')
            if machine.control=='drop_super':receiver.fields['enough_perms']=None
            machine.method('ResourcePermission','__init__',receiver,[request,view])
        return [receiver,context['action'],obj],user
    if ref['function'].endswith('.has_permission'):return [receiver,request,view],user
    return [receiver,request,view,obj],user

def observe(data,ref,adapted,control=None):
    try:program,entry=prepare(data,ref,adapted)
    except AdmissionError as error:
        return dict(id=ref['id'],status='inconclusive',contexts=len(ref['contexts']),unknown_contexts=len(ref['contexts']),
            observations=[],reason=str(error),stage='source_admission')
    observations=[]
    for context in ref['contexts']:
        machine=AdaptedInterpreter(program,data,ref,control) if adapted else EffectInterpreter(program,DataRecord('Unused',{}),{})
        try:
            args,user=setup(data,ref,context,machine,adapted)
            result=machine.run(entry,args)
            if isinstance(result,DataRecord):actual=dict(kind='return_user',same_principal=result is user)
            elif result is None or type(result) in (bool,str,int):actual=dict(kind='return',value=result)
            else:raise AdmissionError('returned value outside selected observation contract')
            agrees=actual==context['expected']
        except SliceFault as fault:
            actual=dict(kind='source_exception',status=getattr(fault,'status_code',None),name=fault.name)
            wanted={**context['expected'],'name':'HTTPException'} if context['expected']['kind']=='source_exception' else context['expected']
            agrees=actual==wanted
        except AdmissionError as error:
            actual=dict(kind='unknown',reason=str(error));agrees=None
        observations.append(dict(id=context['id'],expected=context['expected'],observed=actual,agrees=agrees,
            function_calls=machine.function_calls))
    unknown=sum(o['agrees'] is None for o in observations)
    differences=sum(o['agrees'] is False for o in observations)
    props=[dict(id=o['id'],expected=True,observed=o['agrees']) for o in observations if o['agrees'] is not None]
    return dict(id=ref['id'],contexts=len(observations),unknown_contexts=unknown,differences=differences,
        status='inconclusive' if unknown else 'contract_mismatch' if differences else 'contract_agreement',
        observations=observations,diagnosis=None if unknown else diagnose_observations(props))

def run(adapted=False,control=None):
    data=load();rows=[observe(data,r,adapted,control) for r in data['reference_input']['references']]
    return dict(mode='secondary_source_adaptation' if adapted else 'frozen_method_primary',
        selected_projects=12,acquired_projects=sum(bool(r.get('acquired')) for r in data['projects']),
        reference_projects=3,reference_boundaries=len(rows),normal_contexts=sum(r['contexts'] for r in rows),
        complete_boundaries=sum(r['status']=='contract_agreement' for r in rows),
        mismatching_boundaries=sum(r['status']=='contract_mismatch' for r in rows),
        unknown_contexts=sum(r['unknown_contexts'] for r in rows),
        unresolved_reference_interfaces=sum(not r['has_reference'] for r in data['reference_input']['candidate_interfaces']),
        candidate_interfaces=len(data['reference_input']['candidate_interfaces']),rows=rows,
        original_application_modules_executed=False,independent_human_gold_claimed=False,
        secondary_is_not_another_blind_transfer=adapted,whole_application_verified=False,new_vulnerability_findings=0,
        model_requests=0)

def main():
    p=argparse.ArgumentParser();p.add_argument('--secondary',action='store_true');p.add_argument('--check',action='store_true');p.add_argument('--control',choices=['wrong_owner','drop_super','wrong_principal']);a=p.parse_args()
    value=run(a.secondary,a.control)
    if a.control:
        if not a.secondary or not any(o.get('agrees') is False for r in value['rows'] for o in r['observations']):
            raise ValueError('owned observation fault was not detected')
        print(json.dumps(dict(control=a.control,observed_difference_detected=True)));return
    path=ROOT/('secondary.json.gz' if a.secondary else 'primary.json.gz')
    if a.check:
        if json.loads(gzip.decompress(path.read_bytes()))!=value:raise ValueError('current prospective result differs')
    else:
        if path.exists():raise ValueError('preserve the first observed result; use --check')
        path.write_bytes(gzip.compress(json.dumps(value,sort_keys=True).encode(),mtime=0))
    print(json.dumps({k:v for k,v in value.items() if k!='rows'},indent=2))

if __name__=='__main__':main()
