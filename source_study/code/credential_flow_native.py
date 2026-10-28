"""Owned normal credential/project rows with actual pinned Django primitives.

Source control flow remains data IR;no target modules,services,requests or tests
execute. Serializer content and actual write actions are explicit boundaries.
"""
from collections import Counter
import hmac
import json
import uuid
from credential_flow_ir import Machine,Record,Ref,Unsupported,QueryMiss,NotFound
from credential_flow_contexts import SECRET,token,stored,check_code,expected


def initialize():
    from django.conf import settings
    settings.configure(SECRET_KEY=SECRET,USE_TZ=False,INSTALLED_APPS=[],
        DATABASES={'default':{'ENGINE':'django.db.backends.sqlite3','NAME':':memory:'}},DEFAULT_AUTO_FIELD='django.db.models.AutoField')
    import django
    django.setup()
    from django.db import models,connection
    def model(name,fields):
        meta=type('Meta',(),dict(app_label='owned_credential',db_table='owned_credential_'+name.lower()))
        return type(name,(models.Model,),{'__module__':__name__,'Meta':meta,**fields})
    Project=model('Project',dict(api_key=models.CharField(max_length=128),api_key_readonly=models.CharField(max_length=128)))
    Check=model('Check',dict(code=models.UUIDField(unique=True),project=models.ForeignKey(Project,on_delete=models.CASCADE)))
    with connection.schema_editor() as schema:
        schema.create_model(Project);schema.create_model(Check)
    return Record('Database',dict(Project=Project,Check=Check,connection=connection))


class Native:
    def __init__(self,db,secret=None):
        self.db=db.fields;self.secret=secret;self.mac_calls=0;self.resolved=None;self.serializers=[];self.source_returns=[]

    def project(self,obj):
        return Record('Project',dict(id=obj.pk,api_key=obj.api_key,api_key_readonly=obj.api_key_readonly))

    def attribute(self,obj,name):
        if obj.kind=='ProjectManager' and name in ('filter','get'):return Ref('ProjectQuery.'+name)
        if obj.kind=='Check' and name=='to_dict':return Ref('Check.to_dict',obj)
        raise Unsupported('unbound typed primitive attribute: '+obj.kind+'.'+name)

    def query_or(self,left,right):
        from django.db.models import Q
        if not isinstance(left,Q) or not isinstance(right,Q):raise Unsupported('OR needs source-bound Q primitives')
        return left|right

    def on_source_return(self,name,value,env):
        if name=='ProjectManager.for_api_key':
            self.resolved=value
            self.source_returns.append(dict(function=name,project=None if value is None else value.fields['id']))

    def call(self,ref,args,kwargs):
        name=ref.name
        if name=='len' and len(args)==1 and not kwargs and isinstance(args[0],(str,bytes,tuple,dict)):return len(args[0])
        if name=='str' and len(args)==1 and not kwargs and type(args[0]) in (str,int,bool):return str(args[0])
        if name=='isinstance' and len(args)==2 and not kwargs and args[1] is dict:return isinstance(args[0],dict)
        if name=='token_urlsafe' and args==[21] and not kwargs:
            if self.secret is None or len(self.secret)!=28 or not self.secret.isalnum():raise Unsupported('normal fixed RNG contract absent')
            return self.secret
        if name=='hmac.digest' and len(args)==3 and not kwargs and type(args[0]) is bytes and type(args[1]) is bytes and args[2]=='sha256':
            self.mac_calls+=1;return hmac.digest(*args)
        if name=='hmac.compare_digest' and len(args)==2 and not kwargs and all(type(a) is str for a in args):return hmac.compare_digest(*args)
        if name=='json.loads' and len(args)==1 and not kwargs and type(args[0]) is str:return json.loads(args[0])
        if name.startswith('scalar.'):
            obj=ref.receiver;method=name.partition('.')[2]
            if method=='startswith' and isinstance(obj,str) and len(args)==1 and isinstance(args[0],str) and not kwargs:return obj.startswith(args[0])
            if method=='split' and isinstance(obj,str) and len(args)==1 and isinstance(args[0],str) and set(kwargs)<={'maxsplit'}:return obj.split(*args,**kwargs)
            if method=='encode' and type(obj) is str and not args and not kwargs:return obj.encode()
            if method=='decode' and type(obj) is bytes and not args and not kwargs:return obj.decode()
            if method=='hex' and type(obj) is bytes and not args and not kwargs:return obj.hex()
        if name=='Q':
            from django.db.models import Q
            if args or not kwargs or not set(kwargs)<={'api_key','api_key_readonly'}:raise Unsupported('unreviewed Q signature')
            return Q(**kwargs)
        if name in ('ProjectQuery.filter','ProjectQuery.get'):
            from django.db.models import Q
            if any(not isinstance(a,Q) for a in args) or not set(kwargs)<={'api_key','api_key_readonly','api_key__startswith','api_key_readonly__startswith'}:
                raise Unsupported('unreviewed Project query')
            if name.endswith('filter'):return [self.project(v) for v in self.db['Project'].objects.filter(*args,**kwargs)]
            try:return self.project(self.db['Project'].objects.get(*args,**kwargs))
            except self.db['Project'].DoesNotExist:raise QueryMiss('owned absent project') from None
        if name=='get_object_or_404':
            from django.shortcuts import get_object_or_404
            from django.http import Http404
            if args!=[Ref('CheckModel')] or set(kwargs)!={'code'}:raise Unsupported('unbound business lookup')
            try:obj=get_object_or_404(self.db['Check'],**kwargs)
            except Http404:raise NotFound('owned absent object') from None
            return Record('Check',dict(id=obj.pk,project_id=obj.project_id,code=str(obj.code)))
        if name=='Check.to_dict':
            if args or set(kwargs)!={'readonly','v'} or ref.receiver.kind!='Check':raise Unsupported('unbound serializer transfer')
            # Intentional consumer boundary,not execution/recreation of the
            # application's complete to_dict or hidden-field filtering.
            data=dict(check_id=ref.receiver.fields['id'],project_id=ref.receiver.fields['project_id'],**kwargs)
            self.serializers.append(data);return dict(owned_serializer_boundary=data)
        if name=='write_boundary':
            if len(args)!=1 or kwargs or not isinstance(args[0],Record):raise Unsupported('write-boundary request identity differs')
            from django.http import JsonResponse
            return JsonResponse({'owned_authorization_boundary':True})
        if name=='JsonResponse':
            if len(args)!=1 or type(args[0]) is not dict or not set(kwargs)<={'status'}:raise Unsupported('unreviewed response signature')
            from django.http import JsonResponse
            return JsonResponse(args[0],**kwargs)
        if name=='HttpResponseForbidden' and not args and not kwargs:
            from django.http import HttpResponseForbidden
            return HttpResponseForbidden()
        raise Unsupported('closed native primitive unavailable: '+name)


def globals_for(mode):
    manager=Record('ProjectManager',{})
    project=Record('Namespace',dict(objects=manager,DoesNotExist=QueryMiss))
    return dict(Project=project,Check=Ref('CheckModel'),settings=Record('Namespace',dict(SECRET_KEY=SECRET)),
        hmac=Record('Namespace',dict(digest=Ref('hmac.digest'),compare_digest=Ref('hmac.compare_digest'))),
        json=Record('Namespace',dict(loads=Ref('json.loads'))),dict=dict,ValueError=ValueError,
        len=Ref('len'),str=Ref('str'),isinstance=Ref('isinstance'),token_urlsafe=Ref('token_urlsafe'),Q=Ref('Q'),
        error=Ref('error'),_get_api_version=Ref('_get_api_version'),get_object_or_404=Ref('get_object_or_404'),
        HttpResponseForbidden=Ref('HttpResponseForbidden'),JsonResponse=Ref('JsonResponse'),
        f=Ref('get_check' if mode=='read' else 'write_boundary'))


def prepare_rows(db,binding,profile):
    records=[]
    for project in (1,2,3):
        holder=Record('Project',dict(id=project,api_key='',api_key_readonly=''))
        for kind,field,method in [('w','api_key','set_api_key'),('r','api_key_readonly','set_api_key_readonly')]:
            key=token(profile,project,kind)
            if profile=='stored_mac':
                native=Native(db,secret=key[4:]);machine=Machine(binding['programs'],globals_for('read'),native)
                got=machine.call(Ref('Project.'+method,holder),[])
                if got!=key or holder.fields[field]!=stored(key):raise ValueError('source producer and independent MAC store disagree')
                records.append(dict(project=project,kind=kind,source_method=method,returned_key_matches=True,stored_value_matches=True,
                    native_mac_calls=native.mac_calls,entropy_contract='fixed owned alphanumeric28chars for token_urlsafe(21);not RNG/security-quality validation'))
            else:holder.fields[field]=key
        db.fields['Project'].objects.create(id=project,api_key=holder.fields['api_key'],api_key_readonly=holder.fields['api_key_readonly'])
        db.fields['Check'].objects.create(id=project,project_id=project,code=uuid.UUID(check_code(project)))
    return records


def measure(binding,inputs):
    db=initialize();rows=[];totals=Counter();producers=[];profile=None
    for case in inputs:
        if case['profile']!=profile:
            db.fields['Check'].objects.all().delete();db.fields['Project'].objects.all().delete()
            producers+=prepare_rows(db,binding,case['profile']);profile=case['profile']
        request=Record('Request',dict(method=case['method'],headers=dict(case['request']['headers']),
            body=bytes.fromhex(case['request']['body_hex']),path_info=case['request']['path_info']))
        native=Native(db);machine=Machine(binding['programs'],globals_for(case['mode']),native);sql=[]
        def capture(execute,statement,params,many,context):
            if not statement.lstrip().upper().startswith('SELECT'):raise ValueError('credential evaluation attempted a write')
            sql.append(dict(statement=statement,parameters=list(params or ())))
            return execute(statement,params,many,context)
        with db.fields['connection'].execute_wrapper(capture):
            try:
                args=[request,case['code']] if case['mode']=='read' else [request]
                response=machine.call(Ref('authorize_read.wrapper' if case['mode']=='read' else 'authorize.wrapper'),args)
                status=response.status_code
            except NotFound:status=404
        current=request.fields.get('project');fields=dict(status=status,project=None if current is None else current.fields['id'],
            readonly=request.fields.get('readonly'),version=request.fields.get('v'),
            consumer='serializer_boundary' if native.serializers else 'authorization_boundary_only' if case['mode']=='write' and status==200 else None)
        wanted=expected(case);identity=current is not None and current is native.resolved
        if current is not None and not identity:raise ValueError('source principal/project object handoff lost identity')
        if native.serializers and (len(native.serializers)!=1 or native.serializers[0]['readonly']!=fields['readonly'] or native.serializers[0]['v']!=fields['version']):
            raise ValueError('serializer readonly/version transfer differs')
        rows.append(dict(id=case['id'],observed=fields,expected=wanted,agrees=fields==wanted,sql=sql,
            exact_resolved_project_identity_transferred=identity,serializer_transfers=native.serializers,
            source_manager_returns=native.source_returns,native_mac_calls=native.mac_calls,IR_steps=machine.steps))
        totals['contexts']+=1;totals['actual_SELECTs']+=len(sql);totals['native_mac_calls']+=native.mac_calls
        totals['exact_project_identity_transfers']+=identity;totals['serializer_transfers']+=len(native.serializers)
        totals['differences']+=fields!=wanted;totals['status_'+str(status)]+=1
    return dict(rows=rows,producer_records=producers,totals=dict(totals),
        original_application_modules_or_tests_executed=False,original_serializer_or_write_action_executed=False,
        original_deployment_or_randomness_security_certified=False)
