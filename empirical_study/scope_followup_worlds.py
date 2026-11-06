"""Reviewed normal paths only. All databases are owned, isolated SQLite scratch."""
import ast,base64,builtins,hashlib,hmac,json,types
from collections import deque
from datetime import datetime,timedelta,timezone
from types import SimpleNamespace as NS
from uuid import UUID
from delegated_runtime import install,finish,parse_source
from remaining_worlds import World,Record,AuthorizationError

_DJ=None
def django_models():
    global _DJ
    if _DJ:return _DJ
    import django
    from django.conf import settings
    if not settings.configured:
        settings.configure(SECRET_KEY='owned-normal-fixture-only',USE_TZ=True,
            DATABASES={'default':{'ENGINE':'django.db.backends.sqlite3','NAME':':memory:'}},
            INSTALLED_APPS=['django.contrib.contenttypes','django.contrib.auth','rest_framework.authtoken'],
            AUTHENTICATION_BACKENDS=['django.contrib.auth.backends.ModelBackend'],LOGGING_CONFIG=None)
        django.setup()
    from django.db import models,connection
    from django.contrib.auth.models import User,Group,Permission
    from django.contrib.contenttypes.models import ContentType
    from rest_framework.authtoken.models import Token
    class Project(models.Model):
        api_key=models.CharField(max_length=100)
        api_key_readonly=models.CharField(max_length=100)
        class Meta:app_label='study'
    class Organizer(models.Model):
        name=models.CharField(max_length=80)
        class Meta:app_label='study'
    class Event(models.Model):
        name=models.CharField(max_length=80)
        class Meta:app_label='study'
    class Child(models.Model):
        name=models.CharField(max_length=80)
        class Meta:app_label='core'
    class Settings(models.Model):
        user=models.OneToOneField(User,on_delete=models.CASCADE,related_name='settings')
        access_expires=models.DateTimeField(null=True)
        class Meta:app_label='study'
    with connection.schema_editor() as editor:
        for cls in (ContentType,Permission,Group,User,Token,Project,Organizer,Event,Child,Settings):editor.create_model(cls)
    _DJ=NS(django=django,settings=settings,models=models,connection=connection,User=User,Permission=Permission,ContentType=ContentType,Token=Token,Project=Project,Organizer=Organizer,Event=Event,Child=Child,Settings=Settings)
    return _DJ

class FollowupWorld(World):
    def __init__(self,case,sample):
        super().__init__(case,sample);self.builtins.update(bytes=bytes,type=type)
    def pack(self,v):
        if hasattr(v,'_meta') and hasattr(v,'pk'):return dict(model=v._meta.label,pk=v.pk)
        return super().pack(v)
    def setup_R03(self):
        d=django_models();c=self.c
        d.Event.objects.all().delete();d.Organizer.objects.all().delete()
        org=d.Organizer.objects.create(pk=1,name='stored organizer')
        # Separate objects from one database identity; non-key fields differ.
        argument_org=d.Organizer(pk=1 if c['same_organizer'] else 2,name='caller context')
        d.Event.objects.create(pk=10,name='selected event')
        ev=d.Event(pk=10,name='different in-memory label')
        device=self.record('device',all_events=c['all_events'],organizer=org,
            limit_events=NS(all=lambda:d.Event.objects.filter(pk=10) if c['selected'] else d.Event.objects.none()))
        self.method(device,'_event_permission_set','device_permissions')
        self.entry_args={'device_has_event_permission':dict(self=device,organizer=argument_org,event=ev,perm_name=c['required'],request=None,session_key=None)}
    def setup_R04(self):
        d=django_models();c=self.c;d.Project.objects.all().delete()
        keys=dict(plain_write='w'*32,plain_read='r'*32,stored_write='hcw_'+'a'*28,stored_read='hcr_'+'b'*28,absent='')
        key=keys[c['key_kind']]
        def stored(k):return k[4:12]+'.'+hmac.digest(d.settings.SECRET_KEY.encode(),k.encode(),'sha256').hex()
        if c['key_kind'].startswith('stored'):
            d.Project.objects.create(pk=1,api_key=stored(keys['stored_write']),api_key_readonly=stored(keys['stored_read']))
        else:d.Project.objects.create(pk=1,api_key=keys['plain_write'],api_key_readonly=keys['plain_read'])
        from django.db.models import Q
        from django.http import JsonResponse
        self.dj=d;self.globals.update(Project=d.Project,Q=Q,hmac=hmac,settings=d.settings,json=json,JsonResponse=JsonResponse)
        request=self.record('request',method='POST' if c['body_key'] or not c['read'] else 'GET',
            body=json.dumps({'api_key':key}).encode() if c['body_key'] else b'',
            headers={} if c['body_key'] else {'X-Api-Key':key},path_info='/api/v3/checks/')
        self.request=request;self.tracked['request']=request
        def consumer(r,*args,**kw):
            self.trace.append(dict(consumer='owned-read' if c['read'] else 'owned-write',project=r.project.pk,readonly=r.readonly,version=r.v))
            # Benign scratch effect witnesses invocation,not original business logic.
            if not c['read']:
                with d.connection.cursor() as cursor:
                    cursor.execute('CREATE TABLE IF NOT EXISTS owned_effects (n INTEGER)')
                    cursor.execute('DELETE FROM owned_effects');cursor.execute('INSERT INTO owned_effects VALUES (1)')
            return JsonResponse({'project':r.project.pk,'readonly':r.readonly,'version':r.v})
        self.consumer=consumer
    def setup_R05(self):
        d=django_models();c=self.c;self.dj=d
        d.Token.objects.all().delete();d.Settings.objects.all().delete();d.User.objects.all().delete();d.Permission.objects.all().delete();d.ContentType.objects.all().delete()
        user=d.User.objects.create(username='normal-user',is_active=True)
        ct=d.ContentType.objects.create(app_label='core',model='child')
        if c['granted'] and c['permission']:
            perm=d.Permission.objects.create(content_type=ct,codename=c['permission']+'_child',name='normal permission')
            user.user_permissions.add(perm)
        token=d.Token.objects.create(key='c'*40,user=user)
        now=datetime(2026,11,5,12,tzinfo=timezone.utc)
        if not c.get('settings_absent'):d.Settings.objects.create(user=user,access_expires=now-timedelta(seconds=1) if c['expired'] else None)
        self.user=user;self.token=token
        from rest_framework import authentication,exceptions
        from rest_framework.permissions import DjangoModelPermissions
        self.authentication=authentication;self.exceptions=exceptions;self.permission_base=DjangoModelPermissions
        self.globals.update(Settings=d.Settings,timezone=NS(now=lambda:now))
    def setup_R11(self):
        c=self.c;now=datetime(2026,11,5,12)
        class Clock:
            @staticmethod
            def now():return now
        def stored(key):
            return c['roles'] if key.startswith('user_roles:') else c['parents'].get(key.split(':',1)[1],[])
        storage=NS(smembers=self.event('storage.rows',stored,True));enforcer=self.engine()
        cache={'editor':{'editor','reader'}} if c['cached'] else {}
        expiry={'editor':now+timedelta(seconds=60)} if c['cached'] else {}
        self.rbac=self.record('rbac',storage=storage,_inheritance_cache=cache,_cache_expiry=expiry,_cache_ttl=timedelta(seconds=60))
        self.method(self.rbac,'_is_cache_valid','cache_valid');self.method(self.rbac,'get_all_inherited_roles','inherited_roles')
        self.globals.update(datetime=Clock,deque=deque,RoleHierarchyError=ValueError,get_rbac_manager=lambda:self.rbac,
            run_in_thread=self.event('thread-call',lambda fn,*a:fn(*a),True),create_authorization_error=lambda msg:AuthorizationError(msg))
        self.entry_args={'check_permission':dict(required_permission=c['required'],user=self.record('user',username='alice'),storage=storage,enforcer=enforcer)}
    def setup_R24(self):
        owner=self.c['owner'];self.user=self.record('user')
        if owner!='Anonymous':self.property(self.user,'is_active',owner+'_active')
    def setup_R13(self):
        World.setup_R13(self)
        c=self.c
        header=base64.b64encode(b'{"alg":"HS256","typ":"JWT"}').decode().rstrip('=')
        payload=dict(sub='owned-user-1',preferred_username='alice',email='fixture@example.invalid',scopes=c['token_scopes'],roles=c['roles'],groups=[])
        encoded=base64.b64encode(json.dumps(payload,separators=(',',':')).encode()).decode().rstrip('=')
        signing=(header+'.'+encoded).encode()
        signature=base64.b64encode(hmac.digest(b'owned-normal-token-key',signing,'sha256')).decode().rstrip('=')
        self.entry_args['authenticate_jwt']['token']=(header+'.'+encoded+'.'+signature) if c['valid_token'] else 'normal-absent-token'
        self.globals['types']=NS(TokenData=lambda **kw:self.record('token_data',**kw))
    def setup_R19(self):
        d=django_models();self.dj=d;c=self.c
        d.Token.objects.all().delete();d.Settings.objects.all().delete();d.User.objects.all().delete();d.Permission.objects.all().delete();d.ContentType.objects.all().delete()
        if c['absent']:user=None
        elif not c['authenticated']:
            from django.contrib.auth.models import AnonymousUser
            user=AnonymousUser()
        else:
            user=d.User.objects.create(username='statistics-user',is_active=c['active'],is_superuser=c['superuser'])
            ct=d.ContentType.objects.create(app_label='paperless',model='application')
            for permission in c['permissions']:
                app,name=permission.split('.',1)
                if app!='paperless':raise ValueError('permission input domain')
                user.user_permissions.add(d.Permission.objects.create(content_type=ct,codename=name,name=name))
        self.auth_user=user
        self.entry_args={'has_global_statistics_permission':dict(user=user)}
    def setup_R26(self):
        self.user=self.record('entry',username=self.c['username'],password=self.c['password'])
        self.property(self.user,'has_credentials',self.c['owner']+'_credentials')
    def setup_R29(self):
        from sqlalchemy import Column,String,Integer,ForeignKey,Table,Uuid,create_engine,select,and_
        from sqlalchemy.orm import declarative_base,relationship,Session,selectinload
        Base=declarative_base()
        link=Table('role_permissions',Base.metadata,Column('role_id',Uuid,ForeignKey('roles.id')),Column('permission_id',Uuid,ForeignKey('permissions.id')))
        class Role(Base):
            __tablename__='roles';id=Column(Uuid,primary_key=True);permission_level=Column(Integer)
            permissions=relationship('Permission',secondary=link)
        class Permission(Base):
            __tablename__='permissions';id=Column(Uuid,primary_key=True);name=Column(String);resource=Column(String);action=Column(String)
        class UserRole(Base):
            __tablename__='user_roles';user_id=Column(Uuid,primary_key=True);role_id=Column(Uuid,ForeignKey('roles.id'),primary_key=True);role=relationship(Role)
        class AgentRole(Base):
            __tablename__='agent_roles';id=Column(Uuid,primary_key=True);agent_id=Column(Uuid);role_id=Column(Uuid);access_type=Column(String)
        class WorkflowRole(Base):
            __tablename__='workflow_roles';id=Column(Uuid,primary_key=True);workflow_id=Column(Uuid);role_id=Column(Uuid);access_type=Column(String)
        engine=create_engine('sqlite://');Base.metadata.create_all(engine);session=Session(engine);c=self.c
        uid,rid,resid,other=[UUID(int=n) for n in (1,2,3,4)]
        role=Role(id=rid,permission_level=c['level'])
        if c['global_permission']:role.permissions=[Permission(id=UUID(int=5),name=c['resource_type']+'.'+c['action'],resource=c['resource_type'],action=c['action'])]
        session.add(role);session.add(UserRole(user_id=uid,role_id=rid))
        if c['assignment']:
            cls=AgentRole if c['resource_type']=='agent' else WorkflowRole;key='agent_id' if cls is AgentRole else 'workflow_id'
            session.add(cls(id=UUID(int=6),role_id=rid,access_type='view' if c['assignment']=='other_resource' else c['assignment'],**{key:other if c['assignment']=='other_resource' else resid}))
        session.commit();self.session=session;self.engine_object=engine
        async def execute(query):
            compiled=query.compile(engine)
            self.trace.append(dict(provider='SQLite.execute',statement=str(compiled),parameters={k:str(v) for k,v in compiled.params.items()}))
            return session.execute(query)
        service=self.record('permission-service',session=NS(execute=execute))
        for r in self.case['functions']:self.method(service,r['binding'],r['binding'])
        self.globals.update(select=select,and_=and_,selectinload=selectinload,Role=Role,Permission=Permission,UserRole=UserRole,AgentRole=AgentRole,WorkflowRole=WorkflowRole)
        self.entry_args={'has_permission':dict(self=service,user=self.record('user',id=uid,is_superuser=c['special'],is_system_admin=False),resource_type=c['resource_type'],action=c['action'],resource_id=resid)}
    def setup_R31(self):
        import casbin
        model=casbin.Model();model.load_model_from_text(self.case['model']['text']);e=casbin.Enforcer(model)
        for kind,*values in self.case['policies']:
            if kind=='p':e.add_policy(*values)
            elif kind=='g':e.add_grouping_policy(*values)
            else:e.add_named_grouping_policy(kind,*values)
        self.handler=self.record('handler',enforcer=NS(enforce=self.event('casbin.enforce',e.enforce),get_roles_for_user=self.event('casbin.roles',e.get_roles_for_user)))
        self.globals['_logger']=NS(error=lambda *a:None)
    def bind_source_methods(self,mode):
        # Do not invoke old project-specific post-install registry assumptions.
        for obj,name,binding in self.source_methods:setattr(obj,name,lambda *a,_o=obj,_b=binding,**kw:self.globals[_b](_o,*a,**kw))
        for obj,name,binding in self.properties:vars(obj).setdefault('_properties',{})[name]=lambda x,_b=binding:finish(self.globals[_b](x))
        if self.case['project']=='R04':
            g=self.globals;cls=self.dj.Project
            cls.compare_api_key=lambda obj,key:finish(g['compare_api_key'](obj,key))
            manager=cls.objects
            manager.for_api_key=lambda key,**kw:finish(g['for_api_key'](manager,key,**kw))
        if self.case['project']=='R05':
            self.dj.Settings.access_expired=property(lambda obj:finish(self.globals['settings_access_expired'](obj)))
        if self.case['project']=='R13':
            # The decoder module imports stdlib base64,whereas the caller
            # imports the project base64 module. Do not merge their globals.
            decoder=next(r for r in self.case['functions'] if r['binding']=='payload_decode')
            sub=NS(globals={'base64':base64,'json':json},builtins=self.builtins,allowed_imports={},native_environments=[],
                native_builtins=lambda:self.native_builtins(),bind_source_methods=lambda mode:None)
            local=install([decoder],sub,mode)
            self.globals['payload_decode']=local['payload_decode']
            self.globals['base64']=NS(decode=local['payload_decode'])
    def invoke(self):
        p=self.case['project'];g=self.globals;c=self.c
        if p=='R04':
            fn=g['authorize_read' if c['read'] else 'authorize'](self.consumer);response=finish(fn(self.request))
            return dict(status_code=response.status_code,body=json.loads(response.content))
        if p=='R05':
            # Full original method is compiled in a class so zero-arg super()
            # receives its correct __class__ cell. No whole target module runs.
            method=parse_source(self.case['functions'][0]['source']);method.decorator_list=[]
            cls=ast.ClassDef(name='SourceTokenAuthentication',bases=[ast.Name(id='NativeTokenBase',ctx=ast.Load())],keywords=[],body=[method],decorator_list=[])
            env=dict(NativeTokenBase=self.authentication.TokenAuthentication,access_expired=lambda user:finish(g['access_expired'](user)),exceptions=self.exceptions,_=lambda x:x,__name__='owned_source_capsule')
            exec(compile(ast.fix_missing_locations(ast.Module(body=[cls],type_ignores=[])),'<source-token-class>','exec'),env)
            if c['authenticated']:user,token=env['SourceTokenAuthentication']().authenticate_credentials(self.token.key)
            else:
                from django.contrib.auth.models import AnonymousUser
                user=AnonymousUser()
            policy=type('SourcePolicy',(self.permission_base,),{'perms_map':self.case['policy_map']})()
            return policy.has_permission(NS(user=user,method=c['method']),NS(queryset=self.dj.Child.objects.all()))
        if p=='R24':
            return dict(authenticated=finish(g[c['owner']+'_authenticated'](self.user)),active=finish(g[c['owner']+'_active'](self.user)) if c['owner']!='Anonymous' else None)
        if p=='R26':return finish(g[c['owner']+'_config'](self.user))
        if p=='R19':
            def observed(execute,sql,params,many,context):
                self.trace.append(dict(provider='Django.permission-query',statement=sql,parameters=[str(x) for x in (params or [])]))
                return execute(sql,params,many,context)
            with self.dj.connection.execute_wrapper(observed):return super().invoke()
        if p=='R31':
            return dict(roles=finish(g['check_permission'](self.handler,c['subject'])),admin=finish(g['check_admin_role'](self.handler,c['subject'])),allowed=finish(g['verify_authorization'](self.handler,c['subject'],c['object'],c['action'])))
        return super().invoke()
    def snapshot(self):
        if self.case['project']=='R11':
            return dict(cached_roles={k:sorted(v) for k,v in self.rbac._inheritance_cache.items()},cache_expiry={k:v.isoformat() for k,v in self.rbac._cache_expiry.items()})
        if self.case['project']=='R19':
            u=self.auth_user
            if u is None:return dict(user=None)
            return dict(user=dict(pk=u.pk,active=u.is_active,authenticated=u.is_authenticated,superuser=u.is_superuser,
                permission_caches={k:sorted(getattr(u,k)) for k in ('_perm_cache','_user_perm_cache','_group_perm_cache') if hasattr(u,k)}))
        return super().snapshot()
