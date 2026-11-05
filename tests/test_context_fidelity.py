"""Source/context correspondence regressions on owned fixtures,not new projects."""
import copy,gzip,hashlib,json,subprocess,sys,tempfile,unittest
from pathlib import Path
ART=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ART))
from reference_completion.replay import load,execute,run
from reference_completion.contracts import reference
class ContextFidelityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):cls.p=load(ART/'reference_completion/inputs.json.gz')
    def check(self,q,i):
        c=next(c for c in self.p['references']['contracts'] if c['function']==q);a,b,d,e=reference(c,i)
        r=execute(self.p['sources'][c['source_key']],c,dict(inputs=i,expected=a,state=b,call_counts=d,call_order=e))
        self.assertEqual(r['status'],'agree',repr(r));return r
    def test_empty_cached_groups_are_not_a_cache_miss(self):
        for q in ('CustomIsGuest.has_permission','CustomIsUser.has_permission','CustomIsAdmin.has_permission'):
            r=self.check(q,{'groups':['admin'],'cached_groups':[]});self.assertIs(r['outcomes'][0]['value'],False)
            self.assertNotIn('active_spaces',[e['call'] for e in r['events']]);self.assertEqual(r['state']['cache']['GROUP_CACHE_1_1'],[])
    def test_none_cache_refreshes_but_cached_rows_are_authoritative(self):
        self.assertIs(self.check('CustomIsAdmin.has_permission',{'groups':['admin'],'cached_groups':None})['outcomes'][0]['value'],True)
        self.assertIs(self.check('CustomIsAdmin.has_permission',{'groups':[],'cached_groups':['admin']})['outcomes'][0]['value'],True)
    def test_zero_or_invalid_repetitions_cannot_pass_without_running(self):
        c=next(c for c in self.p['references']['contracts'] if c['function']=='IsReadOnlyDRF.has_permission')
        for repeat in (0,-1,True,False,33,'2',1.0):
            i={'repeat':repeat};a,b,d,e=reference(c,i);r=execute(self.p['sources'][c['source_key']],c,dict(inputs=i,expected=a,state=b,call_counts=d,call_order=e))
            self.assertEqual(r['status'],'unknown')
        r=self.check(c['function'],{'repeat':2});self.assertEqual(len(r['outcomes']),2);self.assertEqual(r['source_calls']['IsReadOnlyDRF__has_permission'],2)
    def test_duplicate_context_ids_are_not_new_evidence(self):
        p=copy.deepcopy(self.p);p['references']['contracts']=p['references']['contracts'][:1];c=p['references']['contracts'][0];c['contexts']=[c['contexts'][0],c['contexts'][0]]
        with self.assertRaises(ValueError):run(p)
    def test_cli_rejects_zero_execution_context(self):
        p=copy.deepcopy(self.p);c=next(c for c in p['references']['contracts'] if c['function']=='IsReadOnlyDRF.has_permission');c['contexts']=c['contexts'][:1];c['contexts'][0]['inputs']['repeat']=0;p['references']['contracts']=[c]
        with tempfile.TemporaryDirectory() as d:
            path=Path(d)/'inputs.json.gz';path.write_bytes(gzip.compress(json.dumps(p).encode()))
            r=subprocess.run([sys.executable,'-B',str(ART/'reference_completion/replay.py'),'--inputs',str(path)],capture_output=True,text=True,encoding='utf-8',timeout=30)
        self.assertEqual(r.returncode,1);self.assertEqual(json.loads(r.stdout)['unknown'],1);self.assertEqual(json.loads(r.stdout)['concrete_agree'],0)
    def test_unknown_user_does_not_become_an_existing_second_user(self):
        for bearer in (True,False):
            r=self.check('get_current_user',{'bearer':bearer,'cookies':{'token':'cookie-normal'},'claims':{'id':'missing'}})
            self.assertEqual(r['outcomes'][0],{'kind':'error','name':'HTTPException','status':401});self.assertEqual(r['state']['scheduled_active'],[])
    def test_claim_identity_not_token_fixture_name_selects_user(self):
        for uid,name in (('u1','user'),('u2','other')):
            r=self.check('get_current_user',{'claims':{'id':uid}});self.assertEqual(r['outcomes'][0]['value'],{'ref':name});self.assertEqual(r['state']['scheduled_active'],[uid])
        self.assertEqual(self.check('get_current_user',{'claims':None})['outcomes'][0]['status'],401)
    def test_authentication_record_absence_activity_and_errors_use_source_wrapper(self):
        for i,status in (({'auth_exists':False},401),({'auth_active':False},401),({'auth_lookup_error':'SQLAlchemyError'},503),({'auth_lookup_error':'ValidationError'},503)):
            r=self.check('get_current_user',dict(i,cookies={'token':'cookie-normal'}));self.assertEqual(r['outcomes'][0]['status'],status)
            self.assertEqual(r['source_calls']['get_auth'],1);self.assertEqual(r['state']['deleted_cookies'],['token']);self.assertEqual(r['state']['scheduled_active'],[])
    def test_missing_mfa_record_does_not_inherit_a_secret(self):
        r=self.check('get_current_user',{'mfa_enabled':True,'mfa_secret':True,'auth_mfa_present':False,'claims':{'id':'u1','mfa_verified':True}});self.assertEqual(r['outcomes'][0]['status'],401)
    def test_target_project_has_its_own_membership_permissions(self):
        for allowed in (False,True):
            i={'data':{'project':2,'description':'owned'},'project_policies':{'1':{'role_permissions':['update'] if not allowed else []},'2':{'role_permissions':['update'] if allowed else []}}}
            r=self.check('CommentAndOrUpdatePerm.check_permissions',i);self.assertIs(r['outcomes'][0]['value'],allowed)
            self.assertIn({'ref':'project-2'},next(e for e in r['events'] if e['call']=='membership_lookup')['args'])
    def test_missing_project_membership_is_not_a_successful_leave(self):
        r=self.check('CanLeaveProject.check_permissions',{'project_policy':{'is_member':False}});self.assertIs(r['outcomes'][0]['value'],False)
    def test_oauth_scope_decisions_use_real_required_and_granted_sets(self):
        for method,scope,want in (('GET','owned read',True),('POST','owned read',False),('POST','owned write',True),('GET','read',False),('get','owned read',True)):
            r=self.check('CustomTokenHasReadWriteScope.has_permission',{'oauth':True,'method':method,'oauth_scope':scope});self.assertIs(r['outcomes'][0]['value'],want)
            self.assertEqual(r['source_calls']['AbstractAccessToken__is_valid'],1)
    def test_oauth_expiry_and_scope_failures_are_distinct(self):
        for expires,want in ((1000,False),(1001,True),(None,False)):
            self.assertIs(self.check('CustomTokenHasScope.has_permission',{'oauth':True,'oauth_expires':expires})['outcomes'][0]['value'],want)
        r=self.check('CustomTokenHasScope.has_permission',{'oauth':True,'oauth_scope':'read','scope_error_details':True});self.assertEqual(r['checked_state']['permission_message']['required_scopes'],['owned'])
        r=self.check('CustomTokenHasScope.has_permission',{'oauth':True,'oauth_scope':'read','oauth_expires':999,'scope_error_details':True});self.assertIsNone(r['checked_state']['permission_message'])
    def test_missing_required_scope_configuration_has_source_fallback(self):
        r=self.check('CustomTokenHasScope.has_permission',{'oauth':True,'required_scopes_missing':True});self.assertEqual(r['outcomes'][0]['name'],'ImproperlyConfigured')
        r=self.check('CustomTokenHasReadWriteScope.has_permission',{'oauth':True,'required_scopes_missing':True,'oauth_scope':'read'});self.assertIs(r['outcomes'][0]['value'],True)
    def test_dependency_release_and_source_inheritance_cannot_be_relabelled(self):
        c=copy.deepcopy(next(c for c in self.p['references']['contracts'] if c['id']=='boundary-48'));s=copy.deepcopy(self.p['sources'][c['source_key']]);c['oauth_dependency']['snapshot']='0'*40
        with self.assertRaises(ValueError):execute(s,c,c['contexts'][0])
        c=copy.deepcopy(next(c for c in self.p['references']['contracts'] if c['id']=='boundary-48'));s['text']=s['text'].replace('class CustomTokenHasScope(TokenHasScope):','class CustomTokenHasScope(OtherScope):');c['source_sha256']=hashlib.sha256(s['text'].encode()).hexdigest()
        with self.assertRaises(ValueError):execute(s,c,c['contexts'][0])
if __name__=='__main__':unittest.main()
