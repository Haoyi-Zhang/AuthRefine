"""Raw-data source-dependency branches;not additional independent applications."""
import copy,sys,unittest
from pathlib import Path
ART=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ART))
from reference_completion.replay import execute,load
from reference_completion.contracts import reference
from reference_completion.interpreter import program_for,AdmissionError

class BatchDependencyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):cls.packet=load(ART/'reference_completion/inputs.json.gz')
    def check(self,q,i,control=None,identifier=None):
        c=next(c for c in self.packet['references']['contracts'] if c['function']==q and (identifier is None or c['id']==identifier))
        out,state,counts,order=reference(c,i)
        r=execute(self.packet['sources'][c['source_key']],c,dict(inputs=i,expected=out,state=state,call_counts=counts,call_order=order),control)
        if control is None:self.assertEqual(r['status'],'agree',repr(r))
        return r
    def test_project_membership_roles_public_anonymous_and_superuser(self):
        for i,want in (({'project_policy':{'permission_name':'view_project','role_permissions':['view_project']}},True),({'project_policy':{'permission_name':'view_project','is_member':False}},False),({'project_policy':{'permission_name':'view_project','is_member':False,'public_permissions':['view_project']}},True),({'authenticated':False,'project_policy':{'permission_name':'view_project','anon_permissions':['view_project']}},True),({'authenticated':False,'project_policy':{'permission_name':'view_project','public_permissions':['view_project']}},False),({'superuser':True,'project_policy':{'permission_name':'view_project'}},True)):
            with self.subTest(i=i):self.assertIs(self.check('HasProjectPerm.check_permissions',i)['outcomes'][0]['value'],want)
    def test_admin_membership_and_leave_conditions(self):
        for p,want in (({'is_member':False,'is_admin':True},False),({'is_admin':True},True),({'is_admin':False},False)):
            self.assertIs(self.check('IsProjectAdmin.check_permissions',{'project_policy':p})['outcomes'][0]['value'],want)
        for p,kind in (({'leave_admin':False},'return'),({'leave_admin':True,'is_owner':True},'error'),({'leave_admin':True,'is_owner':False,'other_active_admin':False},'error'),({'leave_admin':True,'is_owner':False,'other_active_admin':True},'return')):
            r=self.check('CanLeaveProject.check_permissions',{'project_policy':p});self.assertEqual(r['outcomes'][0]['kind'],kind)
            self.assertEqual(r['source_calls']['can_user_leave_project'],1)
    def test_comment_role_short_circuit_and_update_fallback(self):
        for role in ([],['comment'],['update'],['comment','update']):
            r=self.check('CommentAndOrUpdatePerm.check_permissions',{'data':{'comment':'owned'},'project_policy':{'role_permissions':role}})
            self.assertIs(r['outcomes'][0]['value'],bool(role))
    def test_password_change_timestamp_and_microsecond_normalization(self):
        for i in ({'password_changed_at':None},{'token_iat':2,'password_changed_at':2,'password_change_microsecond':999999},{'token_iat':2,'password_changed_at':3},{'token_claims':{}}):
            self.check('JSONWebTokenAuthentication.authenticate',i)
    def test_unrepresentable_datetime_is_unknown_not_a_source_success(self):
        c=next(c for c in self.packet['references']['contracts'] if c['function']=='JSONWebTokenAuthentication.authenticate')
        for stamp in (-62135596801,253402300800,True):
            i={'token_iat':stamp};out,state,counts,order=reference(c,i)
            r=execute(self.packet['sources'][c['source_key']],c,dict(inputs=i,expected=out,state=state,call_counts=counts,call_order=order))
            self.assertEqual(r['status'],'unknown')
    def test_request_context_fields_and_precedence(self):
        i={'headers':{'WebSocketId':'socket','ClientSessionId':'abc-123','ClientUndoRedoActionGroupId':'00000000-0000-4000-8000-000000000001'},'meta':{'HTTP_X_FORWARDED_FOR':' 192.0.2.1, 192.0.2.2','HTTP_X_REAL_IP':'192.0.2.3','REMOTE_ADDR':'192.0.2.4'},'impersonated_by':9}
        r=self.check('JSONWebTokenAuthentication.authenticate',i);s=r['checked_state']['user_context']
        self.assertEqual(s['remote_addr_ip'],'192.0.2.1');self.assertEqual(s['impersonated_by_user_id'],9)
        self.assertEqual(s['untrusted_client_session_id'],'abc-123')
        for meta in ({'HTTP_X_REAL_IP':' 192.0.2.3 '},{'REMOTE_ADDR':'192.0.2.4'},{}):self.check('JSONWebTokenAuthentication.authenticate',{'meta':meta})
    def test_invalid_headers_preserve_partial_state_and_skip_later_effects(self):
        for headers in ({'ClientSessionId':'not valid'},{'ClientSessionId':7},{'ClientUndoRedoActionGroupId':'not-uuid'}):
            r=self.check('JSONWebTokenAuthentication.authenticate',{'headers':headers})
            self.assertEqual(r['outcomes'][0]['kind'],'error');self.assertIn('web_socket_id',r['checked_state']['user_context'])
            self.assertNotIn('impersonated_by_user_id',r['checked_state']['user_context']);self.assertEqual(r['call_counts']['sentry_setup'],0)
    def test_missing_user_context_writes_are_detected(self):
        r=self.check('JSONWebTokenAuthentication.authenticate',{},'drop_user_context');self.assertEqual(r['status'],'mismatch')
    def test_preview_cookie_name_uses_source_and_prefix(self):
        r=self.check('BuilderPreviewAuthentication.authenticate',{'preview_cookie':'owned-preview','cookie_prefix':'owned-'})
        self.assertEqual(r['source_calls']['get_builder_preview_cookie_name'],1)
    def test_jwt_header_parsing_and_basic_source_getter(self):
        for i in ({'header':''},{'header':'Other owned'},{'header':'Bearer owned-normal-token'}):self.check('JWTAuthentication.authenticate',i)
        r=self.check('BasicAuthentication.authenticate',{'header':'Basic b3duZWQtdXNlcjpvd25lZC1wYXNzd29yZA=='})
        self.assertEqual(r['source_calls']['get_authorization_header'],1)
    def test_group_permissions_and_default_fallback(self):
        for i,want in (({'default_permissions':{},'group_permissions':[{'features':{'api_keys':True}}]},'return'),({'default_permissions':{'features':{'api_keys':True}},'group_permissions':[{'features':{'api_keys':False}}]},'return'),({'default_permissions':{}},'error'),({'default_permissions':{},'permission_template':{'features':{'api_keys':True}}},'return')):
            r=self.check('get_current_user_by_api_key',i);self.assertEqual(r['outcomes'][0]['kind'],want);self.assertEqual(r['source_calls']['has_permission'],1)
    def test_token_stamp_type_and_mfa_branches(self):
        for i in ({'claims':{'id':'u1','session_stamp':'s'},'account_stamp':'s'},{'claims':{'id':'u1','typ':'unknown'}},{'mfa_enabled':True},{'mfa_enabled':True,'mfa_secret':True,'claims':{'id':'u1','mfa_verified':True}},{'mfa_enabled':True,'mfa_secret':True,'mfa_reset':True,'claims':{'id':'u1','mfa_verified':True}},{'mfa_enabled':True,'mfa_oauth_bypass':True,'claims':{'id':'u1','auth_method':'oauth'}},{'mfa_enabled':True,'claims':{'id':'u1','typ':'automation'}}):self.check('get_current_user',i)
    def test_revocation_rows_and_lookup_error_source_policy(self):
        for i in ({'token_revoked':True,'claims':{'id':'u1','jti':'owned'}},{'revoked_at':'2','claims':{'id':'u1','iat':2}},{'revoked_at':'2','claims':{'id':'u1','iat':3}},{'revoked_at':'2','claims':{'id':'u1'}},{'revoked_at':'invalid'},{'redis_error':True}):self.check('get_current_user',dict(i,redis_enabled=True))
    def test_model_usage_reads_raw_pool_keys(self):
        r=self.check('get_current_usage',{'public_usage':True,'usage_pool':{'a':[],'b':[1]}});self.assertEqual(r['outcomes'][0]['value']['model_ids'],['a','b'])
    def test_permission_table_tampering_rejected(self):
        c=copy.deepcopy(next(c for c in self.packet['references']['contracts'] if c['id']=='boundary-11'));c['batch_constants']['taiga_permission_tables']['ADMINS_PERMISSIONS']+=['made-up']
        with self.assertRaises(ValueError):execute(self.packet['sources'][c['source_key']],c,c['contexts'][0])
    def test_general_lambda_remains_unadmitted(self):
        with self.assertRaises(AdmissionError):program_for('def f():\n return list(map(lambda x:x+1,[1]))\n','f')

if __name__=='__main__':unittest.main()
