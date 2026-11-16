"""Test-only server with stubbed reads and an isolated SQLite estate."""
import os
from pathlib import Path
import secrets
import sys
from types import SimpleNamespace
from copy import deepcopy

root=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(root/'src'))
os.environ.pop('ION_DATABASE_URL',None)
os.environ['ION_DATA_DIR']=str(root/'.audit/de-data')
os.environ['ION_DEV_MODE']='true'
os.environ['ION_DE_LICENSE_ENFORCED']='true'
os.environ['ION_DE_MODULE_ENABLED']='false'
password=root/'.audit/de-browser-password'
if not password.exists():
    password.write_text(secrets.token_urlsafe(36),encoding='utf-8')
os.environ['ION_ADMIN_PASSWORD']=password.read_text(encoding='utf-8')
import ion
assert Path(ion.__file__).resolve().parent==root/'src/ion'
from ion.web.server import app
from ion.web import de_tide_api as tide
from ion.web.ui import _detection_engineering_catalogue as catalogue

def result(value):
    return lambda *args,**kwargs:deepcopy(value)

def async_result(value):
    async def read(*args,**kwargs):
        return deepcopy(value)
    return read

rule={'name':'Rule "quoted" <safe>','severity':'critical','quality_score':0,'enabled':False,'mitre_ids':['T1003'],'rule_id':'rule-1'}
tide.tide_de_spaces=result({'spaces':[{'space':'default','rule_count':2},{'space':'quoted"space','rule_count':0}],'active':'default'})
tide.tide_de_set_space=lambda space:{'ok':True,'active':space}
tide.tide_de_sync_status=result({'healthy':0,'total_datasets':0})
tide.tide_de_sync_now=result({'synced':0,'total':0})
tide.tide_de_posture=result({'enabled':True,'total_rules':2,'enabled_rules':1,'disabled_rules':1,'covered_techniques':1,'total_techniques':10,'unmapped_rules':0,'total_systems':1,'severity':{'critical':{'total':2,'enabled':1,'disabled':1}},'quality':{'excellent':0,'good':0,'fair':0,'poor':2,'avg_quality':0}})
tide.tide_de_disabled_critical=result([rule])
tide.tide_de_gaps=result({'enabled':True,'total_blind_spots':1,'blind_spots_by_tactic':{'credential-access':[{'id':'T1003','name':'Technique <safe>'}]},'quick_wins':[rule],'unmapped_rules':[rule],'systems_coverage':[{'name':'System <safe>','applied_rules':0}]})
tide.tide_de_use_cases=result([{'name':'Use case <safe>','description':'Description','steps':[{'order':1,'name':'Step','tactic':'credential-access','techniques':['T1003'],'required_rule':'Rule'}],'technique_coverage':{'T1003':{'rule_count':2,'enabled_rules':1}}}])
def rules(search='',severity='',enabled='',offset=0,limit=50):
    return {'rows':[dict(rule,name=rule['name']+str(offset))],'total':100}
tide.tide_de_rules=rules
tide.tide_de_kill_chain_alerts=async_result({'enabled':True,'progressions':[{'host':'Host <safe>','playbook_name':'Playbook','severity':'critical','fired_steps':1,'total_steps':2,'pct_complete':50,'steps':[{'name':'Step','order':1,'fired':True,'techniques':['T1003'],'alert_data':{'count':0,'rules':['Rule']}}]}],'total_hosts_checked':0,'playbook_count':1})
tide.tide_de_execution=async_result({'enabled':True,'summary':{'total_alerts':0,'unique_rules_firing':0,'avg_alerts_per_rule':0,'noisy_rules':0,'silent_enabled_rules':0,'status':{'open':0},'tide_matched':0},'timeline':[{'timestamp':'2026-10-13','count':0}],'severity_timeline':[{'timestamp':'2026-10-13','critical':0,'high':0,'medium':0,'low':0}],'top_firing':[{'rule_name':'Rule <safe>','alert_count':0,'close_rate':0,'in_tide':True,'tide_severity':'critical'}],'noisy_rules':[],'silent_rules':[{'name':'Silent <safe>','severity':'critical','quality_score':0,'mitre_ids':[]}]})
tide.tide_de_systems=result([{'id':'system-1','name':'System <safe>','classification':'C'}])
actor={'id':'actor"quoted','name':'Actor <safe>','entity_type':'threat_actor','aliases':['Alias'],'description':'Description <safe>','readiness_pct':0,'covered_count':0,'gap_count':1,'total_ttps':1,'covered':[],'gaps':[{'mitre_id':'T1003','name':'Technique'}]}
tide.tide_de_actor_readiness=async_result({'enabled':True,'actors':[actor],'tide_covered_techniques':0,'tide_total_techniques':10})
tide.tide_de_system_readiness=async_result({'enabled':True,'actor':{'id':actor['id'],'name':'Actor <safe>'},'system':{'name':'System <safe>'},'readiness_pct':0,'covered_count':0,'gap_count':1,'total_ttps':1,'coverage_matrix':[{'mitre_id':'T1003','name':'Technique <safe>','state':'gap','rule_count':0,'enabled_rules':0}],'ai_summary':None})
catalogue.get_d3fend_coverage=result({'summary':{'overall_pct':0,'fully_covered':0,'partial':0,'blind':1,'total_techniques':1,'tide_enabled':True},'tactics':[{'id':'detect','name':'Detect','covered_count':0,'technique_count':1,'coverage_pct':0}],'techniques':[{'id':'D3-X','name':'Defence <safe>','tactic':'detect','state':'blind','description':'Description <safe>','covered_attacks':0,'total_attacks':1,'coverage_pct':0}]})
catalogue.vulnerability_service.coverage_overview=result({'summary':{'total':1,'uncovered':1,'covered':0,'critical':1,'kev':0,'avg_cvss':0},'vulnerabilities':[{'id':1,'cve_id':'CVE-2026-0001','title':'Vulnerability <safe>','severity':'critical','cvss_score':0,'affected_asset_count':0,'affected_assets':[],'coverage_pct':0,'covered':False,'detection_rules':[],'technique_ids':[],'kev':False}]})
plan={'id':1,'name':'Plan <safe>','actor_name':'Actor','status':'draft','step_count':1,'passed_count':0,'coverage_pct':0,'updated_at':'2026-10-13','steps':[{'id':1,'name':'Step <safe>','mitre_id':'T1003','description':'Description','status':'pending','expected_detection':'Rule','evidence':None}]}
catalogue.emulation_service.list_plans=result([plan])
catalogue.emulation_service.get_plan=lambda *args,**kwargs:SimpleNamespace(to_dict=result(plan))

import uvicorn
uvicorn.run(app,host='127.0.0.1',port=8820,log_level='warning')
