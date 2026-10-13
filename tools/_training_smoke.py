from pathlib import Path
from playwright.sync_api import sync_playwright
import re

root = Path(__file__).resolve().parents[1]
shell = (root/'src/ion/web/templates/training.html').read_text(encoding='utf-8')
parts=[]
for start,end in [('function populateRoleDropdowns()', 'let assessmentFormRendered'),('function renderForecast()', 'async function saveAssessment()'),('async function loadTeamData()', '// Permission-based tab visibility')]:
    a=shell.index(start);b=shell.index(end,a);parts.append(shell[a:b])
code='\n'.join(parts)
ids=set(re.findall(r"getElementById\('([^']+)'\)",code))
with sync_playwright() as p:
    browser=p.chromium.launch(channel='msedge',headless=True)
    page=browser.new_page()
    page.set_content((root/'src/ion/web/templates/_fragments/training_client_nodes.html').read_text(encoding='utf-8')+''.join(('<select id="'+id+'"></select>') if id in {'sa-current-role','sa-target-role'} else '<div id="'+id+'"></div>' for id in ids))
    page.add_script_tag(content="function cloneTemplate(id) { return document.getElementById(id).content.firstElementChild.cloneNode(true); }")
    page.add_script_tag(content=(root/'src/ion/web/static/js/training-nodes.js').read_text(encoding='utf-8'))
    page.add_script_tag(content="let teamData=null; const teamSubLoaded={}; const ROLES={}; const SKILLS_MATRIX={'Incident Response': {a:{name:'A <B>',targets:{}}}}; let careerGoal={}; let userRatings={}; "+code)
    page.evaluate("""() => {
        teamData = {members:[{user_id:1,username:'Alice',display_name:'A "quoted" <name>',roles:['analyst'],skills:{a:4}}],snapshots:[{skill_key:'a',date:'2026-10-01',avg_proficiency:4}]};
        renderTeamComposition();renderCapabilityCoverage();renderHeatmap();renderSparklines();populateDepartureDropdown();
        knowledgeData={articles:[]};renderKnowledge();
        schedMembers=teamData.members;schedData={};renderScheduleGrid();renderCapCoverageGrid();
        switchCovView('week');switchCovView('month');
        covThresholdsAvailable=true;covThresholds={'Incident Response':{min_staff:2,min_level:3}};renderUnderstaffed();
        openFillGap('Incident Response','2026-10-01');openThresholdConfig();openDayRoster('2026-10-01');openMemberProfile(1);
    }""")
    assert page.locator('#team-comp-cards').inner_text().startswith('1')
    assert page.locator('#team-heatmap').inner_text().find('A <B>')>=0
    assert page.locator('#sparkline-grid svg polyline').count()==1
    assert page.locator('#sparkline-grid svg').evaluate('(svg) => svg.viewBox.baseVal.width') == 100
    assert page.locator('#sparkline-grid svg').evaluate('(svg) => svg.viewBox.baseVal.height') == 30
    assert page.locator('#sparkline-grid svg').evaluate('(svg) => svg.preserveAspectRatio.baseVal.align') == 1
    assert page.locator('#sparkline-grid svg').evaluate('(svg) => svg.viewBox.baseVal.width') == 100
    assert page.locator('#sparkline-grid svg').evaluate('(svg) => svg.viewBox.baseVal.height') == 30
    assert page.locator('#km-grid tr[data-doc]').count()>20
    assert page.locator('#sched-grid [data-click-action="openMemberProfile"]').get_attribute('data-args')=='[1]'
    assert page.locator('#threshold-config-root input').count()==20
    assert page.locator('#member-popover-root').inner_text().find('A "quoted" <name>')>=0
    page.evaluate("""() => {
        const id = 'role"quoted';
        ROLES[id] = {title:'Role <quoted>', certs:[{name:'Cert <quoted>',price:0,provider:'Provider & Co',difficulty:'advanced'}]};
        careerGoal={current_role:id,target_role:id};
        for(let i=0;i<16;i++) SKILLS_MATRIX['Incident Response']['gap'+i] = {name:'Skill '+i,targets:{[id]:3}};
        populateRoleDropdowns();renderForecast();
        knowledgeData={articles:[{capability_key:ALL_SOC_DOCS[0].key,doc_status:'comprehensive',owner_user_id:1,notes:'Literal <note>'}]};
        renderKnowledge();
    }""")
    assert page.locator('#sa-target-role').input_value() == 'role"quoted'
    assert page.locator('#sa-current-role option').count() == 2
    assert page.locator('#sa-forecast .sa-gap-item').count() == 15
    assert '+ 1 more...' in page.locator('#sa-forecast').inner_text()
    assert page.locator('#sa-forecast .cert-name').inner_text() == 'Cert <quoted>'
    assert page.locator('#sa-forecast .cert-price').inner_text() == '~£0'
    first_doc = page.evaluate('ALL_SOC_DOCS[0].key')
    doc_row = page.locator('#km-grid tr[data-doc]').filter(has=page.locator('textarea')).first
    assert doc_row.locator('select[data-field="doc_status"]').input_value() == 'comprehensive'
    assert doc_row.locator('select[data-field="owner_user_id"]').input_value() == '1'
    assert doc_row.locator('textarea').input_value() == 'Literal <note>'
    page.evaluate("""() => { for(let i=0;i<16;i++) userRatings['gap'+i]=3;renderForecast(); }""")
    assert 'meet or exceed all skill targets' in page.locator('#sa-forecast').inner_text()
    page.evaluate("""async () => {
        window.fetch = async () => ({ok:false});
        teamData=null;await loadTeamData();
        await loadKnowledgeData();await loadScheduleData();
        await loadCovThresholds();renderUnderstaffed();
    }""")
    for selector in ['#team-heatmap','#team-comp-cards','#soc-cap-grid','#sparkline-grid','#km-grid','#sched-grid','#soc-understaffed']:
        assert 'unavailable' in page.locator(selector).inner_text().lower()
    page.evaluate("""async () => {
        window.fetch = async () => ({ok:true,json:async()=>({members:[],snapshots:[]})});
        await loadTeamData();
    }""")
    assert 'No team members' in page.locator('#team-comp-cards').inner_text()
    page.evaluate("""async () => {
        window.fetch = async () => ({ok:true,json:async()=>({impacts:[],readiness_before:0,readiness_after:0})});
        document.getElementById('departure-user').value='1';
        await simulateDeparture();
    }""")
    assert page.locator('#departure-results').inner_text().count('0%')==2
    print('Team, coverage, heatmap, sparkline SVG, knowledge table, schedule, weekly/monthly coverage, staffing, gap, thresholds, day roster and member profile DOM smoke passed.')
    browser.close()
