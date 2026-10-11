"""
CyberSentinel Scanner UI
Flask-based dashboard for running scans and viewing reports
"""
import sys
sys.path.append('/scanner')

from flask import Flask, render_template_string, request, jsonify, send_file
import threading, os
from datetime import datetime
from scanner import VulnShopScanner, findings as global_findings
from reporter import generate_report
scan_status = {'running': False, 'done': False, 'started': None, 'finished': None}

app = Flask(__name__)

print("🔥 Scanner booting...")


DASHBOARD_HTML = '''
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>CyberSentinel Enterprise Scanner</title>
<style>
:root{--navy:#0d2b55;--red:#c62828;--teal:#00695c;--amber:#e65100;--bg:#0a0e1a;--card:#111827;--border:#1e2d45;--text:#e0e0e0;--muted:#64748b;--green:#22c55e}
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:'Segoe UI',Arial,sans-serif;background:var(--bg);color:var(--text);min-height:100vh}
.top-bar{background:linear-gradient(90deg,#0d2b55,#00695c);padding:0 2rem;height:56px;display:flex;align-items:center;justify-content:space-between}
.brand{font-size:1.3rem;font-weight:700;color:#fff;letter-spacing:-0.3px}
.brand span{color:#80cbc4}
.container{max-width:1300px;margin:0 auto;padding:1.5rem}
.card{background:var(--card);border:0.5px solid var(--border);border-radius:10px;padding:1.25rem}
.grid-3{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:1rem;margin-bottom:1.5rem}
.stat{text-align:center;padding:1.25rem;border-radius:10px;border:0.5px solid var(--border)}
.stat .num{font-size:2.2rem;font-weight:700;line-height:1}
.stat .lbl{font-size:0.82rem;color:var(--muted);margin-top:5px}
.badge{display:inline-block;font-size:11px;padding:2px 9px;border-radius:4px;font-weight:600}
.b-critical{background:#7f0000;color:#ffccbc}
.b-high{background:#7c3900;color:#ffe0b2}
.b-medium{background:#7a5800;color:#fff176}
.b-low{background:#1b4d1b;color:#a5d6a7}
.b-info{background:#0a2f5c;color:#90caf9}
.btn{padding:10px 22px;border:none;border-radius:6px;font-size:0.95rem;font-weight:600;cursor:pointer;transition:opacity .2s}
.btn:hover{opacity:.85}
.btn-primary{background:#1565c0;color:#fff}
.btn-success{background:#00695c;color:#fff}
.btn-danger{background:#c62828;color:#fff}
.btn-disabled{background:#374151;color:#6b7280;cursor:not-allowed}
.progress-bar{height:8px;background:#1e2d45;border-radius:4px;overflow:hidden;margin:8px 0}
.progress-fill{height:100%;background:linear-gradient(90deg,#00695c,#1565c0);border-radius:4px;transition:width .5s}
.log-box{background:#050810;border:0.5px solid var(--border);border-radius:8px;padding:12px;height:260px;overflow-y:auto;font-family:monospace;font-size:12px;line-height:1.6}
.log-box .crit{color:#ff5252}
.log-box .high{color:#ff8f00}
.log-box .med{color:#ffe082}
.log-box .info{color:#80cbc4}
.log-box .ok{color:#69f0ae}
.findings-table{width:100%;border-collapse:collapse;font-size:0.88rem}
.findings-table th{background:#0d2b55;color:#fff;padding:9px 12px;text-align:left;font-weight:500}
.findings-table td{padding:9px 12px;border-bottom:0.5px solid var(--border);vertical-align:top}
.findings-table tr:hover td{background:#131c2e}
.endpoint{font-family:monospace;font-size:0.8rem;color:#80cbc4}
.cvss-9{color:#ff5252;font-weight:700}
.cvss-7{color:#ff8f00;font-weight:700}
.cvss-5{color:#ffe082;font-weight:700}
.payload-box{background:#050810;border-radius:4px;padding:6px 10px;font-family:monospace;font-size:0.78rem;color:#ef9a9a;max-width:280px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.section-title{font-size:1rem;font-weight:600;color:#90caf9;margin-bottom:1rem;display:flex;align-items:center;gap:8px}
.pulse{display:inline-block;width:8px;height:8px;border-radius:50%;background:#22c55e;animation:pulse 1.2s infinite}
@keyframes pulse{0%,100%{opacity:1;transform:scale(1)}50%{opacity:.5;transform:scale(1.3)}}
.tab-bar{display:flex;gap:4px;margin-bottom:1rem;border-bottom:0.5px solid var(--border);padding-bottom:0}
.tab{padding:8px 16px;border-radius:6px 6px 0 0;font-size:0.88rem;cursor:pointer;color:var(--muted);border:0.5px solid transparent;border-bottom:none;transition:all .2s}
.tab.active{background:var(--card);color:#90caf9;border-color:var(--border)}
.tab-content{display:none}.tab-content.active{display:block}
</style>
</head>
<body>
<div class="top-bar">
  <span class="brand">Cyber<span>Sentinel</span> &nbsp;<span style="font-size:0.75rem;background:#1e2d45;padding:2px 8px;border-radius:3px;font-weight:400">Enterprise v2.0</span></span>
  <span style="font-size:0.85rem;color:#64748b">Advanced Django Security Scanner</span>
</div>

<div class="container">

  <!-- Stats row -->
  <div class="grid-3" id="statsRow">
    <div class="stat" style="border-color:#7f0000">
      <div class="num" style="color:#ff5252" id="critCount">0</div>
      <div class="lbl">Critical</div>
    </div>
    <div class="stat" style="border-color:#7c3900">
      <div class="num" style="color:#ff8f00" id="highCount">0</div>
      <div class="lbl">High</div>
    </div>
    <div class="stat" style="border-color:#7a5800">
      <div class="num" style="color:#ffe082" id="medCount">0</div>
      <div class="lbl">Medium</div>
    </div>
    <div class="stat" style="border-color:#1b4d1b">
      <div class="num" style="color:#a5d6a7" id="lowCount">0</div>
      <div class="lbl">Low / Info</div>
    </div>
    <div class="stat" style="border-color:#0d2b55">
      <div class="num" style="color:#90caf9" id="totalCount">0</div>
      <div class="lbl">Total Findings</div>
    </div>
  </div>

  <!-- Scan control -->
  <div class="card" style="margin-bottom:1.5rem">
    <div class="section-title">
      <span id="statusDot" style="display:inline-block;width:8px;height:8px;border-radius:50%;background:#374151"></span>
      Scan Control
    </div>
    <div style="display:flex;gap:12px;align-items:center;flex-wrap:wrap;margin-bottom:1rem">
      <div style="flex:1;min-width:250px">
        <label style="font-size:0.82rem;color:var(--muted);display:block;margin-bottom:4px">Target URL</label>
        <input id="targetUrl" value="{{ target }}" style="width:100%;background:#050810;border:0.5px solid var(--border);color:#e0e0e0;padding:9px 14px;border-radius:6px;font-size:0.95rem">
      </div>
      <div style="display:flex;gap:8px;align-items:flex-end;padding-bottom:0">
        <button class="btn btn-primary" onclick="startScan()" id="scanBtn">▶ Start Scan</button>
        <button class="btn btn-success" onclick="downloadReport()" id="reportBtn" style="display:none">⬇ PDF Report</button>
      </div>
    </div>
    <div class="progress-bar"><div class="progress-fill" id="progressFill" style="width:0%"></div></div>
    <div style="font-size:0.82rem;color:var(--muted);margin-top:4px" id="statusText">Ready to scan</div>
  </div>

  <!-- Tabs -->
  <div class="tab-bar">
    <div class="tab active" onclick="switchTab('findings')">Findings</div>
    <div class="tab" onclick="switchTab('log')">Live Log</div>
    <div class="tab" onclick="switchTab('modules')">Modules</div>
  </div>

  <!-- Findings tab -->
  <div class="tab-content active" id="tab-findings">
    <div class="card">
      <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:1rem;flex-wrap:wrap;gap:8px">
        <div class="section-title" style="margin:0">Vulnerability Findings <span id="findCount" style="font-size:0.85rem;color:var(--muted)">(0)</span></div>
        <div style="display:flex;gap:8px">
          <select id="sevFilter" onchange="filterFindings()" style="background:#050810;border:0.5px solid var(--border);color:#e0e0e0;padding:6px 10px;border-radius:5px;font-size:0.85rem">
            <option value="ALL">All Severities</option>
            <option value="CRITICAL">Critical only</option>
            <option value="HIGH">High only</option>
            <option value="MEDIUM">Medium only</option>
          </select>
        </div>
      </div>
      <div style="overflow-x:auto">
        <table class="findings-table">
          <thead>
            <tr>
              <th>#</th><th>Severity</th><th>ID</th><th>Title</th>
              <th>Endpoint</th><th>CVSS</th><th>Payload</th><th>Fix Preview</th>
            </tr>
          </thead>
          <tbody id="findingsBody">
            <tr><td colspan="8" style="text-align:center;padding:2rem;color:var(--muted)">Run a scan to see findings</td></tr>
          </tbody>
        </table>
      </div>
    </div>
  </div>

  <!-- Log tab -->
  <div class="tab-content" id="tab-log">
    <div class="card">
      <div class="section-title"><span class="pulse" id="logPulse" style="display:none"></span> Live Scan Log</div>
      <div class="log-box" id="logBox">
        <div class="info">CyberSentinel Enterprise Scanner ready.</div>
        <div class="info">Click "Start Scan" to begin assessment.</div>
      </div>
    </div>
  </div>

  <!-- Modules tab -->
  <div class="tab-content" id="tab-modules">
    <div class="card">
      <div class="section-title">Scan Modules</div>
      <div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(280px,1fr));gap:1rem">
        {% for mod in modules %}
        <div style="border:0.5px solid var(--border);border-radius:8px;padding:1rem;border-left:3px solid {{ mod.color }}">
          <div style="font-size:0.95rem;font-weight:600;color:#e0e0e0;margin-bottom:4px">{{ mod.name }}</div>
          <div style="font-size:0.8rem;color:var(--muted);margin-bottom:8px">{{ mod.desc }}</div>
          <div style="display:flex;flex-wrap:wrap;gap:5px">
            {% for t in mod.tests %}
            <span style="font-size:10px;padding:1px 7px;border-radius:3px;background:#1e2d45;color:#90caf9">{{ t }}</span>
            {% endfor %}
          </div>
        </div>
        {% endfor %}
      </div>
    </div>
  </div>

</div><!-- /container -->

<script>
let allFindings=[], pollInterval=null;

function switchTab(name){
  document.querySelectorAll('.tab').forEach(t=>t.classList.remove('active'));
  document.querySelectorAll('.tab-content').forEach(t=>t.classList.remove('active'));
  event.target.classList.add('active');
  document.getElementById('tab-'+name).classList.add('active');
}

function log(msg,cls='info'){
  const box=document.getElementById('logBox');
  const div=document.createElement('div');
  div.className=cls; div.textContent=msg;
  box.appendChild(div); box.scrollTop=box.scrollHeight;
}

function startScan(){
  const target=document.getElementById('targetUrl').value;
  document.getElementById('scanBtn').textContent='Scanning...';
  document.getElementById('scanBtn').className='btn btn-disabled';
  document.getElementById('scanBtn').disabled=true;
  document.getElementById('reportBtn').style.display='none';
  document.getElementById('progressFill').style.width='5%';
  document.getElementById('statusText').textContent='Initialising scan...';
  document.getElementById('statusDot').style.background='#22c55e';
  document.getElementById('statusDot').style.animation='pulse 1s infinite';
  document.getElementById('logPulse').style.display='inline-block';
  document.getElementById('logBox').innerHTML='';
  log('🚀 Starting CyberSentinel Enterprise scan against: '+target);
  log('⏳ Modules loading: Injection · Auth · Access Control · Business Logic · Advanced · Data · API');

  fetch('/api/scan',{method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({target})})
  .then(r=>r.json())
  .then(d=>{
    if(d.status==='started') pollInterval=setInterval(pollStatus,2000);
  });
}

function pollStatus(){
  fetch('/api/status').then(r=>r.json()).then(d=>{
    updateStats(d.findings);
    document.getElementById('progressFill').style.width=d.progress+'%';
    document.getElementById('statusText').textContent=d.message;
    if(d.log_tail) d.log_tail.forEach(l=>log(l, l.includes('CRITICAL')?'crit':l.includes('HIGH')?'high':l.includes('MEDIUM')?'med':'info'));
    if(d.done){
      clearInterval(pollInterval);
      document.getElementById('scanBtn').textContent='▶ Start Scan';
      document.getElementById('scanBtn').className='btn btn-primary';
      document.getElementById('scanBtn').disabled=false;
      document.getElementById('reportBtn').style.display='inline-block';
      document.getElementById('statusDot').style.animation='none';
      document.getElementById('statusDot').style.background='#90caf9';
      document.getElementById('logPulse').style.display='none';
      log('✅ Scan complete. '+d.findings.length+' findings.','ok');
      renderFindings(d.findings);
    }
  });
}

function updateStats(f){
  const c={CRITICAL:0,HIGH:0,MEDIUM:0,LOW:0,INFO:0};
  f.forEach(x=>{ c[x.severity]=(c[x.severity]||0)+1; });
  document.getElementById('critCount').textContent=c.CRITICAL;
  document.getElementById('highCount').textContent=c.HIGH;
  document.getElementById('medCount').textContent=c.MEDIUM;
  document.getElementById('lowCount').textContent=(c.LOW||0)+(c.INFO||0);
  document.getElementById('totalCount').textContent=f.length;
  document.getElementById('findCount').textContent='('+f.length+')';
  allFindings=f;
}

const sevBadge={CRITICAL:'b-critical',HIGH:'b-high',MEDIUM:'b-medium',LOW:'b-low',INFO:'b-info'};
const cvssClass=s=>s>=9?'cvss-9':s>=7?'cvss-7':'cvss-5';

function renderFindings(findings){
  const tbody=document.getElementById('findingsBody');
  const filter=document.getElementById('sevFilter').value;
  const show=filter==='ALL'?findings:findings.filter(f=>f.severity===filter);
  if(!show.length){tbody.innerHTML='<tr><td colspan="8" style="text-align:center;padding:2rem;color:var(--muted)">No findings match filter</td></tr>';return;}
  tbody.innerHTML=show.map((f,i)=>`
    <tr>
      <td style="color:var(--muted)">${i+1}</td>
      <td><span class="badge ${sevBadge[f.severity]||'b-info'}">${f.severity}</span></td>
      <td style="font-family:monospace;font-size:0.8rem;color:#80cbc4">${f.vuln_id}</td>
      <td style="font-weight:500;color:#e0e0e0;max-width:180px">${f.title}</td>
      <td class="endpoint">${f.endpoint}</td>
      <td class="${cvssClass(f.cvss_score)}">${f.cvss_score}</td>
      <td><div class="payload-box" title="${f.payload}">${f.payload.substring(0,50)}${f.payload.length>50?'...':''}</div></td>
      <td style="font-size:0.78rem;color:var(--muted);max-width:200px;word-break:break-word">${f.fix.substring(0,100)}...</td>
    </tr>
  `).join('');
}

function filterFindings(){renderFindings(allFindings);}

function downloadReport(){
  fetch('/api/report',{method:'POST'}).then(r=>r.json()).then(d=>{
    if(d.url) window.location.href=d.url;
  });
}
</script>
</body>
</html>
'''

modules_meta = [
    {'name':'Injection Attacks','color':'#ff5252','desc':'SQL injection, Command injection, SSTI, XXE, XSS',
     'tests':['SQLi (error/union/time/boolean)','CMDi (shell=True)','SSTI ({{ 7|add:7 }})','XXE (file:///)','Stored/Reflected XSS']},
    {'name':'Authentication','color':'#ff8f00','desc':'Brute force, session, CSRF, JWT attacks',
     'tests':['Brute force (no lockout)','Session cookie flags','CSRF token bypass','JWT none-algorithm','JWT weak secret']},
    {'name':'Access Control','color':'#ffe082','desc':'IDOR, privilege escalation, mass assignment',
     'tests':['IDOR on user data','IDOR on orders','Unauth debug endpoint','Mass assignment']},
    {'name':'Business Logic','color':'#00695c','desc':'Price manipulation, coupon abuse, race conditions',
     'tests':['Negative quantity','100% coupon','Client-side price','Mass order update','Unlimited refund']},
    {'name':'Advanced Attacks','color':'#7f77dd','desc':'SSRF, path traversal, deserialization (RCE)',
     'tests':['SSRF (AWS metadata)','Path traversal (/etc/passwd)','Pickle deserialization RCE']},
    {'name':'Data Exposure','color':'#1565c0','desc':'Unauthenticated data dumps, GraphQL, headers',
     'tests':['Mass user export','GraphQL introspection','Security headers audit']},
    {'name':'API Security','color':'#00695c','desc':'Mass data exposure, rate limiting, authentication',
     'tests':['Internal fields exposed','No rate limiting','No authentication']},
]

scan_log = []
scan_progress = 0

@app.route('/')
def index():
    target = os.environ.get('TARGET_URL', 'http://web:8000')
    return render_template_string(DASHBOARD_HTML, target=target, modules=modules_meta)

@app.route('/api/scan', methods=['POST'])
def api_scan():
    global current_findings, scan_log, scan_progress
    data   = request.get_json()
    target = data.get('target', os.environ.get('TARGET_URL', 'http://web:8000'))

    if scan_status['running']:
        return jsonify({'status': 'already_running'})

    current_findings = []
    scan_log         = ['🚀 Scan started against: ' + target]
    scan_progress    = 0
    scan_status.update({'running': True, 'done': False,
                        'started': datetime.now().isoformat()})

    def run():
        global scan_progress
        try:
            scanner = VulnShopScanner(target)
            results = scanner.run()
            current_findings.extend(results)
            scan_progress = 100
        except Exception as e:
            scan_log.append(f'❌ Scan error: {e}')
        finally:
            scan_status.update({'running': False, 'done': True,
                                'finished': datetime.now().isoformat()})

    t = threading.Thread(target=run, daemon=True)
    t.start()
    return jsonify({'status': 'started'})

@app.route('/api/status')
def api_status():
    import random
    if scan_status['running']:
        global scan_progress
        scan_progress = min(scan_progress + random.randint(2, 8), 95)

    findings_data = []
    from scanner import findings as live_findings
    for f in live_findings:
        findings_data.append({
            'vuln_id':    f.vuln_id,
            'severity':   f.severity,
            'category':   f.category,
            'title':      f.title,
            'endpoint':   f.endpoint,
            'method':     f.method,
            'payload':    f.payload,
            'evidence':   f.evidence,
            'cvss_score': f.cvss_score,
            'fix':        f.fix,
        })

    log_tail = []
    if scan_status['running'] and findings_data:
        last = findings_data[-1]
        log_tail = [f"  {'🔴' if last['severity']=='CRITICAL' else '🟠' if last['severity']=='HIGH' else '🟡'} [{last['severity']}] {last['title']} @ {last['endpoint']}"]

    return jsonify({
        'running':  scan_status['running'],
        'done':     scan_status['done'],
        'progress': scan_progress if scan_status['running'] else (100 if scan_status['done'] else 0),
        'message':  'Scanning...' if scan_status['running'] else ('Scan complete' if scan_status['done'] else 'Ready'),
        'findings': findings_data,
        'log_tail': log_tail,
    })

@app.route('/api/report', methods=['POST'])
def api_report():
    from scanner import findings as live_findings
    if not live_findings:
        return jsonify({'error': 'No findings — run scan first'})
    target = os.environ.get('TARGET_URL', 'http://web:8000')
    ts     = datetime.now().strftime('%Y%m%d_%H%M%S')
    path   = f'/reports/cybersentinel_report_{ts}.pdf'
    generate_report(live_findings, target, path)
    return jsonify({'url': f'/report/download/{ts}'})

@app.route('/report/download/<ts>')
def download_report(ts):
    path = f'/reports/cybersentinel_report_{ts}.pdf'
    if os.path.exists(path):
        return send_file(path, as_attachment=True,
                         download_name=f'CyberSentinel_Report_{ts}.pdf')
    return 'Report not found', 404

# SINGLE ENTRY POINT
if __name__ == '__main__':
    os.makedirs('/reports', exist_ok=True)
    print("🔥 Scanner started on port 9000...")
    app.run(host='0.0.0.0', port=9000, debug=True)
