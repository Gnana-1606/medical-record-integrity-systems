"""Academic Medical Record Integrity System.
Uses SQLite transactions, SHA-256 record hashes, a deterministic Merkle tree,
version history, role-based authorization, audit events and a safe tamper demo.
Demo only: do not use real patient data or deploy publicly without a security review.
"""
from flask import Flask, render_template, render_template_string, request, redirect, url_for, session, flash, abort, send_file
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from pathlib import Path
import sqlite3, hashlib, json, os, csv, io, secrets, hmac
from datetime import datetime, timezone

BASE=Path(__file__).resolve().parent
DB_PATH=Path(os.environ.get('MEDICAL_DB_PATH', BASE/'data'/'medical_records.db'))
CSV_PATH=BASE/'data'/'medical_records_clean_final.csv'
FIELDS=['Record_ID','Patient_ID','Name','Age','Gender','Blood_Group','Diagnosis','Prescription','Doctor','Hospital_ID','Visit_Year','Discharge_Status','Version']
EDITABLE={'Diagnosis','Prescription','Doctor','Discharge_Status'}
app=Flask(__name__)
app.secret_key=os.environ.get('FLASK_SECRET_KEY') or 'DEMO-ONLY-change-this-secret-before-use-'+secrets.token_hex(16)
app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE='Lax', MAX_CONTENT_LENGTH=2*1024*1024)


def now(): return datetime.now(timezone.utc).isoformat(timespec='seconds')
def canonical(record): return json.dumps({k:str(record.get(k,'') if record.get(k) is not None else '').strip() for k in FIELDS},sort_keys=True,separators=(',',':'),ensure_ascii=False)
def digest(record): return hashlib.sha256(canonical(record).encode()).hexdigest()
def db():
    con=sqlite3.connect(DB_PATH, timeout=20)
    con.row_factory=sqlite3.Row
    con.execute('PRAGMA foreign_keys=ON')
    return con

def merkle_root(pairs):
    hashes=[h for _,h in sorted(pairs)]
    if not hashes: return hashlib.sha256(b'EMPTY-MERKLE-TREE').hexdigest(), []
    levels=[hashes[:]]; cur=hashes[:]
    while len(cur)>1:
        if len(cur)%2: cur.append(cur[-1])
        cur=[hashlib.sha256((cur[i]+cur[i+1]).encode()).hexdigest() for i in range(0,len(cur),2)]
        levels.append(cur)
    return cur[0],levels

def audit(con, actor, action, record_id='', outcome='success', details=''):
    con.execute('INSERT INTO audit_events(ts,actor,action,record_id,outcome,details) VALUES(?,?,?,?,?,?)',(now(),actor,action,record_id,outcome,details[:1000]))

def init_db():
    DB_PATH.parent.mkdir(parents=True,exist_ok=True)
    with db() as con:
        con.executescript('''
        CREATE TABLE IF NOT EXISTS records(record_id TEXT PRIMARY KEY, patient_id TEXT NOT NULL, data_json TEXT NOT NULL, trusted_hash TEXT NOT NULL, version INTEGER NOT NULL, updated_at TEXT NOT NULL, updated_by TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS versions(id INTEGER PRIMARY KEY AUTOINCREMENT, record_id TEXT NOT NULL, version INTEGER NOT NULL, ts TEXT NOT NULL, actor TEXT NOT NULL, data_json TEXT NOT NULL, record_hash TEXT NOT NULL, change_summary TEXT NOT NULL, UNIQUE(record_id,version));
        CREATE TABLE IF NOT EXISTS audit_events(id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT NOT NULL, actor TEXT NOT NULL, action TEXT NOT NULL, record_id TEXT, outcome TEXT NOT NULL, details TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS app_meta(key TEXT PRIMARY KEY,value TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS users(username TEXT PRIMARY KEY,password_hash TEXT NOT NULL,role TEXT NOT NULL,active INTEGER NOT NULL DEFAULT 1);
        CREATE TABLE IF NOT EXISTS login_security(username TEXT PRIMARY KEY, failures INTEGER NOT NULL DEFAULT 0, window_start REAL NOT NULL DEFAULT 0, locked_until REAL NOT NULL DEFAULT 0);
        CREATE TABLE IF NOT EXISTS security_alerts(id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT NOT NULL, type TEXT NOT NULL, severity TEXT NOT NULL, username TEXT NOT NULL DEFAULT '', record_id TEXT NOT NULL DEFAULT '', message TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'OPEN', resolution TEXT NOT NULL DEFAULT '');
        CREATE TABLE IF NOT EXISTS record_locks(record_id TEXT PRIMARY KEY, locked_at TEXT NOT NULL, locked_by TEXT NOT NULL, reason TEXT NOT NULL);
        ''')
        # Demo accounts are initialized only if absent. Change them for any non-demo use.
        if not con.execute('SELECT 1 FROM users LIMIT 1').fetchone():
            con.executemany('INSERT INTO users(username,password_hash,role) VALUES(?,?,?)',[
                ('doctor',generate_password_hash(os.environ.get('DEMO_DOCTOR_PASSWORD','doctor123')),'doctor'),
                ('auditor',generate_password_hash(os.environ.get('DEMO_AUDITOR_PASSWORD','auditor123')),'auditor'),
                ('admin',generate_password_hash(os.environ.get('DEMO_ADMIN_PASSWORD','admin123')),'admin')])
        if not con.execute('SELECT 1 FROM records LIMIT 1').fetchone():
            if not CSV_PATH.exists(): raise FileNotFoundError(f'Dataset not found: {CSV_PATH}')
            with CSV_PATH.open(newline='',encoding='utf-8-sig') as f:
                for row in csv.DictReader(f):
                    row={k:str(row.get(k,'') or '').strip() for k in FIELDS}
                    rid=row['Record_ID']
                    if not rid: continue
                    rh=digest(row); ts=now()
                    con.execute('INSERT INTO records VALUES(?,?,?,?,?,?,?)',(rid,row['Patient_ID'],json.dumps(row,ensure_ascii=False),rh,int(row.get('Version') or 1),ts,'dataset-import'))
                    con.execute('INSERT OR IGNORE INTO versions(record_id,version,ts,actor,data_json,record_hash,change_summary) VALUES(?,?,?,?,?,?,?)',(rid,int(row.get('Version') or 1),ts,'dataset-import',json.dumps(row,ensure_ascii=False),rh,'Initial imported record'))
            audit(con,'system','dataset_import','','success',f'Imported {con.execute("SELECT COUNT(*) FROM records").fetchone()[0]} records')
        rebuild_root(con)

def rebuild_root(con):
    pairs=[(r['record_id'],r['trusted_hash']) for r in con.execute('SELECT record_id,trusted_hash FROM records ORDER BY record_id')]
    root,levels=merkle_root(pairs)
    con.execute("INSERT INTO app_meta(key,value) VALUES('trusted_merkle_root',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",(root,))
    con.execute("INSERT INTO app_meta(key,value) VALUES('merkle_levels',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",(json.dumps(levels),))
    return root

def add_security_alert(con, kind, message, username='', record_id='', severity='HIGH'):
    con.execute("INSERT INTO security_alerts(ts,type,severity,username,record_id,message,status) VALUES(?,?,?,?,?,?,'OPEN')",
                (now(),kind,severity,username or '',record_id or '',str(message)[:1000]))
    audit(con, username or 'system', 'security_alert', record_id or '', 'created', f'{kind}: {message}')

def is_record_locked(con, record_id):
    return con.execute('SELECT 1 FROM record_locks WHERE record_id=?', (record_id,)).fetchone() is not None

def lock_record(con, record_id, reason, actor='system'):
    con.execute('INSERT INTO record_locks(record_id,locked_at,locked_by,reason) VALUES(?,?,?,?) ON CONFLICT(record_id) DO UPDATE SET locked_at=excluded.locked_at,locked_by=excluded.locked_by,reason=excluded.reason',
                (record_id, now(), actor, str(reason)[:1000]))
    audit(con, actor, 'record_locked', record_id, 'success', reason)

def login_lock_remaining(con, username):
    row=con.execute('SELECT locked_until FROM login_security WHERE username=?',(username,)).fetchone()
    if row and float(row['locked_until']) > __import__('time').time():
        return int(float(row['locked_until'])-__import__('time').time())
    return 0

def register_failed_login(con, username):
    import time
    ts=time.time(); row=con.execute('SELECT * FROM login_security WHERE username=?',(username,)).fetchone()
    if row and ts-float(row['window_start']) <= 300:
        failures=int(row['failures'])+1; start=float(row['window_start'])
    else:
        failures=1; start=ts
    locked_until=ts+300 if failures >= 5 else 0
    con.execute('INSERT INTO login_security(username,failures,window_start,locked_until) VALUES(?,?,?,?) ON CONFLICT(username) DO UPDATE SET failures=excluded.failures,window_start=excluded.window_start,locked_until=excluded.locked_until',(username,failures,start,locked_until))
    if failures >= 5:
        add_security_alert(con,'ACCOUNT_LOCKOUT','Account temporarily locked after five failed login attempts within five minutes.',username=username,severity='HIGH')
        audit(con,username,'account_lockout','','blocked','Temporary 5-minute lockout')

def clear_failed_logins(con, username):
    con.execute('DELETE FROM login_security WHERE username=?',(username,))

def current_user(): return session.get('username')
def login_required(fn):
    @wraps(fn)
    def wrapped(*a,**kw):
        if not current_user():
            flash('Please log in to continue.','warning'); return redirect(url_for('login',next=request.path))
        return fn(*a,**kw)
    return wrapped
def roles_required(*roles):
    def deco(fn):
        @wraps(fn)
        @login_required
        def wrapped(*a,**kw):
            if session.get('role') not in roles: abort(403)
            return fn(*a,**kw)
        return wrapped
    return deco

def csrf_check():
    token=request.form.get('_csrf','')
    if not token or not hmac.compare_digest(token,session.get('_csrf','')): abort(400,'Invalid form token. Refresh and try again.')
def csrf_token():
    if '_csrf' not in session: session['_csrf']=secrets.token_urlsafe(32)
    return session['_csrf']
app.jinja_env.globals['csrf_token']=csrf_token

@app.context_processor
def inject_user(): return {'logged_user':current_user(),'user_role':session.get('role')}

@app.route('/')
def home():
    if current_user(): return redirect(url_for('dashboard'))
    return render_template('home.html')

@app.route('/login',methods=['GET','POST'])
def login():
    if request.method=='POST':
        csrf_check(); username=request.form.get('username','').strip(); password=request.form.get('password','')
        with db() as con:
            remaining=login_lock_remaining(con, username or 'unknown')
            if remaining > 0:
                audit(con,username or 'unknown','login_blocked','','failure',f'Account locked for approximately {remaining} more seconds')
                flash(f'Temporarily locked after repeated failed attempts. Try again in about {remaining} seconds.','danger')
                return render_template('login.html'), 429
            user=con.execute('SELECT * FROM users WHERE username=? AND active=1',(username,)).fetchone()
            if user and check_password_hash(user['password_hash'],password):
                clear_failed_logins(con, username)
                session.clear(); session['username']=username; session['role']=user['role']; session['_csrf']=secrets.token_urlsafe(32)
                audit(con,username,'login','','success','Authenticated')
                return redirect(url_for('dashboard'))
            audit(con,username or 'unknown','login','','failure','Invalid credentials')
            register_failed_login(con, username or 'unknown')
        flash('Invalid username or password. Repeated failures trigger a temporary lockout.','danger')
    return render_template('login.html')

@app.route('/logout',methods=['POST'])
@login_required
def logout():
    csrf_check(); who=current_user()
    with db() as con: audit(con,who,'logout','','success','Session ended')
    session.clear(); flash('You have been logged out.','success'); return redirect(url_for('home'))

@app.route('/dashboard')
@login_required
def dashboard():
    with db() as con:
        total=con.execute('SELECT COUNT(*) FROM records').fetchone()[0]
        versions=con.execute('SELECT COUNT(*) FROM versions').fetchone()[0]
        events=con.execute('SELECT COUNT(*) FROM audit_events').fetchone()[0]
        verified=0; failed=0
        for r in con.execute('SELECT data_json,trusted_hash FROM records'):
            if digest(json.loads(r['data_json']))==r['trusted_hash']: verified+=1
            else: failed+=1
        root=con.execute("SELECT value FROM app_meta WHERE key='trusted_merkle_root'").fetchone()['value']
        actual,_=merkle_root([(r['record_id'],r['trusted_hash']) for r in con.execute('SELECT record_id,trusted_hash FROM records')])
        recent=con.execute('SELECT * FROM audit_events ORDER BY id DESC LIMIT 6').fetchall()
    return render_template('dashboard.html',total=total,verified=verified,failed=failed,versions=versions,events=events,root=root,root_ok=(root==actual),recent=recent)

@app.route('/patients')
@app.route('/search')
@login_required
def patients():
    q=request.args.get('q','').strip()
    rows=[]
    with db() as con:
        if q:
            rows=con.execute("SELECT * FROM records WHERE record_id=? OR patient_id=? OR patient_id LIKE ? ORDER BY patient_id,record_id LIMIT 250",(q,q,f'%{q}%')).fetchall()
        else: rows=con.execute('SELECT * FROM records ORDER BY record_id LIMIT 100').fetchall()
    items=[{**dict(r),'data':json.loads(r['data_json'])} for r in rows]
    return render_template('patients.html',items=items,q=q)

@app.route('/patient/<record_id>')
@login_required
def patient_detail(record_id):
    with db() as con:
        r=con.execute('SELECT * FROM records WHERE record_id=?',(record_id,)).fetchone()
        if not r: abort(404)
        data=json.loads(r['data_json']); computed=digest(data)
        root=con.execute("SELECT value FROM app_meta WHERE key='trusted_merkle_root'").fetchone()['value']
        actual,_=merkle_root([(x['record_id'],x['trusted_hash']) for x in con.execute('SELECT record_id,trusted_hash FROM records')])
        audit(con,current_user(),'view_record',record_id,'success','Record detail viewed')
    return render_template('patient_detail.html',r=r,data=data,computed=computed,hash_ok=(computed==r['trusted_hash']),root=root,root_ok=(root==actual))

@app.route('/verify/<record_id>',methods=['GET','POST'])
@login_required
def verify(record_id):
    with db() as con:
        r=con.execute('SELECT * FROM records WHERE record_id=?',(record_id,)).fetchone()
        if not r: abort(404)
        data=json.loads(r['data_json']); computed=digest(data); hash_ok=hmac.compare_digest(computed,r['trusted_hash'])
        trusted_root=con.execute("SELECT value FROM app_meta WHERE key='trusted_merkle_root'").fetchone()['value']
        calculated_root,_=merkle_root([(x['record_id'],x['trusted_hash']) for x in con.execute('SELECT record_id,trusted_hash FROM records')])
        root_ok=hmac.compare_digest(trusted_root,calculated_root)
        ok=hash_ok and root_ok
        if not ok:
            reason=f'Integrity mismatch during verification: hash_match={hash_ok}; root_match={root_ok}'
            lock_record(con,record_id,reason,current_user() or 'system')
            add_security_alert(con,'RECORD_INTEGRITY_MISMATCH','Possible tampering detected. Record edits have been locked pending admin investigation.',username=current_user() or '',record_id=record_id,severity='CRITICAL')
        audit(con,current_user(),'verify_record',record_id,'success' if ok else 'failure',f'hash_match={hash_ok}; root_match={root_ok}')
    return render_template('verify.html',r=r,data=data,computed=computed,hash_ok=hash_ok,trusted_root=trusted_root,calculated_root=calculated_root,root_ok=root_ok,ok=ok)

@app.route('/edit/<record_id>',methods=['GET','POST'])
@roles_required('doctor','admin')
def edit_record(record_id):
    with db() as con:
        r=con.execute('SELECT * FROM records WHERE record_id=?',(record_id,)).fetchone()
        if not r: abort(404)
        data=json.loads(r['data_json'])
        if is_record_locked(con, record_id):
            audit(con,current_user(),'edit_blocked_locked_record',record_id,'blocked','Record locked after an integrity alert')
            flash('This record is locked because of a security alert. An administrator must investigate and unlock it.','danger')
            return redirect(url_for('patient_detail',record_id=record_id))
        if request.method=='POST':
            csrf_check(); changed=[]; newdata=dict(data)
            for field in EDITABLE:
                val=request.form.get(field,data.get(field,'' )).strip()
                if val!=str(data.get(field,'')): newdata[field]=val; changed.append(field)
            if not changed:
                flash('No changes detected.','info'); return redirect(url_for('patient_detail',record_id=record_id))
            newver=int(r['version'])+1; newdata['Version']=str(newver); rh=digest(newdata); ts=now()
            # Transaction: preserve old state then update current state and root atomically.
            con.execute('INSERT INTO versions(record_id,version,ts,actor,data_json,record_hash,change_summary) VALUES(?,?,?,?,?,?,?)',(record_id,newver,ts,current_user(),json.dumps(newdata,ensure_ascii=False),rh,', '.join(changed)))
            con.execute('UPDATE records SET patient_id=?,data_json=?,trusted_hash=?,version=?,updated_at=?,updated_by=? WHERE record_id=?',(newdata['Patient_ID'],json.dumps(newdata,ensure_ascii=False),rh,newver,ts,current_user(),record_id))
            rebuild_root(con); audit(con,current_user(),'edit_record',record_id,'success',f'version={newver}; changed={", ".join(changed)}')
            flash(f'Record saved as version {newver}.','success'); return redirect(url_for('patient_detail',record_id=record_id))
    return render_template('edit.html',r=r,data=data)

@app.route('/history/<record_id>')
@login_required
def history(record_id):
    with db() as con:
        if not con.execute('SELECT 1 FROM records WHERE record_id=?',(record_id,)).fetchone(): abort(404)
        rows=con.execute('SELECT * FROM versions WHERE record_id=? ORDER BY version DESC',(record_id,)).fetchall()
    return render_template('history.html',record_id=record_id,rows=rows)

@app.route('/restore/<record_id>/<int:version>',methods=['POST'])
@roles_required('doctor','admin')
def restore(record_id,version):
    csrf_check()
    with db() as con:
        old=con.execute('SELECT * FROM versions WHERE record_id=? AND version=?',(record_id,version)).fetchone()
        cur=con.execute('SELECT * FROM records WHERE record_id=?',(record_id,)).fetchone()
        if not old or not cur: abort(404)
        olddata=json.loads(old['data_json']); current=json.loads(cur['data_json']); newver=int(cur['version'])+1
        restored=dict(olddata); restored['Version']=str(newver); rh=digest(restored); ts=now()
        changed=[k for k in FIELDS if str(current.get(k,''))!=str(restored.get(k,'')) and k!='Version']
        con.execute('INSERT INTO versions(record_id,version,ts,actor,data_json,record_hash,change_summary) VALUES(?,?,?,?,?,?,?)',(record_id,newver,ts,current_user(),json.dumps(restored,ensure_ascii=False),rh,f'Restored from version {version}; changed: {", ".join(changed)}'))
        con.execute('UPDATE records SET data_json=?,trusted_hash=?,version=?,updated_at=?,updated_by=? WHERE record_id=?',(json.dumps(restored,ensure_ascii=False),rh,newver,ts,current_user(),record_id))
        rebuild_root(con); audit(con,current_user(),'restore_version',record_id,'success',f'restored_from={version}; created_version={newver}')
    flash(f'Restored version {version} as new version {newver}.','success'); return redirect(url_for('history',record_id=record_id))

@app.route('/tamper-demo',methods=['GET','POST'])
@roles_required('doctor','admin')
def tamper_demo():
    result=None
    if request.method=='POST':
        csrf_check(); action=request.form.get('action','safe_demo')
        rid=request.form.get('record_id','').strip(); field=request.form.get('field','Prescription').strip()
        if field not in FIELDS or field in {'Record_ID','Patient_ID','Version'}:
            flash('Choose a supported mutable field.','danger'); return redirect(url_for('tamper_demo'))
        with db() as con:
            r=con.execute('SELECT * FROM records WHERE record_id=?',(rid,)).fetchone()
            if not r: flash('Record ID not found.','danger'); return redirect(url_for('tamper_demo'))
            original=json.loads(r['data_json']); trusted=r['trusted_hash']; altered=dict(original)
            altered[field]=str(original.get(field,''))+' [UNAUTHORIZED TEST CHANGE]'
            altered_hash=digest(altered); detected=not hmac.compare_digest(altered_hash,trusted)
            if action == 'lock_demo':
                # Create an isolated TEST record, then simulate a direct database edit
                # without updating its trusted hash. Never alter the selected real record.
                demo_id='DEMOLOCK_'+secrets.token_hex(4).upper()
                demo_original=dict(original); demo_original['Record_ID']=demo_id
                demo_original['Patient_ID']='DEMO-ONLY'
                demo_original['Version']='1'
                demo_trusted=digest(demo_original)
                demo_altered=dict(demo_original)
                demo_altered[field]=str(demo_original.get(field,''))+' [SIMULATED UNAUTHORIZED CHANGE]'
                ts=now()
                con.execute('INSERT INTO records(record_id,patient_id,data_json,trusted_hash,version,updated_at,updated_by) VALUES(?,?,?,?,?,?,?)',
                            (demo_id,'DEMO-ONLY',json.dumps(demo_altered,ensure_ascii=False),demo_trusted,1,ts,'security-demo'))
                con.execute('INSERT INTO versions(record_id,version,ts,actor,data_json,record_hash,change_summary) VALUES(?,?,?,?,?,?,?)',
                            (demo_id,1,ts,'security-demo',json.dumps(demo_original,ensure_ascii=False),demo_trusted,'Disposable security test record; trusted baseline'))
                rebuild_root(con)
                reason=f'Simulated unauthorized change to test-only record field {field}; trusted hash retained.'
                lock_record(con,demo_id,reason,current_user() or 'system')
                add_security_alert(con,'RECORD_INTEGRITY_MISMATCH','Integrity mismatch detected in disposable test record. Record locked pending admin investigation.',username=current_user() or '',record_id=demo_id,severity='CRITICAL')
                audit(con,current_user(),'tamper_lock_demo',demo_id,'detected',reason)
                result={'record_id':demo_id,'field':field,'before':demo_original.get(field,''),'after':demo_altered[field],
                        'trusted_hash':demo_trusted,'altered_hash':digest(demo_altered),'detected':True,
                        'original_unchanged':True,'lock_demo':True}
            else:
                audit(con,current_user(),'tamper_simulation',rid,'detected' if detected else 'failure',f'isolated_copy_only; field={field}; mismatch={detected}')
                if detected:
                    add_security_alert(con,'TAMPER_DEMO_DETECTED','Safe tamper demonstration detected a modified disposable copy. Original database record was not changed.',username=current_user() or '',record_id=rid,severity='HIGH')
                result={'record_id':rid,'field':field,'before':original.get(field,''),'after':altered[field],'trusted_hash':trusted,'altered_hash':altered_hash,'detected':detected,'original_unchanged':digest(json.loads(con.execute('SELECT data_json FROM records WHERE record_id=?',(rid,)).fetchone()['data_json']))==trusted,'lock_demo':False}
    return render_template('tamper.html',result=result)

@app.route('/merkle')
@login_required
def merkle():
    with db() as con:
        pairs=[(r['record_id'],r['trusted_hash']) for r in con.execute('SELECT record_id,trusted_hash FROM records ORDER BY record_id')]
        root,levels=merkle_root(pairs); trusted=con.execute("SELECT value FROM app_meta WHERE key='trusted_merkle_root'").fetchone()['value']
    shown=[{'level':i,'count':len(l),'hashes':l[:16],'truncated':len(l)>16} for i,l in enumerate(levels)]
    return render_template('merkle.html',root=root,trusted=trusted,root_ok=root==trusted,levels=shown,total=len(pairs))

@app.route('/audit')
@roles_required('auditor','admin')
def audit_log():
    with db() as con: rows=con.execute('SELECT * FROM audit_events ORDER BY id DESC LIMIT 500').fetchall()
    return render_template('audit.html',rows=rows)

@app.route('/report/<record_id>')
@login_required
def report(record_id):
    with db() as con:
        r=con.execute('SELECT * FROM records WHERE record_id=?',(record_id,)).fetchone()
        if not r: abort(404)
        data=json.loads(r['data_json']); calculated=digest(data); ok=calculated==r['trusted_hash']
        root=con.execute("SELECT value FROM app_meta WHERE key='trusted_merkle_root'").fetchone()['value']
        actual,_=merkle_root([(x['record_id'],x['trusted_hash']) for x in con.execute('SELECT record_id,trusted_hash FROM records')])
        audit(con,current_user(),'integrity_report',record_id,'success','Report generated')
    body='MEDICAL RECORD INTEGRITY REPORT\n'+'='*34+'\n'+f'Generated UTC: {now()}\nRecord ID: {record_id}\nPatient ID: {data.get("Patient_ID","")}\nVersion: {r["version"]}\nRecord SHA-256: {calculated}\nTrusted SHA-256: {r["trusted_hash"]}\nRecord hash match: {ok}\nMerkle Root: {actual}\nTrusted root match: {root==actual}\nOverall status: {"VERIFIED" if ok and root==actual else "INTEGRITY FAILURE"}\n\nAcademic demonstration only; not for clinical use.\n'
    return send_file(io.BytesIO(body.encode()),mimetype='text/plain',as_attachment=True,download_name=f'integrity_report_{record_id}.txt')

@app.route('/admin/users',methods=['GET','POST'])
@roles_required('admin')
def manage_users():
    if request.method=='POST':
        csrf_check(); username=request.form.get('username','').strip(); password=request.form.get('password',''); role=request.form.get('role','')
        if not username or len(password)<12 or role not in {'doctor','auditor','admin'}:
            flash('Use a username, a password of at least 12 characters, and a valid role.','danger')
        else:
            with db() as con:
                con.execute('INSERT INTO users(username,password_hash,role,active) VALUES(?,?,?,1) ON CONFLICT(username) DO UPDATE SET password_hash=excluded.password_hash,role=excluded.role,active=1',(username,generate_password_hash(password),role))
                audit(con,current_user(),'manage_user','','success',f'account={username}; role={role}')
            flash('User saved.','success')
    with db() as con: users=con.execute('SELECT username,role,active FROM users ORDER BY username').fetchall()
    return render_template('users.html',users=users)

@app.route('/admin/security')
@roles_required('admin')
def admin_security():
    with db() as con:
        alerts=con.execute("SELECT * FROM security_alerts ORDER BY id DESC LIMIT 200").fetchall()
        locks=con.execute('SELECT * FROM record_locks ORDER BY locked_at DESC').fetchall()
        events=con.execute('SELECT * FROM audit_events ORDER BY id DESC LIMIT 100').fetchall()
    return render_template_string("""<!doctype html><html><head><meta charset='utf-8'><title>Security Monitoring</title>
    <style>body{font-family:Arial;max-width:1100px;margin:30px auto;padding:0 18px;color:#172033}table{width:100%;border-collapse:collapse;margin:12px 0 28px}th,td{padding:9px;border-bottom:1px solid #ddd;text-align:left;vertical-align:top}th{background:#eef2f7}.critical{color:#b91c1c;font-weight:bold}.btn{padding:7px 10px;background:#173b67;color:white;border:0;border-radius:5px}input{padding:7px}a{color:#1756a9}</style></head><body>
    <p><a href='{{ url_for("dashboard") }}'>← Dashboard</a> | <a href='{{ url_for("manage_users") }}'>Manage users</a> | <a href='{{ url_for("audit_log") }}'>Audit log</a></p>
    <h1>Security Monitoring</h1><p>Open alerts: <b>{{ alerts|selectattr('status','equalto','OPEN')|list|length }}</b> · Locked records: <b>{{ locks|length }}</b></p>
    <h2>Security alerts</h2>{% for a in alerts %}<section style='border:1px solid #ddd;border-radius:8px;padding:12px;margin:10px 0'><b class='{{ "critical" if a.severity=="CRITICAL" else "" }}'>{{ a.severity }} — {{ a.type }}</b><p>{{ a.message }}</p><small>{{ a.ts }} | user={{ a.username or '-' }} | record={{ a.record_id or '-' }} | status={{ a.status }}</small>
    {% if a.status=='OPEN' %}<form method='post' action='{{ url_for("resolve_security_alert", alert_id=a.id) }}'><input type='hidden' name='_csrf' value='{{ csrf_token() }}'><input name='resolution' placeholder='Investigation result' required><button class='btn'>Resolve alert</button></form>{% endif %}</section>{% else %}<p>No alerts.</p>{% endfor %}
    <h2>Locked records</h2><table><tr><th>Record</th><th>Reason</th><th>Locked at</th><th>Action</th></tr>{% for l in locks %}<tr><td>{{ l.record_id }}</td><td>{{ l.reason }}</td><td>{{ l.locked_at }}</td><td><form method='post' action='{{ url_for("unlock_security_record", record_id=l.record_id) }}'><input type='hidden' name='_csrf' value='{{ csrf_token() }}'><input name='reason' placeholder='Why safe to unlock?' required><button class='btn'>Unlock</button></form>{% if l.record_id.startswith('DEMOLOCK_') %}<form method='post' action='{{ url_for("delete_demo_record", record_id=l.record_id) }}' onsubmit='return confirm("Delete this disposable demo record?")'><input type='hidden' name='_csrf' value='{{ csrf_token() }}'><button class='btn' style='background:#9b1c1c;margin-top:6px'>Delete demo record</button></form>{% endif %}</td></tr>{% else %}<tr><td colspan='4'>No locked records.</td></tr>{% endfor %}</table>
    <h2>Recent audit events</h2><table><tr><th>Time</th><th>Actor</th><th>Action</th><th>Record</th><th>Outcome</th><th>Details</th></tr>{% for e in events %}<tr><td>{{ e.ts }}</td><td>{{ e.actor }}</td><td>{{ e.action }}</td><td>{{ e.record_id or '-' }}</td><td>{{ e.outcome }}</td><td>{{ e.details }}</td></tr>{% endfor %}</table></body></html>""", alerts=alerts, locks=locks, events=events)

@app.route('/admin/security/resolve/<int:alert_id>', methods=['POST'])
@roles_required('admin')
def resolve_security_alert(alert_id):
    csrf_check(); resolution=request.form.get('resolution','').strip()
    if not resolution: abort(400)
    with db() as con:
        cur=con.execute("UPDATE security_alerts SET status='RESOLVED',resolution=? WHERE id=? AND status='OPEN'",(resolution[:1000],alert_id))
        audit(con,current_user(),'resolve_security_alert','', 'success' if cur.rowcount else 'failure',f'alert_id={alert_id}; resolution={resolution}')
    flash('Alert resolution saved.','success'); return redirect(url_for('admin_security'))

@app.route('/admin/security/unlock/<record_id>', methods=['POST'])
@roles_required('admin')
def unlock_security_record(record_id):
    csrf_check(); reason=request.form.get('reason','').strip()
    if not reason: abort(400)
    with db() as con:
        con.execute('DELETE FROM record_locks WHERE record_id=?',(record_id,))
        audit(con,current_user(),'record_unlocked',record_id,'success',f'Admin review: {reason[:900]}')
        add_security_alert(con,'RECORD_UNLOCKED','Administrator unlocked the record after review: '+reason,username=current_user() or '',record_id=record_id,severity='MEDIUM')
    flash('Record unlocked; action recorded in audit log.','success'); return redirect(url_for('admin_security'))

@app.route('/admin/security/delete-demo/<record_id>',methods=['POST'])
@roles_required('admin')
def delete_demo_record(record_id):
    csrf_check()
    if not record_id.startswith('DEMOLOCK_'):
        abort(400, 'Only disposable DEMOLOCK_ records can be deleted here.')
    with db() as con:
        exists=con.execute('SELECT 1 FROM records WHERE record_id=?',(record_id,)).fetchone()
        if not exists: abort(404)
        con.execute('DELETE FROM versions WHERE record_id=?',(record_id,))
        con.execute('DELETE FROM record_locks WHERE record_id=?',(record_id,))
        con.execute('DELETE FROM records WHERE record_id=?',(record_id,))
        rebuild_root(con)
        audit(con,current_user(),'delete_demo_record',record_id,'success','Disposable security test record removed after demonstration')
    flash('Disposable security test record deleted. Original patient records were not changed.','success')
    return redirect(url_for('admin_security'))

@app.errorhandler(403)
def forbidden(e): return render_template('error.html',code=403,message='You do not have permission to access this page.'),403
@app.errorhandler(404)
def not_found(e): return render_template('error.html',code=404,message='The requested page or record was not found.'),404
@app.errorhandler(400)
def bad_request(e): return render_template('error.html',code=400,message=getattr(e,'description','Invalid request.')),400

init_db()
if __name__=='__main__':
    app.run(host='0.0.0.0',port=int(os.environ.get('PORT','5000')),debug=False)
