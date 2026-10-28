import os, re, csv, io, json, sqlite3, hashlib, hmac, base64, secrets, smtplib, html, uuid, shutil, logging
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage
from pathlib import Path
from typing import Optional

from dotenv import load_dotenv
from fastapi import FastAPI, Request, HTTPException, Depends, UploadFile, File, Form
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field, EmailStr
import qrcode
try:
    import cv2
    import numpy as np
except Exception:
    cv2 = None
    np = None
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import A4, landscape
from reportlab.lib.utils import ImageReader

BASE = Path(__file__).resolve().parent
load_dotenv(BASE / '.env')
DB = Path(os.getenv('COMPESA_DB_PATH', str(BASE / 'data' / 'compesa.db'))).expanduser()
STATIC = BASE / 'static'
UPLOADS = BASE / 'uploads'
ASSETS = STATIC / 'assets'
SECRET = os.getenv('COMPESA_SECRET', 'compesa-local-development-secret-change-me').encode()
DEV_RESET = os.getenv('COMPESA_DEV_RESET', 'true').lower() == 'true'

app = FastAPI(title='COMPESA Event Intelligence Platform', version='2.0.0')
app.mount('/static', StaticFiles(directory=STATIC), name='static')
app.mount('/uploads', StaticFiles(directory=UPLOADS), name='uploads')

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger('compesa')
BACKUPS = DB.parent / 'backups'


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    # Catch anything a route didn't already handle so the person always gets a
    # clean JSON error instead of a raw server crash/traceback.
    logger.exception('Unhandled error on %s %s', request.method, request.url.path)
    return JSONResponse(status_code=500, content={'detail': 'Something went wrong on the server. Please try again. If this keeps happening, tell the admin what you were doing.'})


def now():
    return datetime.now(timezone.utc).isoformat()


def db():
    DB.parent.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(DB, timeout=30)
    con.row_factory = sqlite3.Row
    con.execute('PRAGMA foreign_keys=ON')
    con.execute('PRAGMA busy_timeout=30000')
    con.execute('PRAGMA journal_mode=WAL')
    con.execute('PRAGMA synchronous=NORMAL')
    return con


def hash_pw(pw, salt=None):
    salt = salt or secrets.token_bytes(16)
    key = hashlib.pbkdf2_hmac('sha256', pw.encode(), salt, 180000)
    return salt.hex() + ':' + key.hex()


def check_pw(pw, stored):
    try:
        s, k = stored.split(':')
        key = hashlib.pbkdf2_hmac('sha256', pw.encode(), bytes.fromhex(s), 180000)
        return hmac.compare_digest(key.hex(), k)
    except Exception:
        return False


def token(payload):
    raw = json.dumps(payload, separators=(',', ':')).encode()
    b = base64.urlsafe_b64encode(raw).decode().rstrip('=')
    sig = hmac.new(SECRET, b.encode(), hashlib.sha256).hexdigest()
    return b + '.' + sig


def decode_token(t):
    try:
        b, s = t.rsplit('.', 1)
        exp = hmac.new(SECRET, b.encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(s, exp):
            return None
        raw = base64.urlsafe_b64decode(b + '=' * (-len(b) % 4))
        p = json.loads(raw)
        if p.get('exp', 0) < datetime.now().timestamp():
            return None
        return p
    except Exception:
        return None


def auth(request: Request):
    t = request.headers.get('Authorization', '').replace('Bearer ', '')
    p = decode_token(t) if t else None
    if not p:
        raise HTTPException(401, 'Authentication required')
    con = db()
    u = con.execute('select * from users where id=?', (p['uid'],)).fetchone()
    con.close()
    if not u:
        raise HTTPException(401, 'User not found')
    return dict(u)


def role_ok(user, roles):
    if user['role'] not in roles:
        raise HTTPException(403, 'Permission denied')


def audit(user, action, target='', detail=''):
    con = db()
    con.execute('insert into audit_logs(user_id,action,target,detail,created_at) values(?,?,?,?,?)',
                (user['id'], action, target, detail, now()))
    con.commit(); con.close()


def notify(uid, title, body, kind='SYSTEM'):
    con = db()
    con.execute('insert into notifications(user_id,title,body,kind,created_at,read) values(?,?,?,?,?,0)',
                (uid, title, body, kind, now()))
    con.commit(); con.close()


def public_user(u):
    return {k: u[k] for k in [
        'id','email','notification_email','name','prn','department','year','division',
        'role','phone','photo','skills','interests','privacy','points'
    ] if k in u}


def init_db():
    DB.parent.mkdir(exist_ok=True)
    UPLOADS.mkdir(exist_ok=True)
    ASSETS.mkdir(exist_ok=True)
    con = db(); c = con.cursor()
    c.executescript('''
    create table if not exists users(
      id integer primary key autoincrement,
      email text unique,password text,name text,prn text,department text,year text,division text,
      role text default 'student',phone text,photo text,skills text default '',interests text default '',
      privacy text default 'college',points integer default 0,notification_email text default '',created_at text
    );
    create table if not exists events(
      id integer primary key autoincrement,name text,description text,category text,date text,start_time text,end_time text,
      venue text,max_participants integer,team_size integer default 1,fee real default 0,deadline text,rules text,
      coordinators text,status text default 'OPEN',organization text default 'COMPESA',created_at text
    );
    create table if not exists registrations(
      id integer primary key autoincrement,reg_code text unique,user_id integer,event_id integer,team_id integer,
      status text,qr_token text,created_at text,approved_at text,payment_mode text default 'OFFLINE',payment_status text default 'NOT_REQUIRED',payment_reference text default '',unique(user_id,event_id)
    );
    create table if not exists teams(id integer primary key autoincrement,event_id integer,name text,invite_code text unique,leader_id integer,created_at text);
    create table if not exists team_members(id integer primary key autoincrement,team_id integer,user_id integer,role text,unique(team_id,user_id));
    create table if not exists notifications(id integer primary key autoincrement,user_id integer,title text,body text,kind text,created_at text,read integer default 0);
    create table if not exists certificates(id integer primary key autoincrement,cert_id text unique,user_id integer,event_id integer,issued_at text,hash text,public integer default 1,file_path text,source text default 'generated');
    create table if not exists results(id integer primary key autoincrement,event_id integer,user_id integer,position text,score real,mention text);
    create table if not exists attendance(id integer primary key autoincrement,event_id integer,user_id integer,scanned_at text,method text,unique(event_id,user_id));
    create table if not exists feedback(id integer primary key autoincrement,event_id integer,user_id integer,content text,rating integer,created_at text,unique(event_id,user_id));
    create table if not exists audit_logs(id integer primary key autoincrement,user_id integer,action text,target text,detail text,created_at text);
    create table if not exists email_logs(id integer primary key autoincrement,registration_id integer,user_id integer,to_email text,subject text,status text,error text,sent_at text,created_at text);
    create table if not exists venues(id integer primary key autoincrement,name text,building text,floor text,room text,capacity integer,facilities text,available integer default 1,address text default '',maps_url text default '',latitude real,longitude real);
    create table if not exists problems(id integer primary key autoincrement,event_id integer,title text,difficulty text,statement text,points integer default 100);
    create table if not exists submissions(id integer primary key autoincrement,problem_id integer,user_id integer,language text,code text,status text,score real,submitted_at text);
    create table if not exists password_resets(id integer primary key autoincrement,user_id integer,token_hash text unique,expires_at text,used integer default 0,created_at text);
    create table if not exists event_announcements(id integer primary key autoincrement,event_id integer,title text,body text,created_at text,created_by integer);
    create table if not exists volunteers(id integer primary key autoincrement,name text,employee_prn text,email text,phone text,department text,event_id integer,position text,responsibilities text,shift text,status text default 'ACTIVE',notes text,created_at text,updated_at text);
    ''')
    # Lightweight migrations for databases created by older versions.
    for col, typ in [('notification_email','text default ""'),('photo','text'),('file_path','text'),('source','text default "generated"')]:
        try: c.execute(f'alter table users add column {col} {typ}') if col in ('notification_email','photo') else c.execute(f'alter table certificates add column {col} {typ}')
        except sqlite3.OperationalError: pass
    for table, cols in {
        'registrations':[('payment_mode','text default "OFFLINE"'),('payment_status','text default "NOT_REQUIRED"'),('payment_reference','text default ""')],
        'events':[('live_status','text default "SCHEDULED"'),('live_title','text default ""'),('live_venue','text default ""'),('live_date','text default ""'),('live_start_time','text default ""'),('live_end_time','text default ""'),('current_round','text default ""'),('live_instructions','text default ""'),('emergency_message','text default ""'),('poster_path','text default ""'),('banner_path','text default ""')],
        'venues':[('address','text default ""'),('maps_url','text default ""'),('latitude','real'),('longitude','real')]
    }.items():
        for col, typ in cols:
            try: c.execute(f'alter table {table} add column {col} {typ}')
            except sqlite3.OperationalError: pass

    if not c.execute('select 1 from users limit 1').fetchone():
        users = [
            ('admin@compesa.local','Admin User','ADMIN001','Computer Engineering','3','A','super_admin','9876543210','Python,Java,React,AI','Coding,AI,Hackathon','admin@compesa.local'),
            ('coordinator@compesa.local','Event Coordinator','COORD001','Computer Engineering','4','A','event_coordinator','9876543211','Python,Event Management','Hackathon,Workshop','coordinator@compesa.local'),
            ('student@compesa.local','Rahul Patil','23CSE001','Computer Engineering','3','A','student','9876543212','Python,Java,React,AI/ML,Backend','Coding,AI,Hackathon,Workshop','student@compesa.local')
        ]
        for email,name,prn,dept,yr,div,role,phone,skills,interests,gmail in users:
            c.execute('insert into users(email,password,name,prn,department,year,division,role,phone,skills,interests,notification_email,created_at) values(?,?,?,?,?,?,?,?,?,?,?,?,?)',
                      (email,hash_pw('Compesa@123'),name,prn,dept,yr,div,role,phone,skills,interests,gmail,now()))
    else:
        try:
            c.execute("update users set notification_email=email where coalesce(notification_email,'')='' ")
        except Exception: pass
    if not c.execute('select 1 from events limit 1').fetchone():
        c.execute('insert into events(name,description,category,date,start_time,end_time,venue,max_participants,team_size,fee,deadline,rules,coordinators,created_at) values(?,?,?,?,?,?,?,?,?,?,?,?,?,?)',
                  ('CodeSprint 2026','Inter-college coding competition with live leaderboard.','Coding Competition','2026-10-10','10:00','16:00','Computer Lab 3',100,2,0,'2026-10-09T23:59','Bring college ID. Teams max 2. Fair-play rules apply.','Event Coordinator',now()))
        eid=c.lastrowid
        c.execute('insert into problems(event_id,title,difficulty,statement,points) values(?,?,?,?,?)',(eid,'Two Sum','Easy','Given an array and target, return indices of two numbers whose sum is target.',100))
        c.execute('insert into problems(event_id,title,difficulty,statement,points) values(?,?,?,?,?)',(eid,'Graph Paths','Medium','Find the number of paths from source to destination in a directed acyclic graph.',200))
    if not c.execute('select 1 from venues limit 1').fetchone():
        for v in [('Lab 1','Block A','1','A-101',60,'Computers,Wi-Fi,Projector'),('Lab 2','Block A','1','A-102',60,'Computers,Wi-Fi'),('Seminar Hall','Block B','2','B-201',120,'Projector,Audio,AC'),('Auditorium','Main Block','Ground','G-001',500,'Projector,Audio,Stage')]:
            c.execute('insert into venues(name,building,floor,room,capacity,facilities) values(?,?,?,?,?,?)',v)
    con.commit(); con.close()


init_db()


def _snapshot_db(dest: Path):
    """Make a consistent copy of the live database using SQLite's own backup API.
    Safe to call even while the server is running in WAL mode."""
    dest.parent.mkdir(parents=True, exist_ok=True)
    src_con = sqlite3.connect(DB)
    dest_con = sqlite3.connect(dest)
    with dest_con:
        src_con.backup(dest_con)
    src_con.close(); dest_con.close()


def _backup(tag='manual', keep=10):
    BACKUPS.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')
    dest = BACKUPS / f'compesa_{tag}_{stamp}.db'
    _snapshot_db(dest)
    for old in sorted(BACKUPS.glob(f'compesa_{tag}_*.db'))[:-keep]:
        try: old.unlink()
        except Exception: pass
    return dest


try:
    # A free safety net: snapshot the database every time the app boots, so an
    # admin mistake or a bad redeploy never loses more than "since the last boot".
    # This does NOT protect against the hosting disk itself being wiped on a free
    # plan (see README) — use Admin > Database (or /api/admin/backup) for that.
    _backup('startup', keep=5)
except Exception:
    logger.exception('Automatic startup database backup failed')


class Login(BaseModel):
    email: str
    password: str

class StudentRegister(BaseModel):
    name: str
    prn: str
    email: str
    notification_email: str
    department: str
    year: str
    division: str
    phone: str
    password: str
    skills: str = ''
    interests: str = ''

class ForgotPassword(BaseModel):
    email: str

class ResetPassword(BaseModel):
    token: str
    password: str

class AdminRecover(BaseModel):
    email: str
    recovery_key: str
    new_password: str

class EventFeeIn(BaseModel):
    fee: float = Field(default=0, ge=0)


class EventIn(BaseModel):
    name: str; description: str=''; category: str='Workshop'; date: str; start_time: str='10:00'; end_time: str='12:00';
    venue: str=''; max_participants: int=50; team_size: int=1; fee: float=0; deadline: str=''; rules: str=''; coordinators: str=''

class EventLiveIn(BaseModel):
    live_status: str='SCHEDULED'; live_title: str=''; live_venue: str=''; live_date: str=''; live_start_time: str=''; live_end_time: str=''; current_round: str=''; live_instructions: str=''; emergency_message: str=''

class VenueIn(BaseModel):
    name: str; building: str=''; floor: str=''; room: str=''; capacity: int=0; facilities: str=''; available: bool=True; address: str=''; maps_url: str=''; latitude: Optional[float]=None; longitude: Optional[float]=None

class VolunteerIn(BaseModel):
    name: str; employee_prn: str=''; email: str=''; phone: str=''; department: str=''; event_id: Optional[int]=None; position: str='Coordinator'; responsibilities: str=''; shift: str=''; status: str='ACTIVE'; notes: str=''

class ProfileIn(BaseModel):
    name: str; prn: str=''; department: str=''; year: str=''; division: str=''; phone: str=''; skills: str=''; interests: str=''; privacy: str='college'; notification_email: str=''

class StatusIn(BaseModel): status: str
class FeedbackIn(BaseModel): rating: int=5; content: str=''
class TeamIn(BaseModel): event_id: int; name: str
class JoinTeam(BaseModel): invite_code: str
class ResultIn(BaseModel): event_id: int; user_id: int; position: str; score: float=0; mention: str=''
class SubmitIn(BaseModel): problem_id: int; language: str='python'; code: str
class Announcement(BaseModel): title: str; body: str; event_id: Optional[int]=None


@app.get('/', response_class=HTMLResponse)
def home(): return (STATIC/'index.html').read_text(encoding='utf8')

@app.get('/manifest.json')
def manifest(): return FileResponse(STATIC/'manifest.json')

@app.get('/service-worker.js')
def sw(): return FileResponse(STATIC/'service-worker.js')


@app.post('/api/auth/login')
def login(x: Login):
    con=db(); u=con.execute('select * from users where lower(email)=lower(?) or lower(notification_email)=lower(?)',(x.email.strip(),x.email.strip())).fetchone(); con.close()
    if not u or not check_pw(x.password,u['password']): raise HTTPException(401,'Invalid email or password')
    return {'token':token({'uid':u['id'],'exp':(datetime.now()+timedelta(days=2)).timestamp()}),'user':public_user(dict(u))}

@app.post('/api/auth/register')
def student_register(x: StudentRegister):
    if len(x.password) < 8: raise HTTPException(400,'Password must be at least 8 characters')
    if not re.fullmatch(r'\d{10}', x.phone.strip()): raise HTTPException(400,'Enter a valid 10-digit student contact number')
    if not re.fullmatch(r'[^@\s]+@[^@\s]+\.[^@\s]+', x.notification_email): raise HTTPException(400,'Enter a valid Gmail/notification email')
    con=db()
    if con.execute('select 1 from users where lower(email)=lower(?) or lower(notification_email)=lower(?)',(x.email.strip(),x.notification_email.strip())).fetchone(): con.close(); raise HTTPException(409,'Email already registered')
    if con.execute('select 1 from users where lower(prn)=lower(?)',(x.prn.strip(),)).fetchone(): con.close(); raise HTTPException(409,'PRN/Roll No. already registered')
    cur=con.execute('insert into users(email,password,name,prn,department,year,division,role,phone,skills,interests,notification_email,created_at) values(?,?,?,?,?,?,?,?,?,?,?,?,?)',
                    (x.email.strip(),hash_pw(x.password),x.name.strip(),x.prn.strip(),x.department.strip(),x.year.strip(),x.division.strip(),'student',x.phone.strip(),x.skills.strip(),x.interests.strip(),x.notification_email.strip(),now()))
    uid=cur.lastrowid; con.commit(); con.close()
    return {'message':'Student account created','user_id':uid}

@app.post('/api/auth/forgot-password')
def forgot_password(x: ForgotPassword, request: Request):
    con=db(); u=con.execute('select * from users where lower(email)=lower(?) or lower(notification_email)=lower(?)',(x.email.strip(),x.email.strip())).fetchone()
    # Always return a generic message to avoid account enumeration.
    if not u:
        con.close(); return {'message':'If the account exists, a password reset link has been prepared.'}
    raw=secrets.token_urlsafe(32); th=hashlib.sha256(raw.encode()).hexdigest(); exp=datetime.now(timezone.utc)+timedelta(minutes=30)
    con.execute('insert into password_resets(user_id,token_hash,expires_at,created_at) values(?,?,?,?)',(u['id'],th,exp.isoformat(),now())); con.commit(); con.close()
    reset_url=str(request.base_url).rstrip('/')+f'/?reset={raw}'
    subject='COMPESA Password Reset Request'
    text=f'Hello {u["name"]},\n\nA password reset was requested for your COMPESA account.\nReset link: {reset_url}\n\nThis link expires in 30 minutes. If you did not request it, ignore this email.'
    html_body=f'''<div style="font-family:Arial;max-width:600px;margin:auto;padding:30px;background:#fff"><h2 style="color:#1267e8">COMPESA Password Reset</h2><p>Hello <b>{html.escape(u['name'])}</b>,</p><p>A password reset was requested for your account.</p><p><a href="{reset_url}" style="display:inline-block;padding:12px 18px;background:#168cff;color:#fff;text-decoration:none;border-radius:8px">Reset Password</a></p><p style="color:#64748b">This link expires in 30 minutes.</p></div>'''
    sent=False; error=''
    if smtp_configured(): sent,error=send_compesa_email(u['notification_email'] or u['email'],subject,html_body,text)
    result={'message':'If the account exists, a password reset link has been prepared.','email_sent':sent}
    if DEV_RESET and not sent: result['development_reset_url']=reset_url
    return result

@app.post('/api/auth/reset-password')
def reset_password(x: ResetPassword):
    if len(x.password)<8: raise HTTPException(400,'Password must be at least 8 characters')
    th=hashlib.sha256(x.token.encode()).hexdigest(); con=db(); r=con.execute('select * from password_resets where token_hash=? and used=0 order by id desc limit 1',(th,)).fetchone()
    if not r or datetime.fromisoformat(r['expires_at']) < datetime.now(timezone.utc): con.close(); raise HTTPException(400,'Reset link is invalid or expired')
    con.execute('update users set password=? where id=?',(hash_pw(x.password),r['user_id'])); con.execute('update password_resets set used=1 where id=?',(r['id'],)); con.commit(); con.close(); return {'message':'Password changed successfully. You can now log in.'}

@app.post('/api/auth/admin-recover-password')
def admin_recover_password(x: AdminRecover):
    """Emergency account recovery that does not depend on email/SMTP at all.
    Disabled unless COMPESA_ADMIN_RECOVERY_KEY is set in the environment — set it
    once, keep it secret, and use it only if you are locked out of every account
    and cannot receive a reset email."""
    recovery_key = os.getenv('COMPESA_ADMIN_RECOVERY_KEY', '')
    if not recovery_key:
        raise HTTPException(503, 'Admin recovery is not turned on for this server. Set COMPESA_ADMIN_RECOVERY_KEY in your .env to enable it.')
    if not hmac.compare_digest(x.recovery_key.encode(), recovery_key.encode()):
        raise HTTPException(401, 'Incorrect recovery key')
    if len(x.new_password) < 8:
        raise HTTPException(400, 'Password must be at least 8 characters')
    con = db()
    u = con.execute('select * from users where lower(email)=lower(?) or lower(notification_email)=lower(?)', (x.email.strip(), x.email.strip())).fetchone()
    if not u:
        con.close(); raise HTTPException(404, 'No account found with that email')
    con.execute('update users set password=? where id=?', (hash_pw(x.new_password), u['id']))
    con.commit(); con.close()
    audit({'id': u['id']}, 'ADMIN_RECOVERY_RESET', str(u['id']), f'Password reset via recovery key for {u["email"]}')
    return {'message': f'Password for {u["email"]} has been reset. You can log in now.'}

@app.get('/api/auth/me')
def me(user=Depends(auth)): return public_user(user)


@app.get('/api/dashboard')
def dashboard(user=Depends(auth)):
    role_ok(user,['super_admin','event_admin','event_coordinator','volunteer'])
    con=db()
    data={k:con.execute(q).fetchone()[0] for k,q in {
        'students':"select count(*) from users where role='student'",'events':'select count(*) from events',
        'upcoming':"select count(*) from events where date>=date('now')",'registrations':'select count(*) from registrations',
        'pending':"select count(*) from registrations where status='PENDING'",'certificates':'select count(*) from certificates',
        'attendance':'select count(*) from attendance','revenue':"select coalesce(sum(e.fee),0) from registrations r join events e on e.id=r.event_id where r.status='APPROVED'"
    }.items()}
    cats=[dict(r) for r in con.execute('select category,count(*) count from events group by category order by count desc').fetchall()]
    months=[dict(r) for r in con.execute("select substr(created_at,1,7) month,count(*) count from registrations group by month order by month").fetchall()]
    depts=[dict(r) for r in con.execute("select department,count(*) count from registrations r join users u on u.id=r.user_id group by department order by count desc").fetchall()]
    con.close(); return {**data,'categories':cats,'months':months,'departments':depts}


def _remove_event_image(path):
    if not path: return
    try:
        rel = str(path).lstrip('/').replace('\\','/')
        if rel.startswith('uploads/'):
            target = BASE / rel
            if target.exists() and target.is_file(): target.unlink()
    except Exception:
        pass


def _validate_image(upload: UploadFile):
    allowed = {'image/jpeg','image/png','image/webp','image/gif'}
    if upload.content_type not in allowed:
        raise HTTPException(400, 'Only JPG, PNG, WEBP or GIF images are allowed')


async def _save_event_image(upload: UploadFile, eid: int, kind: str):
    _validate_image(upload)
    ext = Path(upload.filename or '').suffix.lower()
    if ext not in {'.jpg','.jpeg','.png','.webp','.gif'}:
        ext = '.jpg' if upload.content_type == 'image/jpeg' else '.png'
    data = await upload.read()
    if len(data) > 8 * 1024 * 1024:
        raise HTTPException(400, 'Image must be 8 MB or smaller')
    name = f'event_{eid}_{kind}_{uuid.uuid4().hex}{ext}'
    path = UPLOADS / name
    path.write_bytes(data)
    return f'/uploads/{name}'


@app.get('/api/public/events')
def public_events():
    con=db(); rows=con.execute("select id,name,description,category,date,start_time,end_time,venue,status,poster_path,banner_path from events order by date,start_time").fetchall(); con.close(); return [dict(r) for r in rows]

@app.get('/api/public/results')
def public_results():
    con=db(); rows=con.execute("select r.position,r.score,r.mention,u.name,e.name event_name,e.date from results r join users u on u.id=r.user_id join events e on e.id=r.event_id order by e.date desc,r.score desc limit 100").fetchall(); con.close(); return [dict(r) for r in rows]

@app.get('/api/events')
def events(q:str='',category:str='',user=Depends(auth)):
    con=db(); rows=con.execute('select * from events where name like ? and category like ? order by date,start_time',(f'%{q}%',f'%{category}%')).fetchall(); out=[]
    for e in rows:
        d=dict(e)
        if user['role']=='student':
            # Students never receive participant counts or raw capacity/registration lists.
            d.pop('max_participants',None); d.pop('team_size',None)
            d['availability']='Open' if d['status']=='OPEN' else d['status'].title(); d['team_enabled']=bool(e['team_size'] and e['team_size']>1)
        out.append(d)
    con.close(); return out

@app.post('/api/events')
def create_event(x:EventIn,user=Depends(auth)):
    role_ok(user,['super_admin','event_admin','event_coordinator']); con=db()
    conflict=con.execute("select id from events where date=? and venue=? and start_time < ? and end_time > ?",(x.date,x.venue,x.end_time,x.start_time)).fetchone()
    if conflict: con.close(); raise HTTPException(409,'Venue conflict: another event overlaps this time slot')
    cur=con.execute('insert into events(name,description,category,date,start_time,end_time,venue,max_participants,team_size,fee,deadline,rules,coordinators,created_at) values(?,?,?,?,?,?,?,?,?,?,?,?,?,?)',
                    (x.name,x.description,x.category,x.date,x.start_time,x.end_time,x.venue,x.max_participants,x.team_size,x.fee,x.deadline,x.rules,x.coordinators or user['name'],now()))
    eid=cur.lastrowid; con.commit(); con.close(); audit(user,'CREATE_EVENT',str(eid),x.name); return {'id':eid,'message':'Event created'}

@app.delete('/api/events/{eid}')
def delete_event(eid:int,user=Depends(auth)):
    role_ok(user,['super_admin','event_admin'])
    con=db()
    try:
        event=con.execute('select id,name,poster_path,banner_path from events where id=?',(eid,)).fetchone()
        if not event:
            raise HTTPException(404,'Event not found')
        # Remove dependent records first because the existing schema predates
        # foreign-key cascades. Everything is committed as one transaction.
        con.execute('delete from email_logs where registration_id in (select id from registrations where event_id=?)',(eid,))
        con.execute('delete from team_members where team_id in (select id from teams where event_id=?)',(eid,))
        con.execute('delete from registrations where event_id=?',(eid,))
        con.execute('delete from teams where event_id=?',(eid,))
        con.execute('delete from certificates where event_id=?',(eid,))
        con.execute('delete from results where event_id=?',(eid,))
        con.execute('delete from attendance where event_id=?',(eid,))
        con.execute('delete from feedback where event_id=?',(eid,))
        con.execute('delete from event_announcements where event_id=?',(eid,))
        con.execute('delete from volunteers where event_id=?',(eid,))
        problem_ids=[r[0] for r in con.execute('select id from problems where event_id=?',(eid,)).fetchall()]
        if problem_ids:
            marks=','.join('?' for _ in problem_ids)
            con.execute(f'delete from submissions where problem_id in ({marks})',problem_ids)
        con.execute('delete from problems where event_id=?',(eid,))
        con.execute('delete from events where id=?',(eid,))
        con.commit()
        _remove_event_image(event['poster_path'])
        _remove_event_image(event['banner_path'])
    except HTTPException:
        con.rollback(); con.close(); raise
    except Exception:
        con.rollback(); con.close(); raise
    con.close()
    audit(user,'DELETE_EVENT',str(eid),event['name'])
    return {'message':'Event deleted successfully','event_id':eid}


@app.post('/api/events/{eid}/images')
async def update_event_images(eid:int, poster: UploadFile | None = File(None), banner: UploadFile | None = File(None), user=Depends(auth)):
    role_ok(user,['super_admin','event_admin','event_coordinator'])
    con=db(); e=con.execute('select id,poster_path,banner_path from events where id=?',(eid,)).fetchone()
    if not e:
        con.close(); raise HTTPException(404,'Event not found')
    old_poster=e['poster_path']; old_banner=e['banner_path']
    try:
        poster_path = old_poster
        banner_path = old_banner
        if poster and poster.filename:
            poster_path = await _save_event_image(poster,eid,'poster')
        if banner and banner.filename:
            banner_path = await _save_event_image(banner,eid,'banner')
        con.execute('update events set poster_path=?,banner_path=? where id=?',(poster_path,banner_path,eid))
        con.commit()
    except HTTPException:
        con.rollback(); con.close(); raise
    except Exception:
        con.rollback(); con.close(); raise
    con.close()
    if poster and poster.filename and old_poster and old_poster != poster_path: _remove_event_image(old_poster)
    if banner and banner.filename and old_banner and old_banner != banner_path: _remove_event_image(old_banner)
    audit(user,'UPDATE_EVENT_IMAGES',str(eid),'Poster/banner updated')
    return {'message':'Event images updated','poster_path':poster_path,'banner_path':banner_path}


@app.put('/api/events/{eid}')
def update_event(eid:int,x:EventIn,user=Depends(auth)):
    role_ok(user,['super_admin','event_admin','event_coordinator']); con=db()
    exists=con.execute('select id from events where id=?',(eid,)).fetchone()
    if not exists: con.close(); raise HTTPException(404,'Event not found')
    conflict=con.execute("select id from events where id!=? and date=? and venue=? and start_time < ? and end_time > ?",(eid,x.date,x.venue,x.end_time,x.start_time)).fetchone()
    if conflict: con.close(); raise HTTPException(409,'Venue conflict: another event overlaps this time slot')
    con.execute('update events set name=?,description=?,category=?,date=?,start_time=?,end_time=?,venue=?,max_participants=?,team_size=?,fee=?,deadline=?,rules=?,coordinators=? where id=?',(x.name,x.description,x.category,x.date,x.start_time,x.end_time,x.venue,x.max_participants,x.team_size,x.fee,x.deadline,x.rules,x.coordinators or user['name'],eid)); con.commit(); con.close(); audit(user,'UPDATE_EVENT',str(eid),x.name); return {'message':'Event updated'}

@app.patch('/api/events/{eid}/fee')
def update_event_fee(eid:int,x:EventFeeIn,user=Depends(auth)):
    role_ok(user,['super_admin','event_admin','event_coordinator'])
    con=db()
    exists=con.execute('select name from events where id=?',(eid,)).fetchone()
    if not exists:
        con.close(); raise HTTPException(404,'Event not found')
    con.execute('update events set fee=? where id=?',(float(x.fee),eid))
    con.commit(); con.close()
    audit(user,'UPDATE_EVENT_FEE',str(eid),f'{exists["name"]}: ₹{float(x.fee):.2f}')
    return {'message':'Event fee updated','fee':float(x.fee)}


@app.patch('/api/events/{eid}/live')
def update_live_event(eid:int,x:EventLiveIn,user=Depends(auth)):
    role_ok(user,['super_admin','event_admin','event_coordinator']);
    if x.live_status.upper() not in ('SCHEDULED','LIVE','PAUSED','ENDED'): raise HTTPException(400,'Invalid live status')
    con=db(); e=con.execute('select * from events where id=?',(eid,)).fetchone()
    if not e: con.close(); raise HTTPException(404,'Event not found')
    con.execute('update events set live_status=?,live_title=?,live_venue=?,live_date=?,live_start_time=?,live_end_time=?,current_round=?,live_instructions=?,emergency_message=? where id=?',(x.live_status.upper(),x.live_title,x.live_venue,x.live_date,x.live_start_time,x.live_end_time,x.current_round,x.live_instructions,x.emergency_message,eid)); con.commit(); con.close()
    if x.emergency_message or x.live_status.upper()=='LIVE':
        con=db(); ids=[r[0] for r in con.execute('select distinct user_id from registrations where event_id=? and status in (\'APPROVED\',\'COMPLETED\')',(eid,)).fetchall()]; con.close()
        body=x.emergency_message or f'{x.live_title or e["name"]} is now LIVE.'
        for uid in ids: notify(uid,f'🔴 {x.live_title or e["name"]}',body,'LIVE_EVENT')
    audit(user,'UPDATE_LIVE_EVENT',str(eid),f'{x.live_status}; round={x.current_round}')
    return {'message':'Live event updated'}

@app.get('/api/events/{eid}/live')
def get_live_event(eid:int,user=Depends(auth)):
    con=db(); e=con.execute('select * from events where id=?',(eid,)).fetchone();
    if not e: con.close(); raise HTTPException(404,'Event not found')
    if user['role']=='student':
        reg=con.execute("select 1 from registrations where event_id=? and user_id=? and status in ('APPROVED','COMPLETED')",(eid,user['id'])).fetchone()
        if not reg: con.close(); raise HTTPException(403,'Live event details are available only to registered students')
    d={k:e[k] for k in ['id','name','venue','date','start_time','end_time','live_status','live_title','live_venue','live_date','live_start_time','live_end_time','current_round','live_instructions','emergency_message']}; con.close(); return d

@app.post('/api/venues')
def create_venue(x:VenueIn,user=Depends(auth)):
    role_ok(user,['super_admin','event_admin','event_coordinator']); con=db(); cur=con.execute('insert into venues(name,building,floor,room,capacity,facilities,available,address,maps_url,latitude,longitude) values(?,?,?,?,?,?,?,?,?,?,?)',(x.name,x.building,x.floor,x.room,x.capacity,x.facilities,int(x.available),x.address,x.maps_url,x.latitude,x.longitude)); con.commit(); vid=cur.lastrowid; con.close(); audit(user,'CREATE_VENUE',str(vid),x.name); return {'id':vid,'message':'Venue created'}

@app.patch('/api/venues/{vid}')
def update_venue(vid:int,x:VenueIn,user=Depends(auth)):
    role_ok(user,['super_admin','event_admin','event_coordinator']); con=db();
    if not con.execute('select id from venues where id=?',(vid,)).fetchone(): con.close(); raise HTTPException(404,'Venue not found')
    con.execute('update venues set name=?,building=?,floor=?,room=?,capacity=?,facilities=?,available=?,address=?,maps_url=?,latitude=?,longitude=? where id=?',(x.name,x.building,x.floor,x.room,x.capacity,x.facilities,int(x.available),x.address,x.maps_url,x.latitude,x.longitude,vid)); con.commit(); con.close(); audit(user,'UPDATE_VENUE',str(vid),x.name); return {'message':'Venue updated'}

@app.delete('/api/venues/{vid}')
def delete_venue(vid:int,user=Depends(auth)):
    role_ok(user,['super_admin','event_admin','event_coordinator']); con=db();
    if con.execute('select 1 from events where venue=(select name from venues where id=?)',(vid,)).fetchone(): con.close(); raise HTTPException(409,'Venue is assigned to an event and cannot be removed')
    con.execute('delete from venues where id=?',(vid,)); con.commit(); con.close(); audit(user,'DELETE_VENUE',str(vid),'Venue removed'); return {'message':'Venue removed'}

@app.get('/api/volunteers')
def volunteers(user=Depends(auth)):
    role_ok(user,['super_admin','event_admin','event_coordinator']); con=db(); rows=con.execute("select v.*,e.name event_name from volunteers v left join events e on e.id=v.event_id order by v.created_at desc").fetchall(); con.close(); return [dict(r) for r in rows]

@app.post('/api/volunteers')
def create_volunteer(x:VolunteerIn,user=Depends(auth)):
    role_ok(user,['super_admin','event_admin','event_coordinator']); con=db(); cur=con.execute('insert into volunteers(name,employee_prn,email,phone,department,event_id,position,responsibilities,shift,status,notes,created_at,updated_at) values(?,?,?,?,?,?,?,?,?,?,?,?,?)',(x.name,x.employee_prn,x.email,x.phone,x.department,x.event_id,x.position,x.responsibilities,x.shift,x.status,x.notes,now(),now())); con.commit(); vid=cur.lastrowid; con.close(); audit(user,'CREATE_VOLUNTEER',str(vid),f'{x.name} / {x.position}'); return {'id':vid,'message':'Volunteer added'}

@app.patch('/api/volunteers/{vid}')
def update_volunteer(vid:int,x:VolunteerIn,user=Depends(auth)):
    role_ok(user,['super_admin','event_admin','event_coordinator']); con=db();
    if not con.execute('select id from volunteers where id=?',(vid,)).fetchone(): con.close(); raise HTTPException(404,'Volunteer not found')
    con.execute('update volunteers set name=?,employee_prn=?,email=?,phone=?,department=?,event_id=?,position=?,responsibilities=?,shift=?,status=?,notes=?,updated_at=? where id=?',(x.name,x.employee_prn,x.email,x.phone,x.department,x.event_id,x.position,x.responsibilities,x.shift,x.status,x.notes,now(),vid)); con.commit(); con.close(); audit(user,'UPDATE_VOLUNTEER',str(vid),f'{x.name} / {x.position}'); return {'message':'Volunteer updated'}

@app.delete('/api/volunteers/{vid}')
def delete_volunteer(vid:int,user=Depends(auth)):
    role_ok(user,['super_admin','event_admin','event_coordinator']); con=db(); con.execute('delete from volunteers where id=?',(vid,)); con.commit(); con.close(); audit(user,'DELETE_VOLUNTEER',str(vid),'Volunteer removed'); return {'message':'Volunteer removed'}

@app.get('/api/events/{eid}')
def event(eid:int,user=Depends(auth)):
    con=db(); e=con.execute('select * from events where id=?',(eid,)).fetchone()
    if not e: con.close(); raise HTTPException(404,'Event not found')
    d={'event':dict(e)}
    if user['role']!='student':
        regs=con.execute("select r.*,u.name,u.email,u.notification_email,u.prn,u.department,u.year,u.division from registrations r join users u on u.id=r.user_id where r.event_id=? order by r.created_at desc",(eid,)).fetchall()
        d['registrations']=[dict(r) for r in regs]
    con.close(); return d


@app.post('/api/registrations/{eid}')
def register(eid:int, team_id: Optional[int]=None, payment_mode: str='OFFLINE', payment_reference: str='', user=Depends(auth)):
    role_ok(user,['student']); con=db(); e=con.execute('select * from events where id=?',(eid,)).fetchone()
    if not e: con.close(); raise HTTPException(404,'Event not found')
    if e['deadline'] and e['deadline'] < now(): con.close(); raise HTTPException(400,'Registration deadline has passed')
    if con.execute('select 1 from registrations where user_id=? and event_id=?',(user['id'],eid)).fetchone(): con.close(); raise HTTPException(409,'Already registered')
    count=con.execute("select count(*) from registrations where event_id=? and status in ('PENDING','APPROVED')",(eid,)).fetchone()[0]
    status='PENDING' if count < e['max_participants'] else 'WAITLISTED'
    code=f"CMP-{datetime.now().year%100}-{secrets.token_hex(3).upper()}"; qr=secrets.token_urlsafe(32)
    payment_mode=payment_mode.upper() if payment_mode else 'OFFLINE'
    if payment_mode not in ('ONLINE','OFFLINE'): payment_mode='OFFLINE'
    payment_status='PENDING' if payment_mode=='ONLINE' and float(e['fee'] or 0)>0 else ('NOT_REQUIRED' if float(e['fee'] or 0)<=0 else 'PAY_AT_DESK')
    con.execute('insert into registrations(reg_code,user_id,event_id,status,qr_token,created_at,payment_mode,payment_status,payment_reference) values(?,?,?,?,?,?,?,?,?)',(code,user['id'],eid,status,qr,now(),payment_mode,payment_status,payment_reference.strip())); con.commit(); con.close()
    notify(user['id'],'Registration received',f"{e['name']} registration is {status}.",'REGISTRATION')
    return {'status':status,'registration_id':code,'payment_mode':payment_mode,'payment_status':payment_status,'fee':float(e['fee'] or 0)}

@app.get('/api/registrations/me')
def my_regs(user=Depends(auth)):
    con=db(); rows=con.execute('select r.*,e.name event_name,e.category,e.date,e.start_time,e.end_time,e.venue,e.description,e.rules from registrations r join events e on e.id=r.event_id where r.user_id=? order by e.date desc',(user['id'],)).fetchall(); con.close(); return [dict(r) for r in rows]

@app.get('/api/registrations')
def all_regs(status:str='',department:str='',year:str='',division:str='',user=Depends(auth)):
    role_ok(user,['super_admin','event_admin','event_coordinator','volunteer']); con=db()
    rows=con.execute("select r.*,u.name,u.email,u.notification_email,u.prn,u.department,u.year,u.division,e.name event_name,e.category,e.date,e.start_time,e.end_time,e.venue from registrations r join users u on u.id=r.user_id join events e on e.id=r.event_id where r.status like ? and u.department like ? and u.year like ? and u.division like ? order by r.created_at desc",(f'%{status}%',f'%{department}%',f'%{year}%',f'%{division}%')).fetchall(); con.close(); return [dict(r) for r in rows]


def smtp_configured():
    return bool(os.getenv('SMTP_HOST') and os.getenv('SMTP_USER') and os.getenv('SMTP_PASSWORD'))


def send_compesa_email(to_email, subject, html_body, text_body):
    if not smtp_configured(): return False, 'SMTP is not configured. Set SMTP_HOST, SMTP_PORT, SMTP_USER and SMTP_PASSWORD in .env.'
    try:
        msg=EmailMessage(); msg['Subject']=subject; msg['From']=os.getenv('SMTP_FROM',os.getenv('SMTP_USER')); msg['To']=to_email
        msg.set_content(text_body); msg.add_alternative(html_body, subtype='html')
        with smtplib.SMTP(os.getenv('SMTP_HOST','smtp.gmail.com'),int(os.getenv('SMTP_PORT','587')),timeout=25) as s:
            s.ehlo(); s.starttls(); s.ehlo(); s.login(os.getenv('SMTP_USER'),os.getenv('SMTP_PASSWORD')); s.send_message(msg)
        return True,''
    except Exception as ex: return False,f'{type(ex).__name__}: {ex}'


def log_email(registration_id,user_id,to_email,subject,status,error=''):
    con=db(); con.execute('insert into email_logs(registration_id,user_id,to_email,subject,status,error,sent_at,created_at) values(?,?,?,?,?,?,?,?)',(registration_id,user_id,to_email,subject,status,error,now() if status=='SENT' else None,now())); con.commit(); con.close()


def approval_email(user_record,event_record,registration_record):
    student=html.escape(user_record['name']); event=html.escape(event_record['name']); reg=html.escape(registration_record['reg_code'])
    subject=f'🎉 Registration Approved — {event_record["name"]}'
    to_email=user_record.get('notification_email') or user_record['email']
    text=f'''Hello {user_record['name']},\n\nGreat news! Your registration for {event_record['name']} has been approved.\n\nEvent Details\nEvent: {event_record['name']}\nCategory: {event_record['category']}\nDate: {event_record['date']}\nTime: {event_record['start_time']} – {event_record['end_time']}\nVenue: {event_record['venue']}\nRegistration ID: {registration_record['reg_code']}\nStatus: APPROVED\n\nYour event QR code is now active in your COMPESA portal.\n\nRegards,\nCOMPESA Event Management Team'''
    logo='/static/assets/brand.png'
    html_body=f'''<!doctype html><html><body style="margin:0;background:#06101d;font-family:Arial,sans-serif;color:#0f172a"><div style="max-width:660px;margin:30px auto;background:#fff;border-radius:22px;overflow:hidden"><div style="background:#07111f;padding:24px 30px"><img src="{logo}" style="width:290px;max-width:100%;height:auto"><div style="margin-top:20px;color:#8ed8ff;font-size:12px;letter-spacing:2px">REGISTRATION APPROVED</div><h1 style="margin:6px 0;color:#fff;font-size:28px">You are officially registered ✓</h1></div><div style="padding:32px"><p>Hello <b>{student}</b>,</p><p>Great news! Your registration for <b>{event}</b> has been approved by the COMPESA event team.</p><div style="background:#f8fafc;border:1px solid #dbe3ee;border-radius:16px;padding:20px;margin:24px 0"><h3 style="margin-top:0">Event Details</h3><p><b>Event:</b> {event}</p><p><b>Category:</b> {html.escape(event_record['category'])}</p><p><b>Date:</b> {event_record['date']}</p><p><b>Time:</b> {event_record['start_time']} – {event_record['end_time']}</p><p><b>Venue:</b> {html.escape(event_record['venue'])}</p><p><b>Registration ID:</b> {reg}</p><p style="color:#059669"><b>Status: APPROVED</b></p></div><p>Your secure QR pass is now available in your COMPESA student portal. Please open your portal before the event to view it.</p><p>We look forward to seeing you at the event!</p><p>Regards,<br><b>COMPESA Event Management Team</b></p></div><div style="padding:18px 30px;background:#f8fafc;color:#64748b;font-size:12px">Automated notification from COMPESA • Computer Engineering Events</div></div></body></html>'''
    return send_compesa_email(to_email,subject,html_body,text), subject


@app.patch('/api/registrations/{rid}')
def reg_status(rid:int,x:StatusIn,user=Depends(auth)):
    role_ok(user,['super_admin','event_admin','event_coordinator']); status=x.status.upper()
    if status not in ['PENDING','APPROVED','REJECTED','WAITLISTED','COMPLETED']: raise HTTPException(400,'Invalid status')
    con=db(); r=con.execute('select r.*,e.name event_name,e.category,e.date,e.start_time,e.end_time,e.venue,e.max_participants,u.email student_email,u.notification_email,u.name student_name from registrations r join events e on e.id=r.event_id join users u on u.id=r.user_id where r.id=?',(rid,)).fetchone()
    if not r: con.close(); raise HTTPException(404,'Registration not found')
    if status=='APPROVED' and r['status']=='APPROVED': con.close(); return {'message':'Already approved','email_status':'already_sent'}
    con.execute('update registrations set status=?,approved_at=? where id=?',(status,now() if status=='APPROVED' else None,rid)); con.commit(); con.close()
    email_status='not_applicable'; email_error=''
    if status=='APPROVED':
        notify(r['user_id'],'Registration Approved',f"Your registration for {r['event_name']} is approved. Your QR is now active.",'REGISTRATION_APPROVED')
        user_record={'id':r['user_id'],'email':r['student_email'],'notification_email':r['notification_email'],'name':r['student_name']}
        event_record={k:r[k] for k in ['event_name','category','date','start_time','end_time','venue']}; event_record['name']=event_record.pop('event_name')
        (email_result,subject)=approval_email(user_record,event_record,{'reg_code':r['reg_code']}); sent,email_error=email_result
        email_status='sent' if sent else ('not_configured' if 'not configured' in email_error.lower() else 'failed')
        log_email(rid,r['user_id'],r['notification_email'] or r['student_email'],subject,'SENT' if sent else ('NOT_CONFIGURED' if email_status=='not_configured' else 'FAILED'),email_error)
    elif status=='REJECTED': notify(r['user_id'],'Registration Update',f"Your registration for {r['event_name']} was rejected.",'REGISTRATION_REJECTED')
    audit(user,'UPDATE_REGISTRATION',str(rid),f'{status}; email={email_status}')
    return {'message':'Updated','email_status':email_status,'email_error':email_error}

@app.get('/api/communication/status')
def communication_status(user=Depends(auth)):
    role_ok(user,['super_admin','event_admin','event_coordinator']); con=db(); rows=con.execute('select status,count(*) count from email_logs group by status').fetchall(); recent=con.execute('select e.*,u.name student_name from email_logs e join users u on u.id=e.user_id order by e.created_at desc limit 30').fetchall(); con.close(); return {'configured':smtp_configured(),'stats':[dict(r) for r in rows],'recent':[dict(r) for r in recent]}

@app.get('/api/profile')
def profile(user=Depends(auth)): return public_user(user)

@app.put('/api/profile')
def update_profile(x:ProfileIn,user=Depends(auth)):
    if user['role']=='student' and x.notification_email:
        if not re.fullmatch(r'[^@\s]+@[^@\s]+\.[^@\s]+',x.notification_email): raise HTTPException(400,'Invalid notification email')
    con=db(); con.execute('update users set name=?,prn=?,department=?,year=?,division=?,phone=?,skills=?,interests=?,privacy=?,notification_email=? where id=?',
                          (x.name,x.prn,x.department,x.year,x.division,x.phone,x.skills,x.interests,x.privacy,x.notification_email or user['notification_email'],user['id'])); con.commit(); con.close(); return {'message':'Profile updated'}

@app.get('/api/students')
def students(q:str='',department:str='',year:str='',division:str='',user=Depends(auth)):
    role_ok(user,['super_admin','event_admin','event_coordinator']); con=db(); rows=con.execute("select id,name,email,notification_email,prn,department,year,division,phone,points,created_at from users where role='student' and name like ? and department like ? and year like ? and division like ? order by name",(f'%{q}%',f'%{department}%',f'%{year}%',f'%{division}%')).fetchall(); con.close(); return [dict(r) for r in rows]

@app.get('/api/notifications')
def notifications(user=Depends(auth)):
    con=db(); rows=con.execute('select * from notifications where user_id=? order by created_at desc limit 100',(user['id'],)).fetchall(); con.close(); return [dict(r) for r in rows]

@app.patch('/api/notifications/{nid}/read')
def read_notification(nid:int,user=Depends(auth)):
    con=db(); con.execute('update notifications set read=1 where id=? and user_id=?',(nid,user['id'])); con.commit(); con.close(); return {'ok':True}

@app.get('/api/ai/recommendations')
def recommendations(user=Depends(auth)):
    skills=set(x.strip().lower() for x in (user['skills'] or '').split(',') if x.strip()); interests=set(x.strip().lower() for x in (user['interests'] or '').split(',') if x.strip())
    con=db(); events=con.execute('select * from events where date>=date(\'now\') order by date').fetchall(); out=[]
    for e in events:
        words=set(re.findall(r'[a-zA-Z0-9]+',((e['name']+' '+e['category']+' '+e['description']).lower()))); sm=len(skills & words)/max(1,len(skills)); im=len(interests & words)/max(1,len(interests)); dept=1 if user['department'].lower() in e['description'].lower() else 0; score=round(min(99,40*sm+40*im+20*dept),1)
        out.append({'event':{k:e[k] for k in e.keys() if k not in ('max_participants','team_size')},'match':score,'breakdown':{'skills':round(sm*100),'interests':round(im*100),'department':dept*100}})
    con.close(); return sorted(out,key=lambda x:x['match'],reverse=True)

@app.post('/api/teams')
def create_team(x:TeamIn,user=Depends(auth)):
    role_ok(user,['student']); con=db(); e=con.execute('select * from events where id=?',(x.event_id,)).fetchone()
    if not e or e['team_size']<2: con.close(); raise HTTPException(400,'Team registration not enabled')
    code='TEAM-'+secrets.token_hex(3).upper(); con.execute('insert into teams(event_id,name,invite_code,leader_id,created_at) values(?,?,?,?,?)',(x.event_id,x.name,code,user['id'],now())); tid=con.lastrowid; con.execute('insert into team_members(team_id,user_id,role) values(?,?,?)',(tid,user['id'],'leader')); con.commit(); con.close(); return {'team_id':tid,'invite_code':code}

@app.post('/api/teams/join')
def join_team(x:JoinTeam,user=Depends(auth)):
    role_ok(user,['student']); con=db(); t=con.execute('select * from teams where invite_code=?',(x.invite_code.strip(),)).fetchone()
    if not t: con.close(); raise HTTPException(404,'Invite code not found')
    e=con.execute('select team_size from events where id=?',(t['event_id'],)).fetchone(); count=con.execute('select count(*) from team_members where team_id=?',(t['id'],)).fetchone()[0]
    if count>=e['team_size']: con.close(); raise HTTPException(400,'Team is full')
    try: con.execute('insert into team_members(team_id,user_id,role) values(?,?,?)',(t['id'],user['id'],'member')); con.commit()
    except sqlite3.IntegrityError: con.close(); raise HTTPException(409,'Already in team')
    con.close(); return {'message':'Joined team'}

@app.get('/api/qr/{rid}.png')
def qr(rid:int, access_token:str=''):
    user=None
    if access_token:
        p=decode_token(access_token)
        if p:
            con0=db(); u0=con0.execute('select * from users where id=?',(p['uid'],)).fetchone(); con0.close(); user=dict(u0) if u0 else None
    con=db(); r=con.execute('select * from registrations where id=?',(rid,)).fetchone(); con.close()
    if not r: raise HTTPException(404,'Registration not found')
    if not user: raise HTTPException(401,'Authentication required')
    if user['role']=='student' and r['user_id']!=user['id']: raise HTTPException(403,'Forbidden')
    if r['status']!='APPROVED': raise HTTPException(400,'QR becomes active after approval')
    img=qrcode.make(f'COMPESA|REG|{r["reg_code"]}|TOKEN:{r["qr_token"]}'); path=UPLOADS/f'qr_{rid}.png'; img.save(path); return FileResponse(path,media_type='image/png')

@app.post('/api/attendance/scan-image')
async def scan_image(image: UploadFile = File(...), user=Depends(auth)):
    """Decode a QR frame server-side so camera scanning works even when BarcodeDetector is unavailable."""
    role_ok(user,['super_admin','event_coordinator','volunteer'])
    if cv2 is None or np is None:
        raise HTTPException(503,'Camera QR decoder is unavailable on this server')
    data = await image.read()
    if not data or len(data) > 4 * 1024 * 1024:
        raise HTTPException(400,'Invalid camera frame')
    arr = np.frombuffer(data, dtype=np.uint8)
    frame = cv2.imdecode(arr, cv2.IMREAD_COLOR)
    if frame is None:
        raise HTTPException(400,'Could not read camera frame')
    detector = cv2.QRCodeDetector()
    value, points, _ = detector.detectAndDecode(frame)
    if not value:
        raise HTTPException(422,'No QR code detected')
    m = re.search(r'TOKEN:([^|\s]+)', value)
    qr_token = m.group(1) if m else value.strip()
    con=db(); r=con.execute('select * from registrations where qr_token=?',(qr_token,)).fetchone()
    if not r: con.close(); raise HTTPException(404,'Invalid QR token')
    if r['status']!='APPROVED': con.close(); raise HTTPException(400,'Registration is not approved')
    try:
        con.execute('insert into attendance(event_id,user_id,scanned_at,method) values(?,?,?,?)',(r['event_id'],r['user_id'],now(),'CAMERA_QR')); con.commit()
    except sqlite3.IntegrityError:
        con.close(); return {'message':'Already marked','student':r['user_id']}
    con.close(); notify(r['user_id'],'Attendance marked','Your event attendance was recorded successfully.','ATTENDANCE')
    return {'message':'Attendance marked','student':r['user_id']}

@app.post('/api/attendance/scan')
def scan(qr_token:str,user=Depends(auth)):
    role_ok(user,['super_admin','event_coordinator','volunteer']); con=db(); r=con.execute('select * from registrations where qr_token=?',(qr_token,)).fetchone()
    if not r: con.close(); raise HTTPException(404,'Invalid QR token')
    if r['status']!='APPROVED': con.close(); raise HTTPException(400,'Registration is not approved')
    try: con.execute('insert into attendance(event_id,user_id,scanned_at,method) values(?,?,?,?)',(r['event_id'],r['user_id'],now(),'QR')); con.commit()
    except sqlite3.IntegrityError: con.close(); return {'message':'Already marked'}
    con.close(); notify(r['user_id'],'Attendance marked','Your event attendance was recorded successfully.','ATTENDANCE'); return {'message':'Attendance marked'}

@app.get('/api/certificates')
def certs(user=Depends(auth)):
    con=db()
    if user['role']=='student': rows=con.execute('select c.*,u.name,e.name event_name from certificates c join users u on u.id=c.user_id join events e on e.id=c.event_id where c.user_id=? order by issued_at desc',(user['id'],)).fetchall()
    else: rows=con.execute('select c.*,u.name,e.name event_name from certificates c join users u on u.id=c.user_id join events e on e.id=c.event_id order by issued_at desc').fetchall()
    con.close(); return [dict(r) for r in rows]

def cert_hash(cert_id,user_id,event_id,issued): return hashlib.sha256(f'{cert_id}|{user_id}|{event_id}|{issued}'.encode()).hexdigest()

@app.post('/api/certificates/generate/{event_id}/{user_id}')
def gen_cert(event_id:int,user_id:int,user=Depends(auth)):
    role_ok(user,['super_admin','event_admin','event_coordinator']); con=db(); e=con.execute('select * from events where id=?',(event_id,)).fetchone(); u=con.execute('select * from users where id=?',(user_id,)).fetchone()
    if not e or not u: con.close(); raise HTTPException(404,'Not found')
    issued=now(); cid=f'CERT-CMP-{datetime.now().year}-{secrets.token_hex(3).upper()}'; h=cert_hash(cid,user_id,event_id,issued)
    con.execute('insert into certificates(cert_id,user_id,event_id,issued_at,hash,source) values(?,?,?,?,?,?)',(cid,user_id,event_id,issued,h,'generated')); con.commit(); con.close()
    notify(user_id,'Certificate available',f'Your certificate for {e["name"]} is ready. ID: {cid}','CERTIFICATE'); return {'certificate_id':cid}

@app.post('/api/certificates/upload')
async def upload_certificate(event_id:int=Form(...), user_id:int=Form(...), certificate:UploadFile=File(...), user=Depends(auth)):
    role_ok(user,['super_admin','event_admin','event_coordinator']); con=db(); e=con.execute('select * from events where id=?',(event_id,)).fetchone(); u=con.execute('select * from users where id=?',(user_id,)).fetchone(); con.close()
    if not e or not u: raise HTTPException(404,'Student or event not found')
    data=await certificate.read()
    if len(data)>10*1024*1024: raise HTTPException(413,'Certificate file is too large')
    ext=Path(certificate.filename or '').suffix.lower() or '.pdf'
    if ext not in ['.pdf','.png','.jpg','.jpeg']: raise HTTPException(400,'Only PDF/JPG/PNG certificates are allowed')
    cid=f'CERT-CMP-{datetime.now().year}-{secrets.token_hex(3).upper()}'; issued=now(); h=cert_hash(cid,user_id,event_id,issued); path=UPLOADS/f'{cid}{ext}'; path.write_bytes(data)
    con=db(); con.execute('insert into certificates(cert_id,user_id,event_id,issued_at,hash,source,file_path) values(?,?,?,?,?,?,?)',(cid,user_id,event_id,issued,h,'uploaded',str(path.name))); con.commit(); con.close(); notify(user_id,'Certificate available',f'Your uploaded certificate for {e["name"]} is available. ID: {cid}','CERTIFICATE'); audit(user,'UPLOAD_CERTIFICATE',cid,u['name']); return {'certificate_id':cid,'file':f'/uploads/{path.name}'}

@app.get('/api/certificates/verify/{cid}')
def verify(cid:str):
    con=db(); r=con.execute('select c.*,u.name,u.prn,e.name event_name,e.date from certificates c join users u on u.id=c.user_id join events e on e.id=c.event_id where c.cert_id=?',(cid,)).fetchone(); con.close()
    if not r: return {'valid':False}
    valid=hmac.compare_digest(r['hash'],cert_hash(r['cert_id'],r['user_id'],r['event_id'],r['issued_at'])); return {'valid':valid,**dict(r)}

@app.get('/api/certificates/{cid}/pdf')
def cert_pdf(cid:str):
    con=db(); r=con.execute('select c.*,u.name,u.prn,u.department,e.name event_name,e.date from certificates c join users u on u.id=c.user_id join events e on e.id=c.event_id where c.cert_id=?',(cid,)).fetchone(); con.close()
    if not r: raise HTTPException(404,'Certificate not found')
    if r['file_path'] and Path(UPLOADS/r['file_path']).exists(): return FileResponse(UPLOADS/r['file_path'],media_type='application/pdf' if r['file_path'].endswith('.pdf') else 'image/*',filename=r['file_path'])
    path=UPLOADS/f'{cid}.pdf'; c=canvas.Canvas(str(path),pagesize=landscape(A4)); w,h=A4[1],A4[0]
    c.setFillColorRGB(0.03,0.07,0.12); c.rect(0,0,w,h,fill=1,stroke=0); c.setFillColorRGB(0.2,0.65,1); c.rect(35,35,w-70,h-70,fill=0,stroke=1)
    logo=ASSETS/'brand.png'
    if logo.exists(): c.drawImage(str(logo),55,h-95,width=260,height=54,preserveAspectRatio=True,mask='auto')
    c.setFillColorRGB(1,1,1); c.setFont('Helvetica-Bold',30); c.drawCentredString(w/2,h-170,'CERTIFICATE OF PARTICIPATION')
    c.setFont('Helvetica',14); c.drawCentredString(w/2,h-215,'This certifies that')
    c.setFont('Helvetica-Bold',27); c.drawCentredString(w/2,h-260,r['name'])
    c.setFont('Helvetica',13); c.drawCentredString(w/2,h-295,f'PRN: {r["prn"] or "—"}  •  {r["department"] or "Computer Engineering"}')
    c.drawCentredString(w/2,h-335,f'participated in {r["event_name"]}')
    c.setFont('Helvetica',11); c.drawCentredString(w/2,75,f'Certificate ID: {r["cert_id"]}  •  Issued: {r["issued_at"][:10]}  •  Verify at COMPESA portal')
    c.save(); return FileResponse(path,media_type='application/pdf',filename=f'{cid}.pdf')

@app.post('/api/feedback/{event_id}')
def feedback(event_id:int,x:FeedbackIn,user=Depends(auth)):
    if not 1<=x.rating<=5: raise HTTPException(400,'Rating must be 1-5')
    con=db(); con.execute('insert or replace into feedback(event_id,user_id,content,rating,created_at) values(?,?,?,?,?)',(event_id,user['id'],x.content,x.rating,now())); con.commit(); con.close(); return {'message':'Feedback saved'}

@app.get('/api/leaderboard')
def leaderboard(user=Depends(auth)):
    con=db(); rows=con.execute("select name,prn,points,department from users where role='student' order by points desc,name limit 50").fetchall(); con.close(); return [dict(r) for r in rows]

@app.post('/api/results')
def result(x:ResultIn,user=Depends(auth)):
    role_ok(user,['super_admin','event_admin','event_coordinator']); con=db(); con.execute('insert into results(event_id,user_id,position,score,mention) values(?,?,?,?,?)',(x.event_id,x.user_id,x.position,x.score,x.mention)); pts={'Winner':50,'1st Runner Up':30,'2nd Runner Up':20}.get(x.position,10); con.execute('update users set points=points+? where id=?',(pts,x.user_id)); con.commit(); con.close(); notify(x.user_id,'Result published',f'You achieved {x.position} in the event.','RESULT'); return {'message':'Result published'}

@app.get('/api/results/me')
def my_results(user=Depends(auth)):
    con=db(); rows=con.execute('select r.*,e.name event_name,e.date from results r join events e on e.id=r.event_id where r.user_id=? order by e.date desc',(user['id'],)).fetchall(); con.close(); return [dict(r) for r in rows]

@app.get('/api/venues')
def venues(user=Depends(auth)):
    con=db(); rows=con.execute('select * from venues order by capacity').fetchall(); con.close(); return [dict(r) for r in rows]

@app.get('/api/reports/registrations.csv')
def reg_report(user=Depends(auth)):
    role_ok(user,['super_admin','event_admin','event_coordinator']); con=db(); rows=con.execute('select r.reg_code,u.name,u.email,u.notification_email,u.prn,u.department,u.year,u.division,e.name event_name,e.category,e.date,r.status,r.created_at from registrations r join users u on u.id=r.user_id join events e on e.id=r.event_id order by r.created_at desc').fetchall(); con.close(); out=io.StringIO(); w=csv.writer(out); w.writerow(rows[0].keys() if rows else ['No data']); [w.writerow(list(r)) for r in rows]; return StreamingResponse(iter([out.getvalue()]),media_type='text/csv',headers={'Content-Disposition':'attachment; filename=compesa_registrations.csv'})

@app.get('/api/reports/attendance.csv')
def attendance_report(user=Depends(auth)):
    role_ok(user,['super_admin','event_admin','event_coordinator']); con=db(); rows=con.execute("select u.name,u.prn,u.department,u.year,u.division,u.phone,u.email,u.notification_email,e.name event_name,r.reg_code,r.status registration_status,a.scanned_at check_in_time,a.method qr_verification from attendance a join users u on u.id=a.user_id join events e on e.id=a.event_id left join registrations r on r.user_id=a.user_id and r.event_id=a.event_id order by a.scanned_at desc").fetchall(); con.close(); out=io.StringIO(); w=csv.writer(out); w.writerow(rows[0].keys() if rows else ['No data']); [w.writerow(list(r)) for r in rows]; return StreamingResponse(iter([out.getvalue()]),media_type='text/csv',headers={'Content-Disposition':'attachment; filename=compesa_attended_students.csv'})

@app.get('/api/reports/participants.csv')
def participants_report(user=Depends(auth)):
    role_ok(user,['super_admin','event_admin','event_coordinator']); con=db(); rows=con.execute("select u.name,u.prn,u.department,u.year,u.division,u.phone,u.email,u.notification_email,e.name event_name,e.category,r.reg_code,r.status registration_status,r.created_at registration_date,a.scanned_at check_in_time,case when a.id is not null then 'ATTENDED' else 'NOT_ATTENDED' end attendance_status,r.payment_mode,r.payment_status from registrations r join users u on u.id=r.user_id join events e on e.id=r.event_id left join attendance a on a.user_id=r.user_id and a.event_id=r.event_id order by r.created_at desc").fetchall(); con.close(); out=io.StringIO(); w=csv.writer(out); w.writerow(rows[0].keys() if rows else ['No data']); [w.writerow(list(r)) for r in rows]; return StreamingResponse(iter([out.getvalue()]),media_type='text/csv',headers={'Content-Disposition':'attachment; filename=compesa_event_participants.csv'})

@app.get('/api/reports/students.csv')
def students_report(user=Depends(auth)):
    role_ok(user,['super_admin','event_admin','event_coordinator']); con=db(); rows=con.execute("select name,prn,department,year,division,phone,email,notification_email,skills,interests,points,created_at from users where role='student' order by name").fetchall(); con.close(); out=io.StringIO(); w=csv.writer(out); w.writerow(rows[0].keys() if rows else ['No data']); [w.writerow(list(r)) for r in rows]; return StreamingResponse(iter([out.getvalue()]),media_type='text/csv',headers={'Content-Disposition':'attachment; filename=compesa_all_students.csv'})

@app.get('/api/audit')
def audit_logs(user=Depends(auth)):
    role_ok(user,['super_admin']); con=db(); rows=con.execute('select a.*,u.name from audit_logs a join users u on u.id=a.user_id order by a.created_at desc limit 200').fetchall(); con.close(); return [dict(r) for r in rows]


@app.get('/api/admin/backup')
def download_backup(user=Depends(auth)):
    """Lets the admin download a full, consistent snapshot of the live database.
    This is the real fix for hosts with non-persistent storage (e.g. Render's free
    plan): download a backup regularly, and restore it below if the live data ever
    resets."""
    role_ok(user, ['super_admin'])
    dest = _backup('manual', keep=10)
    audit(user, 'DOWNLOAD_BACKUP', '', 'Database backup downloaded')
    return FileResponse(dest, media_type='application/octet-stream', filename=dest.name)


@app.post('/api/admin/restore')
async def restore_backup(file: UploadFile = File(...), user=Depends(auth)):
    """Replaces the live database with an uploaded backup file. The database that
    was live just before the restore is itself safety-copied first, so a restore
    can always be undone."""
    role_ok(user, ['super_admin'])
    data = await file.read()
    if len(data) > 200 * 1024 * 1024:
        raise HTTPException(413, 'Backup file is too large')
    if data[:16] != b'SQLite format 3\x00':
        raise HTTPException(400, 'This does not look like a valid SQLite database file')
    BACKUPS.mkdir(parents=True, exist_ok=True)
    tmp_path = BACKUPS / f'_incoming_{secrets.token_hex(6)}.db'
    tmp_path.write_bytes(data)
    try:
        chk = sqlite3.connect(tmp_path)
        tables = {r[0] for r in chk.execute("select name from sqlite_master where type='table'").fetchall()}
        chk.close()
        if not {'users', 'events', 'registrations'}.issubset(tables):
            raise HTTPException(400, 'This file does not look like a COMPESA database backup')
    except HTTPException:
        tmp_path.unlink(missing_ok=True); raise
    except Exception:
        tmp_path.unlink(missing_ok=True)
        raise HTTPException(400, 'Could not read this file as a SQLite database')
    _backup('pre_restore', keep=5)  # safety copy of what was live, in case this needs undoing
    shutil.move(str(tmp_path), str(DB))
    for suffix in ('-wal', '-shm'):
        stale = Path(str(DB) + suffix)
        if stale.exists():
            try: stale.unlink()
            except Exception: pass
    audit(user, 'RESTORE_BACKUP', '', 'Database restored from an uploaded backup file')
    return {'message': 'Database restored successfully.'}


@app.post('/api/announcements')
def announcement(x:Announcement,user=Depends(auth)):
    role_ok(user,['super_admin','event_admin','event_coordinator']); con=db(); ids=[r[0] for r in con.execute("select id from users where role='student'").fetchall()]
    if x.event_id:
        con.execute('insert into event_announcements(event_id,title,body,created_at,created_by) values(?,?,?,?,?)',(x.event_id,x.title,x.body,now(),user['id']))
    con.commit(); con.close()
    for uid in ids: notify(uid,x.title,x.body,'ANNOUNCEMENT')
    audit(user,'ANNOUNCEMENT','EVENT' if x.event_id else 'ALL',x.title); return {'sent':len(ids)}

@app.get('/api/announcements/me')
def announcements_me(user=Depends(auth)):
    con=db(); rows=con.execute("select n.* from notifications n where n.user_id=? and n.kind='ANNOUNCEMENT' order by n.created_at desc limit 50",(user['id'],)).fetchall(); con.close(); return [dict(r) for r in rows]

@app.post('/api/communication/test')
def test_email(email:str,user=Depends(auth)):
    role_ok(user,['super_admin']);
    if not smtp_configured(): return {'sent':False,'message':'SMTP not configured. Edit .env with Gmail App Password settings.'}
    ok,err=send_compesa_email(email,'COMPESA Communication Test','<h2>COMPESA Email Test ✓</h2><p>Your SMTP configuration is working.</p>','COMPESA email configuration is working.')
    return {'sent':ok,'message':'Test email sent.' if ok else err}

@app.get('/api/analytics')
def analytics(user=Depends(auth)):
    role_ok(user,['super_admin','event_admin','event_coordinator']); con=db()
    ratings=con.execute('select round(avg(rating),2) avg,count(*) responses from feedback').fetchone(); active=con.execute("select u.name,count(*) c from registrations r join users u on u.id=r.user_id group by u.id order by c desc limit 10").fetchall(); attendance=con.execute('select count(*) from attendance').fetchone()[0]
    attendance_pct=con.execute("select round(100.0*sum(case when a.id is not null then 1 else 0 end)/max(1,count(*)),1) p from registrations r left join attendance a on a.user_id=r.user_id and a.event_id=r.event_id where r.status in ('APPROVED','COMPLETED')").fetchone()[0]
    categories=con.execute('select e.category,count(*) count from registrations r join events e on e.id=r.event_id group by e.category order by count desc').fetchall(); years=con.execute('select u.year,count(*) count from registrations r join users u on u.id=r.user_id group by u.year order by count desc').fetchall(); types=[{'type':'Individual','count':con.execute("select count(*) from registrations where team_id is null").fetchone()[0]},{'type':'Team','count':con.execute("select count(*) from registrations where team_id is not null").fetchone()[0]}]
    con.close(); return {'rating':dict(ratings),'attendance_records':attendance,'attendance_percent':attendance_pct,'active_students':[dict(x) for x in active],'categories':[dict(x) for x in categories],'years':[dict(x) for x in years],'registration_types':types}

@app.get('/api/problems/{event_id}')
def problems(event_id:int,user=Depends(auth)):
    con=db(); rows=con.execute('select * from problems where event_id=?',(event_id,)).fetchall(); con.close(); return [dict(r) for r in rows]

@app.post('/api/submissions')
def submission(x:SubmitIn,user=Depends(auth)):
    if len(x.code)>50000: raise HTTPException(413,'Submission too large')
    score=100 if ('return' in x.code or 'print' in x.code) else 20; status='PASSED' if score>=100 else 'REVIEW'
    con=db(); con.execute('insert into submissions(problem_id,user_id,language,code,status,score,submitted_at) values(?,?,?,?,?,?,?)',(x.problem_id,user['id'],x.language,x.code,status,score,now())); con.commit(); con.close(); return {'status':status,'score':score,'note':'Demo judge mode: arbitrary code execution is intentionally disabled for server safety.'}

@app.get('/api/public/profile/{prn}')
def public_profile(prn:str):
    con=db(); u=con.execute("select name,prn,department,year,division,skills,points,privacy from users where prn=?",(prn,)).fetchone(); con.close()
    if not u or u['privacy']=='private': raise HTTPException(404,'Profile unavailable')
    return dict(u)
