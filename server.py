#!/usr/bin/env python3
"""Notepad: dependency-free shared notes for a single Linux service."""
import argparse, getpass, hashlib, hmac, json, os, secrets, sqlite3, threading, time
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from http.cookies import SimpleCookie
from pathlib import Path
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parent
DATA = Path(os.environ.get('DATA_DIR', ROOT / 'data'))
SESSIONS = {}
ATTEMPTS = {}
LOCK = threading.RLock()

@contextmanager
def db():
    c = sqlite3.connect(DATA / 'notes.db', timeout=10)
    c.row_factory = sqlite3.Row
    try:
        c.execute('PRAGMA foreign_keys=ON')
        with c:
            yield c
    finally:
        c.close()

def password_hash(value, salt=None):
    salt = salt or secrets.token_hex(16)
    return salt + ':' + hashlib.scrypt(value.encode(), salt=bytes.fromhex(salt), n=16384, r=8, p=1).hex()

def matches(value, stored):
    return bool(stored) and hmac.compare_digest(password_hash(value, stored.split(':')[0]), stored)

def init():
    DATA.mkdir(parents=True, exist_ok=True, mode=0o700)
    with db() as c:
        c.executescript('''
        PRAGMA journal_mode=WAL;
        CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY,value TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS channels(id TEXT PRIMARY KEY,name TEXT NOT NULL UNIQUE,password TEXT,version INTEGER NOT NULL DEFAULT 1);
        CREATE TABLE IF NOT EXISTS notes(id TEXT PRIMARY KEY,channel TEXT NOT NULL REFERENCES channels(id) ON DELETE CASCADE,title TEXT NOT NULL,body TEXT NOT NULL,version INTEGER NOT NULL DEFAULT 1,updated REAL NOT NULL);
        ''')
        for table in ('channels', 'notes'):
            if 'owner' not in {r['name'] for r in c.execute(f'PRAGMA table_info({table})')}:
                c.execute(f'ALTER TABLE {table} ADD COLUMN owner TEXT')
        if not c.execute('SELECT 1 FROM channels').fetchone():
            c.execute('INSERT INTO channels(id,name) VALUES (?,?)', ('general','general'))

class Error(Exception):
    def __init__(self, status, message): self.status, self.message = status, message

class Handler(BaseHTTPRequestHandler):
    server_version = 'Notepad'
    def log_message(self, *_): pass
    def reply(self, status, data, mime='application/json', cookie=None):
        raw = json.dumps(data).encode() if mime == 'application/json' else data
        self.send_response(status)
        for key, val in {'Content-Type':mime,'Content-Length':str(len(raw)), 'Cache-Control':'no-store', 'X-Content-Type-Options':'nosniff','Referrer-Policy':'same-origin','Content-Security-Policy':"default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"}.items(): self.send_header(key,val)
        if cookie:
            for value in ([cookie] if isinstance(cookie,str) else cookie):
                self.send_header('Set-Cookie',value)
        self.end_headers()
        self.wfile.write(raw)
    def session(self):
        cookies = SimpleCookie()
        try: cookies.load(self.headers.get('Cookie',''))
        except Exception: pass
        token = cookies.get('session')
        with LOCK:
            s = SESSIONS.get(token.value if token else '')
            if s and s['expires'] > time.time(): return s
        return {'admin':False,'grants':{},'csrf':None}
    def throttle(self):
        key = self.client_address[0]
        with LOCK:
            now = time.time()
            for k in list(ATTEMPTS):
                if not ATTEMPTS[k] or now-ATTEMPTS[k][-1]>300: del ATTEMPTS[k]
            tries = [t for t in ATTEMPTS.get(key,[]) if now-t<300]
            if len(tries)>=15: raise Error(429,'Too many attempts. Try again in five minutes.')
            ATTEMPTS[key]=tries+[now]
    def new_session(self, admin=False, grants=None):
        token=secrets.token_urlsafe(32)
        cookies=SimpleCookie()
        try: cookies.load(self.headers.get('Cookie',''))
        except Exception: pass
        owner=cookies.get('notepad_owner')
        owner=owner.value if owner else ''
        if len(owner)!=64 or any(ch not in '0123456789abcdef' for ch in owner):
            owner=secrets.token_hex(32)
        owner_id=hashlib.sha256(owner.encode()).hexdigest()
        with LOCK:
            for k in list(SESSIONS):
                if SESSIONS[k]['expires'] < time.time(): del SESSIONS[k]
            SESSIONS[token]={'owner':owner_id,'admin':admin,'grants':grants or {},'csrf':secrets.token_urlsafe(32),'expires':time.time()+43200}
        secure='; Secure' if os.environ.get('COOKIE_SECURE')=='1' else ''
        self.reply(200, {'ok':True}, cookie=[f'session={token}; HttpOnly; SameSite=Strict; Path=/; Max-Age=43200{secure}',f'notepad_owner={owner}; HttpOnly; SameSite=Strict; Path=/; Max-Age=31536000{secure}'])
    def require_admin(self,s):
        if not s['admin']: raise Error(403,'Administrator access required.')
    def can_delete(self,s,row):
        return bool(s['admin'] or (s.get('owner') and row['owner']==s['owner']))
    def require_delete(self,s,row):
        if not self.can_delete(s,row): raise Error(403,'Only the creator or an administrator can delete this item.')
    def note_data(self,s,row):
        result=dict(row)
        result.pop('owner',None)
        result['can_delete']=self.can_delete(s,row)
        return result
    def access(self,c,s,cid):
        ch=c.execute('SELECT * FROM channels WHERE id=?',(cid,)).fetchone()
        if not ch: raise Error(404,'Channel not found.')
        if ch['password'] and not s['admin'] and s['grants'].get(cid)!=ch['version']: raise Error(403,'Unlock this channel first.')
        return ch
    def string(self,d,key,limit,default=None):
        v=d.get(key,default)
        if not isinstance(v,str) or len(v)>limit: raise Error(400,f'Invalid {key} (maximum {limit} characters).')
        return v
    def do_GET(self): self.handle_request()
    def do_POST(self): self.handle_request()
    def do_PUT(self): self.handle_request()
    def do_DELETE(self): self.handle_request()
    def handle_request(self):
        try: self.route()
        except Error as e: self.reply(e.status,{'error':e.message})
        except (ValueError,TypeError,json.JSONDecodeError): self.reply(400,{'error':'Invalid request.'})
        except sqlite3.IntegrityError: self.reply(409,{'error':'That channel name already exists.'})
        except Exception: self.reply(500,{'error':'Server error. Please retry.'})
    def route(self):
        path=urlparse(self.path).path
        method=self.command
        if not path.startswith('/api/'):
            if method!='GET': raise Error(405,'Method not allowed.')
            files={'/':('index.html','text/html; charset=utf-8'),'/app.js':('app.js','text/javascript; charset=utf-8'),'/style.css':('style.css','text/css; charset=utf-8')}
            if path not in files: raise Error(404,'Not found.')
            file,mime=files[path]
            return self.reply(200,(ROOT/'public'/file).read_bytes(),mime)
        s=self.session()
        d={}
        if method!='GET':
            # TLS may terminate at a tunnel; match the public Host for HTTP or HTTPS.
            # PUBLIC_ORIGIN pins the exact origin when a proxy overrides Host.
            origin=self.headers.get('Origin')
            configured=os.environ.get('PUBLIC_ORIGIN', '').strip().rstrip('/')
            host=self.headers.get('Host','')
            allowed={configured} if configured else {'http://'+host, 'https://'+host}
            if origin and origin not in allowed: raise Error(403,'Origin not allowed. Set PUBLIC_ORIGIN to your public website address if your proxy changes the Host header.')
            if self.headers.get('Content-Type','').split(';')[0]!='application/json': raise Error(415,'JSON required.')
            n=int(self.headers.get('Content-Length','0'))
            if n<0 or n>1100000: raise Error(413,'Request too large.')
            d=json.loads(self.rfile.read(n) or b'{}')
            if not isinstance(d,dict): raise Error(400,'JSON object required.')
            if path not in ('/api/login',) and (not s['csrf'] or not hmac.compare_digest(self.headers.get('X-CSRF-Token',''),s['csrf'])): raise Error(403,'Session expired. Reload the page.')
        with db() as c:
            if path=='/api/session' and method=='GET':
                if not s['csrf']: return self.new_session()
                return self.reply(200,{'admin':s['admin'],'csrf':s['csrf']})
            if path=='/api/login' and method=='POST':
                self.throttle()
                stored=c.execute("SELECT value FROM settings WHERE key='admin'").fetchone()
                if not stored or not matches(self.string(d,'password',1024),stored[0]): raise Error(401,'Incorrect admin password.')
                return self.new_session(True)
            if path=='/api/logout' and method=='POST':
                with LOCK:
                    for k in list(SESSIONS):
                        if SESSIONS[k] is s: del SESSIONS[k]
                return self.new_session()
            if path=='/api/channels':
                if method=='GET':
                    rows=c.execute('SELECT c.*, (SELECT count(*) FROM notes n WHERE n.channel=c.id) AS count FROM channels c ORDER BY name').fetchall()
                    return self.reply(200,[{'id':r['id'],'name':r['name'],'locked':bool(r['password']),'accessible':not r['password'] or s['admin'] or s['grants'].get(r['id'])==r['version'],'count':r['count'],'version':r['version'],'can_delete':self.can_delete(s,r)} for r in rows])
                if method=='POST':
                    name=self.string(d,'name',60).strip()
                    if not name: raise Error(400,'Enter a channel name.')
                    password=self.string(d,'password',1024,'')
                    cid=secrets.token_hex(12)
                    c.execute('INSERT INTO channels(id,name,password,owner) VALUES (?,?,?,?)',(cid,name,password_hash(password) if password else None,s['owner']))
                    s['grants'][cid]=1
                    return self.reply(201,{'id':cid})
            p=path.strip('/').split('/')
            if len(p)>=3 and p[1]=='channels':
                cid=p[2]
                if len(p)==4 and p[3]=='unlock' and method=='POST':
                    self.throttle()
                    ch=c.execute('SELECT * FROM channels WHERE id=?',(cid,)).fetchone()
                    if not ch: raise Error(404,'Channel not found.')
                    if ch['password'] and not matches(self.string(d,'password',1024),ch['password']): raise Error(401,'Incorrect channel password.')
                    s['grants'][cid]=ch['version']
                    return self.reply(200,{'ok':True})
                ch=self.access(c,s,cid)
                if len(p)==3 and method in ('DELETE','PUT'):
                    if method=='DELETE':
                        self.require_delete(s,ch)
                        c.execute('DELETE FROM channels WHERE id=?',(cid,))
                    else:
                        self.require_admin(s)
                        name=self.string(d,'name',60).strip()
                        if not name: raise Error(400,'Enter a channel name.')
                        if 'password' in d:
                            pw=self.string(d,'password',1024)
                            c.execute('UPDATE channels SET name=?,password=?,version=version+1 WHERE id=?',(name,password_hash(pw) if pw else None,cid))
                        else: c.execute('UPDATE channels SET name=? WHERE id=?',(name,cid))
                    return self.reply(200,{'ok':True})
                if len(p)==4 and p[3]=='notes':
                    if method=='GET': return self.reply(200,[self.note_data(s,r) for r in c.execute('SELECT * FROM notes WHERE channel=? ORDER BY updated DESC',(cid,))])
                    if method=='POST':
                        nid=secrets.token_hex(12)
                        c.execute('INSERT INTO notes(id,channel,title,body,updated,owner) VALUES (?,?,?,?,?,?)',(nid,cid,self.string(d,'title',120,'Untitled note'),self.string(d,'body',1000000,''),time.time(),s['owner']))
                        return self.reply(201,{'id':nid})
            if len(p)==3 and p[1]=='notes':
                note=c.execute('SELECT * FROM notes WHERE id=?',(p[2],)).fetchone()
                if not note: raise Error(404,'Note not found.')
                self.access(c,s,note['channel'])
                if method=='DELETE':
                    self.require_delete(s,note)
                    c.execute('DELETE FROM notes WHERE id=?',(note['id'],))
                    return self.reply(200,{'ok':True})
                if method=='PUT':
                    title=self.string(d,'title',120).strip() or 'Untitled note'
                    body=self.string(d,'body',1000000)
                    cur=c.execute('UPDATE notes SET title=?,body=?,version=version+1,updated=? WHERE id=? AND version=?',(title,body,time.time(),note['id'],d.get('version')))
                    if cur.rowcount!=1: raise Error(409,'This note changed on another device. Copy your draft, then reload the latest version.')
                    return self.reply(200,self.note_data(s,c.execute('SELECT * FROM notes WHERE id=?',(note['id'],)).fetchone()))
            raise Error(404,'Not found.')

if __name__=='__main__':
    parser=argparse.ArgumentParser()
    parser.add_argument('--set-admin',action='store_true')
    args=parser.parse_args()
    init()
    if args.set_admin:
        pw=getpass.getpass('New admin password (12+ characters): ')
        if len(pw)<12 or pw!=getpass.getpass('Confirm password: '): raise SystemExit('Passwords must match and contain at least 12 characters.')
        with db() as c: c.execute("INSERT OR REPLACE INTO settings VALUES ('admin',?)",(password_hash(pw),))
        print('Admin password saved. Restart the service to invalidate existing sessions.')
    else:
        with db() as c:
            if not c.execute("SELECT 1 FROM settings WHERE key='admin'").fetchone(): raise SystemExit('Run python3 server.py --set-admin first.')
        host=os.environ.get('HOST','0.0.0.0'); port=int(os.environ.get('PORT','8080'))
        print(f'Notepad listening on http://{host}:{port}',flush=True)
        ThreadingHTTPServer((host,port),Handler).serve_forever()
