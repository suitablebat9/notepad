import http.cookiejar, importlib.util, json, os, tempfile, threading, unittest, urllib.request, urllib.error
from pathlib import Path

class AppTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp=tempfile.TemporaryDirectory();os.environ['DATA_DIR']=cls.tmp.name
        spec=importlib.util.spec_from_file_location('app',Path(__file__).with_name('server.py'))
        cls.app=importlib.util.module_from_spec(spec);spec.loader.exec_module(cls.app);cls.app.init()
        with cls.app.db() as c:c.execute("INSERT INTO settings VALUES ('admin',?)",(cls.app.password_hash('test-admin-password'),))
        cls.server=cls.app.ThreadingHTTPServer(('127.0.0.1',0),cls.app.Handler)
        threading.Thread(target=cls.server.serve_forever,daemon=True).start()
        cls.url='http://127.0.0.1:'+str(cls.server.server_port)
    @classmethod
    def tearDownClass(cls):cls.server.shutdown();cls.server.server_close();cls.tmp.cleanup()
    def client(self):
        op=urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
        token=['']
        def req(path,method='GET',body=None,headers=None):
            r=urllib.request.Request(self.url+'/api'+path,method=method,data=None if body is None else json.dumps(body).encode(),headers={'Content-Type':'application/json','X-CSRF-Token':token[0],**(headers or {})})
            try:
                with op.open(r) as response:return response.status,json.load(response)
            except urllib.error.HTTPError as e:
                with e:return e.code,json.load(e)
        req('/session');token[0]=req('/session')[1]['csrf']
        return req,token
    def test_full_flow(self):
        a,ta=self.client();b,tb=self.client();admin,tc=self.client()
        status,ch=a('/channels','POST',{'name':'Private','password':'x'});self.assertEqual(status,201);cid=ch['id']
        status,n=a('/channels/'+cid+'/notes','POST',{'title':'Test','body':'from device one'});self.assertEqual(status,201);nid=n['id']
        self.assertEqual(b('/channels/'+cid+'/notes')[0],403)
        self.assertEqual(b('/notes/'+nid,'PUT',{'title':'hack','body':'x','version':1})[0],403)
        self.assertEqual(b('/channels/'+cid+'/unlock','POST',{'password':'wrong'})[0],401)
        self.assertEqual(b('/channels/'+cid+'/unlock','POST',{'password':'x'})[0],200)
        self.assertEqual(b('/channels/'+cid+'/notes')[1][0]['body'],'from device one')
        self.assertEqual(b('/notes/'+nid,'PUT',{'title':'Test','body':'from device two','version':1})[0],200)
        self.assertEqual(a('/notes/'+nid,'PUT',{'title':'Test','body':'stale','version':1})[0],409)
        self.assertEqual(b('/notes/'+nid,'DELETE',{})[0],403)
        self.assertEqual(admin('/login','POST',{'password':'test-admin-password'})[0],200);tc[0]=admin('/session')[1]['csrf']
        self.assertEqual(admin('/channels/'+cid+'/notes')[1][0]['body'],'from device two')
        self.assertEqual(admin('/notes/'+nid,'PUT',{'title':'Admin edit','body':'admin body','version':2})[0],200)
        self.assertEqual(admin('/channels/'+cid,'PUT',{'name':'Private','password':'y'})[0],200)
        self.assertEqual(b('/channels/'+cid+'/notes')[0],403)
        self.assertEqual(admin('/notes/'+nid,'DELETE',{})[0],200)
        self.assertEqual(admin('/channels/'+cid,'DELETE',{})[0],200)
        self.assertEqual(admin('/channels/'+cid+'/notes')[0],404)
    def test_creator_deletion(self):
        a,ta=self.client();b,tb=self.client()
        cid=a('/channels','POST',{'name':'Owned'})[1]['id']
        nid=a('/channels/'+cid+'/notes','POST',{})[1]['id']
        other=b('/channels/'+cid+'/notes','POST',{})[1]['id']
        self.assertTrue(next(c for c in a('/channels')[1] if c['id']==cid)['can_delete'])
        self.assertFalse(next(c for c in b('/channels')[1] if c['id']==cid)['can_delete'])
        rows=a('/channels/'+cid+'/notes')[1]
        self.assertTrue(next(n for n in rows if n['id']==nid)['can_delete'])
        self.assertNotIn('owner',rows[0])
        self.assertEqual(b('/channels/'+cid,'DELETE',{})[0],403)
        self.assertEqual(b('/notes/'+nid,'DELETE',{})[0],403)
        self.assertEqual(a('/notes/'+other,'DELETE',{})[0],403)
        self.assertEqual(a('/channels/'+cid,'PUT',{'name':'Renamed'})[0],403)
        # Ownership persists across admin sign-in/out and server session loss.
        self.assertEqual(a('/login','POST',{'password':'test-admin-password'})[0],200)
        ta[0]=a('/session')[1]['csrf']
        self.assertEqual(a('/logout','POST',{})[0],200)
        ta[0]=a('/session')[1]['csrf']
        with self.app.LOCK:self.app.SESSIONS.clear()
        a('/session');ta[0]=a('/session')[1]['csrf']
        self.assertEqual(a('/notes/'+nid,'DELETE',{})[0],200)
        self.assertEqual(a('/channels/'+cid,'DELETE',{})[0],200)
        with self.app.db() as c:
            self.assertIsNone(c.execute('SELECT 1 FROM notes WHERE id=?',(other,)).fetchone())
        self.assertEqual(a('/channels/general','DELETE',{})[0],403)
    def test_legacy_schema_migration(self):
        old_data=self.app.DATA
        with tempfile.TemporaryDirectory() as folder:
            try:
                self.app.DATA=Path(folder)
                with self.app.db() as c:
                    c.executescript("CREATE TABLE channels(id TEXT PRIMARY KEY,name TEXT NOT NULL UNIQUE,password TEXT,version INTEGER NOT NULL DEFAULT 1); CREATE TABLE notes(id TEXT PRIMARY KEY,channel TEXT NOT NULL,title TEXT NOT NULL,body TEXT NOT NULL,version INTEGER NOT NULL DEFAULT 1,updated REAL NOT NULL); INSERT INTO channels(id,name) VALUES ('legacy','Legacy'); INSERT INTO notes VALUES ('old','legacy','Old note','Keep me',1,0);")
                self.app.init();self.app.init()
                with self.app.db() as c:
                    row=c.execute("SELECT * FROM notes WHERE id='old'").fetchone()
                    self.assertEqual(row['body'],'Keep me');self.assertIsNone(row['owner'])
            finally:self.app.DATA=old_data
    def test_tunnel_origin(self):
        a,t=self.client()
        headers={'Host':'notes.example.com','Origin':'https://notes.example.com'}
        status,ch=a('/channels','POST',{'name':'Tunnel'},headers)
        self.assertEqual(status,201)
        self.assertEqual(a('/channels/'+ch['id']+'/notes','POST',{'body':'via tunnel'},headers)[0],201)
        self.assertEqual(a('/channels','POST',{'name':'Cross origin'},{**headers,'Origin':'https://evil.example'})[0],403)
        self.assertEqual(a('/channels','POST',{'name':'Null origin'},{**headers,'Origin':'null'})[0],403)
        os.environ['PUBLIC_ORIGIN']='https://public.example.com/'
        try:
            self.assertEqual(a('/channels','POST',{'name':'Pinned origin'},{'Host':'localhost:8080','Origin':'https://public.example.com'})[0],201)
            self.assertEqual(a('/channels','POST',{'name':'Wrong origin'},headers)[0],403)
        finally:
            os.environ.pop('PUBLIC_ORIGIN',None)
    def test_csrf_and_persistence(self):
        a,t=self.client();old=t[0];t[0]='bad'
        self.assertEqual(a('/channels','POST',{'name':'blocked'})[0],403);t[0]=old
        status,ch=a('/channels','POST',{'name':'Persistent'});self.assertEqual(status,201)
        self.app.init()
        self.assertTrue(any(c['id']==ch['id'] for c in a('/channels')[1]))
        with urllib.request.urlopen(self.url) as r:self.assertIn(b'Notepad',r.read())

if __name__=='__main__':unittest.main(verbosity=2)
