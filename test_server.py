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
        def req(path,method='GET',body=None):
            r=urllib.request.Request(self.url+'/api'+path,method=method,data=None if body is None else json.dumps(body).encode(),headers={'Content-Type':'application/json','X-CSRF-Token':token[0]})
            try:
                with op.open(r) as response:return response.status,json.load(response)
            except urllib.error.HTTPError as e:
                with e:return e.code,json.load(e)
        req('/session');token[0]=req('/session')[1]['csrf']
        return req,token
    def test_full_flow(self):
        a,ta=self.client();b,tb=self.client();admin,tc=self.client()
        status,ch=a('/channels','POST',{'name':'Private','password':'secret-pass'});self.assertEqual(status,201);cid=ch['id']
        status,n=a('/channels/'+cid+'/notes','POST',{'title':'Test','body':'from device one'});self.assertEqual(status,201);nid=n['id']
        self.assertEqual(b('/channels/'+cid+'/notes')[0],403)
        self.assertEqual(b('/notes/'+nid,'PUT',{'title':'hack','body':'x','version':1})[0],403)
        self.assertEqual(b('/channels/'+cid+'/unlock','POST',{'password':'wrong'})[0],401)
        self.assertEqual(b('/channels/'+cid+'/unlock','POST',{'password':'secret-pass'})[0],200)
        self.assertEqual(b('/channels/'+cid+'/notes')[1][0]['body'],'from device one')
        self.assertEqual(b('/notes/'+nid,'PUT',{'title':'Test','body':'from device two','version':1})[0],200)
        self.assertEqual(a('/notes/'+nid,'PUT',{'title':'Test','body':'stale','version':1})[0],409)
        self.assertEqual(a('/notes/'+nid,'DELETE',{})[0],403)
        self.assertEqual(admin('/login','POST',{'password':'test-admin-password'})[0],200);tc[0]=admin('/session')[1]['csrf']
        self.assertEqual(admin('/channels/'+cid+'/notes')[1][0]['body'],'from device two')
        self.assertEqual(admin('/notes/'+nid,'PUT',{'title':'Admin edit','body':'admin body','version':2})[0],200)
        self.assertEqual(admin('/channels/'+cid,'PUT',{'name':'Private','password':'changed-pass'})[0],200)
        self.assertEqual(b('/channels/'+cid+'/notes')[0],403)
        self.assertEqual(admin('/notes/'+nid,'DELETE',{})[0],200)
        self.assertEqual(admin('/channels/'+cid,'DELETE',{})[0],200)
        self.assertEqual(admin('/channels/'+cid+'/notes')[0],404)
    def test_csrf_and_persistence(self):
        a,t=self.client();old=t[0];t[0]='bad'
        self.assertEqual(a('/channels','POST',{'name':'blocked'})[0],403);t[0]=old
        status,ch=a('/channels','POST',{'name':'Persistent'});self.assertEqual(status,201)
        self.app.init()
        self.assertTrue(any(c['id']==ch['id'] for c in a('/channels')[1]))
        with urllib.request.urlopen(self.url) as r:self.assertIn(b'Notepad',r.read())

if __name__=='__main__':unittest.main(verbosity=2)
