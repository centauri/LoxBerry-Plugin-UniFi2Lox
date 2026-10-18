import json
import os
from pathlib import Path
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'bin'))
import https_manager as h
import https_dns_hook as hook


class SettingsTests(unittest.TestCase):
    def test_hostname_validation(self):
        self.assertEqual(h.domain_name('Camera.Example.com.'), 'camera.example.com')
        for bad in ['127.0.0.1', '*.example.com', 'a..com', '-a.com', 'a-.com',
                    'a.com/../x', 'a.com;touch x', 'a.com:443', 'https://a.com', 'a', 'a\n.com']:
            with self.subTest(bad=bad), self.assertRaises(h.Error):
                h.domain_name(bad)

    def test_ports_and_origin(self):
        for data in [dict(listen_port=443), dict(listen_port=8443,snapshot_port=8443),
                     dict(mode='external',external_url='http://camera.example.com'),
                     dict(mode='external',external_url='https://user:pw@camera.example.com'),
                     dict(mode='external',external_url='https://camera.example.com/api'),
                     dict(provider='exec'), dict(staging='false')]:
            with self.subTest(data=data), self.assertRaises(h.Error):
                h.validate_settings(data)
        c = h.validate_settings(dict(mode='external',external_url='https://camera.example.com:8443/'))
        self.assertEqual(c['external_url'], 'https://camera.example.com:8443')

    def test_fixed_camera_routes(self):
        settings = h.validate_settings(dict(mode='managed',domain='camera.example.com'))
        cfg = h.gateway_config(settings, dict(server=dict(username='test',password='not-in-config'),
                             cameras=[dict(slug='front',enabled=True),dict(slug='private',enabled=False)]),
                             'unifi2lox', '/tmp/cert', '/tmp/key', 'bcrypt', '/tmp/admin')
        text = json.dumps(cfg)
        self.assertNotIn('not-in-config', text)
        self.assertNotIn('private', text)
        routes = cfg['apps']['http']['servers']['cameras']['routes'][0]['handle'][1]['routes']
        self.assertEqual(routes[0]['handle'][0]['uri'], '/api/stream.mjpeg?src=front_mjpeg')
        self.assertEqual(routes[1]['handle'][0]['uri'], '/plugins/unifi2lox/snapshot.php?cam=front')
        self.assertEqual(routes[0]['match'][0]['method'], ['GET','HEAD'])
        self.assertEqual(routes[-1]['handle'][0]['status_code'],404)


class ManagerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='u2l-', dir='/tmp')
        self.m = h.Manager(self.tmp.name, 'u2l')
        self.settings = h.validate_settings(dict(mode='managed',domain='camera.example.test', email='test@example.test',terms=True))
        h.write_private(self.m.settings_file, self.settings)
        h.write_private(self.m.home/'config/plugins/u2l/config.json', dict(server=dict(enabled=True,port=1984,username='viewer',password='testpass'),cameras=[dict(enabled=True,slug='front',name='Front')]))
    def tearDown(self):
        self.m.stop()
        self.tmp.cleanup()

    def test_secrets_never_return_and_blank_preserves(self):
        self.m.save(dict(settings=self.settings,credentials={'CF_DNS_API_TOKEN':'secret-token'}))
        self.m.save(dict(settings=self.settings,credentials={'CF_DNS_API_TOKEN':''}))
        self.assertNotIn('secret-token',json.dumps(self.m.status()))
        self.assertTrue(self.m.status()['has_credentials']['CF_DNS_API_TOKEN'])
        self.assertEqual((self.m.base/'secrets.json').stat().st_mode & 0o777,0o600)
        self.assertEqual(self.m.base.stat().st_mode & 0o777,0o700)
        with self.assertRaises(h.Error):
            self.m.save(dict(settings=self.settings,credentials={'EXEC_PATH':'/evil'}))
        self.m.save(dict(settings=self.settings,clear_credentials=True))
        self.assertEqual(self.m.status()['has_credentials'],{})

    def test_default_off_does_not_launch_or_download(self):
        h.write_private(self.m.settings_file,h.DEFAULTS)
        with patch.object(self.m,'apply') as apply, patch.object(self.m,'enqueue') as enqueue:
            self.m.watchdog()
            apply.assert_not_called(); enqueue.assert_not_called()

    def test_lock_prevents_configuration_change_during_challenge(self):
        with h.lock(self.m.base/'operation.lock'), self.assertRaises(h.Error):
            self.m.save(dict(settings=self.settings))

    def test_manual_challenge_confirmation_and_timeout(self):
        jobdir = h.private_dir(self.m.base/'jobs'/'abcdef')
        result=[]
        t=threading.Thread(target=lambda: result.append(hook.run('present','_acme-challenge.camera.example.test.','txt-value',jobdir,timeout=5)))
        t.start()
        deadline=time.time()+3
        while not (jobdir/'challenge.json').exists() and time.time()<deadline: time.sleep(.02)
        challenge=h.read_json(jobdir/'challenge.json')
        h.write_private(jobdir/'confirmed.json',dict(nonce='old-nonce'))
        time.sleep(.1)
        self.assertTrue(t.is_alive())
        h.write_private(jobdir/'confirmed.json',dict(nonce=challenge['nonce']))
        t.join(3)
        self.assertEqual(result,[0])
        self.assertEqual(h.read_json(jobdir/'state.json')['phase'],'validating')
        hook.run('cleanup','name','value',jobdir)
        self.assertTrue(h.read_json(jobdir/'challenge.json')['cleanup'])
        self.assertEqual(hook.run('present','name','value',jobdir,timeout=0),1)

    def test_cancelled_manual_challenge_and_stale_confirmation(self):
        jobdir = h.private_dir(self.m.base/'jobs'/'cancel-test')
        h.write_private(jobdir/'cancelled.json', {'cancelled': True})
        self.assertEqual(hook.run('present','name','value',jobdir,timeout=3),1)
        h.write_private(self.m.base/'job.json',dict(id='cancel-test',phase='waiting_dns'))
        with patch.object(self.m,'job_running',return_value=True), self.assertRaises(h.Error):
            self.m.confirm('cancel-test','stale-nonce')

    def test_background_apply_never_reenables_disabled_https(self):
        h.write_private(self.m.base/'enabled.json',dict(enabled=False))
        with patch.object(self.m,'plugin',side_effect=AssertionError('must not start')):
            self.m.apply(require_enabled=True)

    def test_only_dns_mode_renews_and_retries_are_bounded(self):
        h.write_private(self.m.base/'enabled.json',dict(enabled=True))
        h.write_private(self.m.active_file,dict(expires=time.time()+86400))
        with patch.object(self.m,'apply'), patch.object(self.m,'enqueue') as enqueue:
            self.m.watchdog(); self.m.watchdog()
            enqueue.assert_called_once_with('issue')
        self.settings['certificate_mode']='manual'
        h.write_private(self.m.settings_file,self.settings)
        h.write_private(self.m.base/'renewal.json',dict(attempt=0))
        with patch.object(self.m,'apply'), patch.object(self.m,'enqueue') as enqueue:
            self.m.watchdog(); enqueue.assert_not_called()

    def test_issue_uses_pinned_cli_and_secret_files_not_arguments(self):
        h.write_private(self.m.base/'secrets.json',{'CF_DNS_API_TOKEN':'secret-token'})
        jobdir=h.private_dir(self.m.base/'jobs'/'fake')
        captured={}
        class Proc:
            pid=999999
            def __init__(self,args,**kwargs):
                captured['args']=args; captured['env']=kwargs['env']
                captured['secret']=Path(kwargs['env']['CF_DNS_API_TOKEN_FILE']).read_text()
            returncode=1
            def poll(self): return 1
            def wait(self,timeout): return 1
        with patch.object(h.subprocess,'Popen',Proc), self.assertRaises(h.Error): self.m.issue(jobdir)
        self.assertEqual(captured['args'][1],'run')
        self.assertNotIn('secret-token',repr(captured['args']))
        self.assertNotIn('secret-token',repr(captured['env']))
        self.assertEqual(captured['secret'],'secret-token')
        self.assertFalse((jobdir/'credentials').exists())


@unittest.skipUnless(os.environ.get('U2L_TEST_CADDY'), 'Set U2L_TEST_CADDY to run real HTTPS integration tests.')
class GatewayIntegrationTests(unittest.TestCase):
    def setUp(self):
        ManagerTests.setUp(self)
        self.binary=Path(os.environ['U2L_TEST_CADDY']).resolve()
        (self.m.tools/'caddy').symlink_to(self.binary)
        from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
        self.received=[]
        received=self.received
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                received.append((self.path,dict(self.headers)))
                body=b'camera-bytes'
                self.send_response(200); self.send_header('Content-Type','image/jpeg'); self.send_header('Content-Length',str(len(body))); self.end_headers(); self.wfile.write(body)
            def log_message(self,*args): pass
        self.upstream=ThreadingHTTPServer(('127.0.0.1',0),Handler)
        self.thread=threading.Thread(target=self.upstream.serve_forever,daemon=True); self.thread.start()
        with socket.socket() as s: s.bind(('127.0.0.1',0)); self.https_port=s.getsockname()[1]
        self.settings.update(listen_port=self.https_port,snapshot_port=self.upstream.server_port,certificate_mode='import')
        h.write_private(self.m.settings_file,self.settings)
        plugin=self.m.plugin(); plugin['server']['port']=self.upstream.server_port
        h.write_private(self.m.home/'config/plugins/u2l/config.json',plugin)
        cert=Path(self.tmp.name)/'cert.pem'; key=Path(self.tmp.name)/'key.pem'
        subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','2','-subj','/CN=camera.example.test','-addext','subjectAltName=DNS:camera.example.test','-keyout',str(key),'-out',str(cert)],check=True,capture_output=True)
        self.cert=cert; self.key=key
        self.m.store_certificate(cert.read_bytes(),key.read_bytes())
    def tearDown(self):
        ManagerTests.tearDown(self)
        self.upstream.shutdown(); self.upstream.server_close(); self.thread.join()
    def request(self,path,auth=True,host='camera.example.test',method='GET'):
        import base64,http.client
        ctx=ssl.create_default_context(cafile=str(self.cert))
        sock=ctx.wrap_socket(socket.create_connection(('127.0.0.1',self.https_port),timeout=5),server_hostname='camera.example.test')
        headers='Host: '+host+'\r\nConnection: close\r\n'
        if auth: headers+='Authorization: Basic '+base64.b64encode(b'viewer:testpass').decode()+'\r\nCookie: secret=cookie\r\n'
        sock.sendall((method+' '+path+' HTTP/1.1\r\n'+headers+'\r\n').encode())
        response=http.client.HTTPResponse(sock);response.begin();data=response.read();status=response.status;sock.close();return status,data
    def test_tls_auth_allowlist_query_isolation_and_reload(self):
        try: self.m.apply()
        except Exception:
            print((self.m.base/'gateway.log').read_text() if (self.m.base/'gateway.log').exists() else (self.m.base/'candidate.json').read_text())
            raise
        self.assertEqual(self.request('/camera/front/video.mjpeg',auth=False)[0],401)
        self.assertEqual(self.received,[])
        self.assertEqual(self.request('/camera/front/video.mjpeg?src=http://attacker.invalid/')[0],200)
        self.assertEqual(self.received[-1][0],'/api/stream.mjpeg?src=front_mjpeg')
        self.assertNotIn('Authorization',self.received[-1][1]); self.assertNotIn('Cookie',self.received[-1][1])
        self.assertEqual(self.request('/camera/front/snapshot.jpg?cam=private&key=evil'),(200,b'camera-bytes'))
        self.assertEqual(self.received[-1][0],'/plugins/u2l/snapshot.php?cam=front')
        for path in ['/api/config','/api/streams','/','/camera/private/video.mjpeg']:
            self.assertEqual(self.request(path)[0],404)
        self.assertEqual(self.request('/camera/front/video.mjpeg',method='POST')[0],404)
        self.assertEqual(self.request('/camera/front/video.mjpeg',host='attacker.example')[0],404)
        pid=self.m.process()
        self.m.apply(); self.assertEqual(self.m.process(),pid)
        self.m.store_certificate(self.cert.read_bytes(),self.key.read_bytes())
        self.assertEqual(self.m.process(),pid)
        self.assertEqual(self.request('/camera/front/video.mjpeg')[0],200)
        plugin=self.m.plugin();plugin['cameras'][0]['enabled']=False
        h.write_private(self.m.home/'config/plugins/u2l/config.json',plugin)
        self.m.watchdog()
        self.assertEqual(self.request('/camera/front/video.mjpeg')[0],404)
    def test_invalid_import_keeps_previous_generation(self):
        old=h.read_json(self.m.active_file)
        with self.assertRaises(h.Error): self.m.store_certificate(b'garbage',self.key.read_bytes())
        self.assertEqual(h.read_json(self.m.active_file),old)
        with self.assertRaises(h.Error): h.certificate_info(self.cert,self.key,'wrong.example.test')
    def test_busy_port_does_not_stop_other_service(self):
        self.settings['listen_port']=self.upstream.server_port
        self.settings['snapshot_port']=80
        h.write_private(self.m.settings_file,self.settings)
        plugin=self.m.plugin();plugin['server']['port']=1984
        h.write_private(self.m.home/'config/plugins/u2l/config.json',plugin)
        with self.assertRaises(h.Error): self.m.apply()
        self.assertIsNone(self.m.process())
        self.assertTrue(self.thread.is_alive())


if __name__=='__main__': unittest.main()
