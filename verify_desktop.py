"""Check a built executable against disposable loopback HTTP, DOCX and Qt UI."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


def verify(binary):
    requests = []
    class Target(BaseHTTPRequestHandler):
        def do_GET(self):
            requests.append(self.path)
            body = b'<html><title>Disposable release QA</title><p>Safe fixture</p></html>'
            self.send_response(200)
            self.send_header('Content-Type', 'text/html')
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        def log_message(self, *args):
            pass
    server = ThreadingHTTPServer(('127.0.0.1', 0), Target)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        with tempfile.TemporaryDirectory(prefix='desktop-release-qa-') as temporary:
            path = Path(temporary)
            url = f'http://127.0.0.1:{server.server_port}'
            spec = path / 'api.json'
            spec.write_text(json.dumps({'openapi': '3.0.3', 'info': {'title': 'QA', 'version': '1'},
                                       'servers': [{'url': url}], 'paths': {'/health': {'get': {'responses': {'200': {'description': 'OK'}}}}}}))
            env = dict(os.environ, QT_QPA_PLATFORM='offscreen')
            outputs = {}
            for name, args in [('api', ['--verify-local-api', url, str(spec)]),
                               ('gui', ['--verify-local-gui'])]:
                output = path / (name + '.json')
                subprocess.run([str(Path(binary).resolve()), *args, str(output)], env=env, check=True, timeout=90)
                outputs[name] = json.loads(output.read_text(encoding='utf-8'))
            assert outputs['api']['word_export_verified']
            assert outputs['api']['persistence_verified'] and outputs['api']['export_verified']
            assert outputs['gui']['gui_constructed']
            assert requests, 'No loopback traffic observed'
            # Only synthetic evidence goes into the release record.
            record = {'version': outputs['api']['application_version'], 'platform': sys.platform,
                      'api_word_json_persistence': True, 'gui_constructed': True,
                      'loopback_requests': len(requests), 'visual_review': False}
            Path('desktop-verification.json').write_text(json.dumps(record, indent=2), encoding='utf-8')
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)


if __name__ == '__main__':
    verify(sys.argv[1])
