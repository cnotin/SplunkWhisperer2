# Splunk Whisperer 2 (Python)
## Usage
I created two files to reduce dependencies (no HTTP server) when building the LPE executable file.

* Local Privilege Escalation (LPE): you have a shell on the computer, then use `PySplunkWhisperer2_local.py`. The following arguments exist but are optional:
    * `--scheme`, default="https"
    * `--port`, default=8089
    * `--username`, default="admin"
    * `--password`, default="changeme"
    * `--payload`, default="calc.exe"
    * `--payload-file`, default="pwn.bat"
    The app bundle is created locally (temp file) and Splunk installs it from there.


* Remote Code Execution (RCE): the Universal Forwarder is exposed, then use `PySplunkWhisperer2_remote.py`. The following arguments exist. They are all optional, except `--lport`:
    * `--scheme`, default="https"
    * `--port`, default=8089
    * `--lhost`, **required=True**
    * `--lport`, default=8181
    * `--username`, default="admin"
    * `--password`, default="changeme" (**note**: this default password does not work remotely by default)
    * `--payload`, default="calc.exe"
    * `--payload-file`, default="pwn.bat"
    The app bundle is created on your computer (temp file) and Splunk fetches it through HTTP (hence the need for `--lhost`).

## Supported platforms
The current code targets Universal Forwarders running on Windows by default. If you want to target Linux, change the payload with `--payload` and the payload filename with `--payload-file`.

* You can build an executable file for `PySplunkWhisperer2_local.py` with PyInstaller, see `build_exe.bat`, so you can run it on any Windows computer without having Python installed.
* `PySplunkWhisperer2_remote.py` runs on Windows and Linux

### Credits
This tool is inspired by [the original Splunk Whisperer](https://github.com/airman604/splunk_whisperer) by @airman604.

The main advantage of this version is that the Deployment Server used by the Universal Forwarder is not changed. It only installs a new application (then removes it) so it is less intrusive and the code is simpler.

### Disclaimer
Resources provided here are shared to demonstrate risk. These can be used only against systems you own or are authorized to test, these must not be used for illegal purposes.
The author cannot be held responsible for any misuse or damage from any material provided here.