# Splunk Whisperer 2 (C#)
## Prerequisites
This tool requires at least .NET 4.5 (which isn't available by default on Windows 7 / 2008). If this condition is not met, see `PySplunkWhisperer2` in the same repository.

## Build instructions
I do not publish binaries on purpose. You have to build it yourself, for example with Visual Studio 2017 Community. The required packages are fetched by NuGet.

## Usage
`SharpSplunkWhisperer2` only implements Local Privilege Escalation (LPE) mode. For Remote Code Execution (RCE),  see `PySplunkWhisperer2` in the same repository.

The following arguments exist but are optional:
* `--UserName`, default="admin"
* `--Password`, default="changeme"
* `--Port`, default=8089
* `--Scheme`, default="https"
* `--Payload`, default="calc.exe"

The app bundle is created locally (temp file) and Splunk installs it from there.

## Supported platforms
`SharpSplunkWhisperer2` is designed to be run locally on Windows computers.

### Credits
This tool is inspired by [the original Splunk Whisperer](https://github.com/airman604/splunk_whisperer) by @airman604.

The main advantage of this version is that the Deployment Server used by the Universal Forwarder is not changed. It only installs a new application (then removes it) so it is less intrusive and the code is simpler.

### Disclaimer
Resources provided here are shared to demonstrate risk. These can be used only against systems you own or are authorized to test, these must not be used for illegal purposes.
The author cannot be held responsible for any misuse or damage from any material provided here.