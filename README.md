# SplunkWhisperer2
## Description
Local privilege escalation, or remote code execution, through Splunk Universal Forwarder (UF) misconfigurations.
See https://clement.notin.org/blog/2019/02/25/Splunk-Universal-Forwarder-Hijacking-2-SplunkWhisperer2/ for more details.

## Which one to use?
* You have a local shell on a Windows computer running Splunk UF?
    * If .NET 4.5, or later, is available (or you don't know), use `SharpSplunkWhisperer2`
    * Otherwise, use `PySplunkWhisperer2_local`
* You can contact remotely the Splunk UF API (HTTPS port 8089 by default) and you have the credentials (**note**: the default credentials are *admin/changeme* but they do not work remotely by default)?
    * Use `PySplunkWhisperer2_remote`

Note also that `SharpSplunkWhisperer2` relies on the [Splunk SDK for C#](http://dev.splunk.com/csharp) library, whereas `PySplunkWhisperer2` directly calls the [Splunk REST API](http://dev.splunk.com/restapi).

### Credits
These tools are inspired by [the original Splunk Whisperer](https://github.com/airman604/splunk_whisperer) by @airman604.

The main advantage of these versions is that the Deployment Server used by the UF is not changed. It only installs a new application (then removes it) so it is less intrusive and the code is simpler.

### Disclaimer
Resources provided here are shared to demonstrate risk. These can be used only against systems you own or are authorized to test, these must not be used for illegal purposes.
The author cannot be held responsible for any misuse or damage from any material provided here.
