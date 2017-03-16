DBC2
============
LAST/CURRENT VERSION: 0.1

Author: truneski - [@truneski](http://twitter.com/truneski)

Invoke-DBC2 (DropboxC2) is a POC modular post-exploitation tool, composed of a Powershell agent running on the victim's machine, 
a controller, running on any machine, powershell modules, and Dropbox servers as a means of communication.

This project came about by my desire to teach myself powershell further and see how far I can push myself.
Inspired by DBC2 (DropboxC2) by [@Arno0x0x](http://twitter.com/Arno0x0x) 
  
The app is distributed under the terms of the [GPLv3 licence](http://www.gnu.org/copyleft/gpl.html).

Architecture
----------------

![DBC2 Architecture](https://dl.dropboxusercontent.com/s/bwgtzt1x5e3zpxe/dbc2_architecture.jpg?dl=0 "DBC2 Architecture")


Features
----------------

DBC2 main features:
  - Various stager (Powershell one liner, batch file, MS-Office macro, javascript, msbuild file, SCT file, ducky, more to come...)
  - Single CLI commands (*one at a time, no environment persistency*)
  - Pseudo-interactive shell (*environment persistency*) - based on an idea from *0xDEADBEEF00 [at] gmail.com*
  - Send file to the agent
  - Retrieve file from the agent
  - Launch processes on the agent
  - Run and interact with PowerShell modules (*Endless capabilities: PowerSploit, Inveigh, Nishang, Empire modules, Powercat, etc.*)
  - Set persistency through Registry RunKey
  
Dependencies & requirements
----------------

DBC2 requires a Dropbox application (*"App folder" only is sufficient*) to be created within your Dropbox account and an access token generated for this application, in order to be able to perform API calls. Look at the intoduction video on how to do this if you're unsure.

On the controller side, DBC2 requires:
* Python 2.7 (not tested with Python 3)
* The following libraries, that can be installed using `pip install -r requirements.txt`:
  - requests>=2.11
  - tabulate
  - pyscrypt
  - pycrypto

DBC2 controller has been successfully tested and used on Linux Kali and Mac OSX.

On the agent side, DBC2 requires:
* .Net framework >= 4.5 (tested sucessfully on Windows 7 and Windows 10)

Security Aspects
-----------

DBC2 controller asks for a DropBox Accesstoken when it starts. The master key and IV need to be set manually `pollingThread.py` script found in lib.
DBC2 performs end-to-end encryption of data using the master key with AES-128/CBC mode. Data exchanged between the agent and the controller flows through the Dropbox servers so while the transfer itself is encrypted, thanks to HTTPS, data has to be end-to-end encrypted to protect the data while at rest on the Dropbox servers.

Installation & Configuration
------------

Installation is pretty straight forward:
* Git clone this repository: `git clone https://github.com/Arno0x/DBC2 dbc2`
* cd into the DBC2 folder: `cd dbc2`
* Install requirements using `pip install -r requirements.txt`
* Give the execution rights to the main script: `chmod +x dropboxC2.py`

To start the controller, simply type `./dropboxC2.py`.

Configuration is done through the `config.py` file:
* You can optionnally specify your Dropbox API access token. If you do so, the controller won't ask you for these when it starts.

Agent Stage
------------
You first have to manually set your Dropbox accesstoken in the Dropbox class which handles the communications with Dropbox.
You could also set a different key and iv instead of the hardcoded ones I've shipped with the script.

DISCLAIMER
----------------
This tool is intended to be used in a legal and legitimate way only:
  - either on your own systems as a means of learning, of demonstrating what can be done and how, or testing your defense and detection mechanisms
  - on systems you've been officially and legitimately entitled to perform some security assessments (pentest, security audits)

Quoting Empire's authors:
*There is no way to build offensive tools useful to the legitimate infosec industry while simultaneously preventing malicious actors from abusing them.*

Author
----------------
Truneski - You can contact me on my twitter page (@truneski).

