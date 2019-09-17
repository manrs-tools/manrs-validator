# MANRS-validator
A BGP Security Auditing Tool that runs locally and checks configuration the router config against the best practices as defined by MANRS
Currently the solution uses RobotFramework (https://robotframework.org) to check the configuration against a .robot audit file and only supports JunOS 
## How to run
Install robot framework on the host 
```
pip install robotframework
```
Download the check_<platform>_cfg.robot file specific to your device config (only JunOS is avaialble at this time) and the <platform>.yaml file.
Edit the <platform>.yaml file and specify the name of your JunOS config file after the line that says "CFG_FILE:"
Example:
```
CFG_FILE: router.cfg
```
Next execute: 
```
robot check_<platform>_cfg.robot
```
and then a log.html, output.xml, and report.html file will appear in the directory providing you the results of the audit.

Check out (https://www.manrs.org/isps/guide/) for information about how to modify your configuration to be in compliance with MANRS guidelines and make your network and the Internet more secure!
