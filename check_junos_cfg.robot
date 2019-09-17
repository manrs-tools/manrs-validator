*** Settings ***
Documentation  Check config file for MANRS standards compliance

Library  OperatingSystem
Library  String
Library  Collections
Variables  ${CURDIR}/${TEST_PLATFORM}.yaml

*** Variables ***
${TEST_PLATFORM}  junos


*** Test Cases ***
Check for config file
  ${status} =  Run keyword and return status  File should exist  ${CFG_FILE}
  Run keyword if  ${status} == ${FALSE}  Fatal error  File ${CFG_FILE} doesn't exist

Verify config file not empty
  ${status} =  Run keyword and return status  File should not be empty  ${CFG_FILE}
  Run keyword if  ${status} == ${FALSE}  Fatal error  File ${CFG_FILE} exists, but appears to be empty

Get config file contents
  ${cfg_data} =  Get File  ${CFG_FILE}
  @{RTR_CFG} =  Split to lines  ${cfg_data}
  Set Global Variable  ${cfg_data}
  Set Global Variable  @{RTR_CFG}

#Show config file
#  Log to console  \n
#  Log to console  ${RTR_CFG}

Show config file by lines
  #@{cfg_lines} =  Split to lines  ${RTR_CFG}
#  Log to console  \n
#  FOR  ${line}  IN  @{RTR_CFG}
#    Log to console  ${line}
#  END
  Get config interfaces

uRPF check on all interfaces - IPv4
#Need to add a method so that it will check all interfaces and alert on it instead of exiting on first error - same with next test of v6
  :FOR   ${if}   IN    @{ifaces.keys()}
      ${temp} =   Set Variable    ${ifaces["${if}"]}
      Should Contain    ${temp}    ${URPF}    ignore_case=True
  END   

uRPF check on all interfaces - IPv6
  :FOR   ${if}   IN    @{ifaces.keys()}
      ${temp} =   Set Variable    ${ifaces["${if}"]}
      Should Contain    ${temp}    ${URPF6}    ignore_case=True
  END   

RADIUS authenticated users - attribute 11
  Log to Console    This is Not Applicable to this config

DHCP via Ethernet - send traffic from src IP/MACs with DHCP offer
  Log to Console    Skipping this for now. This is more applicable to a switch than a Peering Router

DHCP via DOCSIS
  Log to Console    This is not applicable here

ACLs being applied to single homed stub customers to prevent them from sending spoofed traffic - IPv4
#checking whether an input filter is applied on every interface
  :FOR   ${if}   IN    @{ifaces.keys()}
      ${temp} =   Set Variable    ${ifaces["${if}"]}
      Should Contain    ${temp}    ${ACL_INP}    ignore_case=True
  END

ACLs being applied to single homed stub customers to prevent them from sending spoofed traffic - IPv6
#checking whether an input filter is applied on every interface
#ideally we want to check for every 'unit', that is, subinterface - doing it just on an interface globally for now
  :FOR   ${if}   IN    @{ifaces.keys()}
      ${temp} =   Set Variable    ${ifaces["${if}"]}
      Should Contain    ${temp}    ${ACL_INP6}    ignore_case=True
  END

Are inbound routing advertisements from customers and peers secured by applying prefix-level filters?
#Ideally we need to check for each BGP neighbor/group. Checking here only once.
  Should Match Regexp      ${cfg_data}     set protocols bgp group [ A-Za-z0-9_-]* import [ A-Za-z0-9_-]*     ignore_case=True

Are inbound routing advertisements restricted to only /24 and shorter for IPv4?
  Should Match Regexp       ${cfg_data}     route-filter \\d+.\\d+.\\d+.\\d+\\/\\d+ upto /24      ignore_case=True

Are inbound routing advertisements restricted to only /48 and shorter?
  Should Match Regexp       ${cfg_data}     route-filter [ A-Za-z0-9:]*::\\/\\d+ upto /48      ignore_case=True  

Are inbound routing advertisements secured by applying AS-path filters?
  Should Match Regexp       ${cfg_data}     set policy-options as-path [A-Za-z0-9_-]* |set policy-options as-path-group [A-Za-z0-9_-]*        ignore_case=True

Are outbound routing advertisements to peers and transit secured by applying prefix-level filters? (including bogon, spoof filters)
  Should Match Regexp      ${cfg_data}     set protocols bgp group [ A-Za-z0-9_-]* export [ A-Za-z0-9_-]*     ignore_case=True

Is the router configured to connect to a RPKI-to-Router interface for ROA validation?
  Should Match Regexp       ${cfg_data}     routing-options validation group [ A-Za-z0-9_-]* session \\d+.\\d+.\\d+.\\d+      ignore_case=True

Is the router configured to drop RPKI invalids?
#this is checking if there is a policy on Invalids - not whether invalids are Rejected
  Should Match Regexp       ${cfg_data}     policy-options policy-statement [ A-Za-z0-9_-]* term [ A-Za-z0-9_-]* from validation-database invalid      ignore_case=True

Are communities applied to routes recieved from customers? Are outbound filters applied to match only routes carrying the correct commmunity attribute?
#this is checking if community is being added or set on a particular policy
  Should Match Regexp       ${cfg_data}     set policy-options policy-statement [ A-Za-z0-9_-]* term [ A-Za-z0-9_-]* then community add [ A-Za-z0-9_-]*     ignore_case=True 

Is BGP TTL security (GTSM) applied to all BGP sessions?
#ttl or ttl-except
  Should Match Regexp       ${cfg_data}     ttl \\d+    ignore_case=True

Is the TCP Authentication Option applied to all BGP sessions?
  Log to Console     Not supported on MX

Is MD5 Authentication applied to all BGP sessions (where TCP AO is unavailable)?
  Should Match Regexp       ${cfg_data}     set protocols bgp group [ A-Za-z0-9_-]* authentication-key      ignore_case=True  

Is the maximum prefix feature enabled and set appropriately at each level of the network?
#OR accepted-prefix-limit
  Should Match Regexp       ${cfg_data}     prefix-limit      ignore_case=True

Is there control plane policing enabled on TCP port 179 - IPv4?
  Should Match Regexp       ${cfg_data}     set firewall family inet filter [ A-Za-z0-9_-]* term [ A-Za-z0-9_-]* from destination-port bgp         ignore_case=True

Is there control plane policing enabled on TCP port 179 - IPv6?
  Should Match Regexp       ${cfg_data}     set firewall family inet6 filter [ A-Za-z0-9_-]* term [ A-Za-z0-9_-]* from destination-port bgp         ignore_case=True

Is there an ACL only allowing TCP port 179 from peer IPs - IPv4?
#Need to match the correct term
  Should Match Regexp       ${cfg_data}     set firewall family inet filter [ A-Za-z0-9_-]* term [ A-Za-z0-9_-]* from source-address        ignore_case=True

Is there an ACL only allowing TCP port 179 from peer IPs - IPv6?
#Need to match the correct term
  Should Match Regexp       ${cfg_data}     set firewall family inet6 filter [ A-Za-z0-9_-]* term [ A-Za-z0-9_-]* from source-address        ignore_case=True

Is logging enabled for BGP neighbor activities?
  Should Match Regexp       ${cfg_data}     set protocols bgp log-updown         ignore_case=True

*** Keywords ***
Get config interfaces
  Set suite variable  &{ifaces}  &{EMPTY}
  FOR  ${line}  IN  @{RTR_CFG}
    ${if} =  Get regexp matches  ${line}  ^set\\sinterfaces\\s(.+?)\\s  1
    Run keyword if  ${if} != @{EMPTY}  Log to console  ${if}[0]  ELSE  Continue for loop
    ${status} =  Run keyword and return status  Dictionary Should Contain Key  ${ifaces}  ${if}[0]
    ${key} =  Set variable  ${if}[0]
    Run keyword if  ${status} == ${TRUE}  Set to dictionary  ${ifaces}  ${key}  ${ifaces}[${key}]${line}\n  ELSE  Set to dictionary  ${ifaces}  ${key}  ${line}
    #Run keyword if  ${status} == ${TRUE}  Log to console  Adding line  ELSE  Set to dictionary  ${ifaces}  ${key}  ${line}\n
  END
  Log to console  Dictionary contents:
  Log dictionary  ${ifaces}  WARN
#  FOR  ${if}  IN  &{ifaces}
#    Log to console  ${if}
#  END
#  :FOR   ${if}   IN    @{ifaces.keys()}
#      Log to console   ${ifaces["${if}"]}
#  END
#  Set Global Variable    &{ifaces}

#Get config BGP Peers
