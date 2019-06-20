# NMAP BRUTEFORCING

Heard so many people that using nmap for port scanning only, here you get some tips and tricks so you can master nmap via commandline!

## AFP - Brute-Force                              
_Performs password guessing against Apple Filing Protocol (AFP)_
     
     roothostname: ~ nmap -p 548 --script afp-brute <host>

     PORT    STATE SERVICE
     548/tcp open  afp
     | afp-brute:
     |_  admin:KenSentMe => Valid credentials



## AJP - Brute-Force                          
     
     roothostname: ~ nmap -p 8009 <ip> --script ajp-brute

     PORT     STATE SERVICE
     8009/tcp open  ajp13
     | ajp-brute:
     |   Accounts
     |     root:secret - Valid credentials
     |   Statistics
     |_    Performed 1946 guesses in 23 seconds, average tps: 82



## Backorifice - Brute-Force                         
_Performs Brute-Force password auditing against the BackOrifice service_ The backorifice - Brute-Force_ports script argument is mandatory (it specifies ports to run the script against)_
     
     roothostname: ~ nmap -sU --script backorifice-brute <host> --script-args backorifice-brute.ports=<ports>

     PORT       STATE  SERVICE
     31337/udp  open   BackOrifice
     | backorifice-brute:
     |   Accounts:
     |     michael => Valid credentials
     |   Statistics
     |_    Perfomed 60023 guesses in 467 seconds, average tps: 138


## Cassandra - Brute-Force                     
_Performs Brute-Force password auditing against the Cassandra database_
     
     roothostname: ~ nmap -p 9160 <ip> --script=cassandra-brute

     PORT     STATE SERVICE VERSION
     9160/tcp open  apani1?
     | cassandra-brute:
     |   Accounts
     |     admin:lover - Valid credentials
     |     admin:lover - Valid credentials
     |   Statistics
     |_    Performed 4581 guesses in 1 seconds, average tps: 4581


## Cics-enum
_CICS transaction ID enumerator for IBM mainframes_ This script is based on mainframe_brute by Dominic White (https://github_com/sensepost/mainframe_brute)_ However, this script doesn't rely on any third party libraries or tools and instead uses the NSE TN3270 library which emulates a TN3270 screen in lua_
     
     roothostname: ~ nmap --script=cics-enum -p 23 <targets>
     roothostname: ~ nmap --script=cics-enum --script-args=idlist=default_cics.txt,cics-enum.command="exit;logon applid(cics42)",cics-enum.path="/home/dade/screenshots/",cics-enum.noSSL=true -p 23 <targets>

PORT   STATE SERVICE
23/tcp open  tn3270
| cics-enum:
|   Accounts:
|     CBAM: Valid - CICS Transaction ID
|     CETR: Valid - CICS Transaction ID
|     CEST: Valid - CICS Transaction ID
|     CMSG: Valid - CICS Transaction ID
|     CEDA: Valid - CICS Transaction ID
|     CEDF: Potentially Valid - CICS Transaction ID
|     DSNC: Valid - CICS Transaction ID
|_  Statistics: Performed 31 guesses in 114 seconds, average tps: 0



## Cics-User - Brute-Force
_CICS User ID brute forcing script for the CESL login screen_
     
      roothostname: ~ nmap --script=cics-user-brute -p 23 <targets>
      roothostname: ~ nmap --script=cics-user-brute --script-args userdb=users.txt cics-user-brute.commands="exit;logon applid(cics42)" -p 23 <targets>

PORT   STATE SERVICE
23/tcp open  tn3270
| cics-user-brute:
|   Accounts:
|     PLAGUE: Valid - CICS User ID
|_  Statistics: Performed 31 guesses in 114 seconds, average tps: 0



## Cics-User-Enum                           
_CICS User ID enumeration script for the CESL/CESN Login screen_
     
     roothostname: ~ nmap --script=cics-user-enum -p 23 <targets>
     roothostname: ~ nmap --script=cics-user-enum --script-args userdb=users_txt cics-user-enum_commands="exit;logon applid(cics42)" -p 23 <targets>
PORT   STATE SERVICE
23/tcp open  tn3270
| cics-user-enum:
|   Accounts:
|     PLAGUE: Valid - CICS User ID
|_  Statistics: Performed 31 guesses in 114 seconds, average tps: 0






## Citrix - Brute-Force-xml
_Attempts to guess valid credentials for the Citrix PN Web Agent XML Service_ The XML service authenticates against the local Windows server or the Active Directory_
     
     roothostname: ~ nmap --script=citrix - Brute-Force-xml --script-args=userdb=<userdb>,passdb=<passdb>,ntdomain=<domain> -p 80,443,8080 <host>

PORT     STATE SERVICE    REASON
8080/tcp open  http-proxy syn-ack
| citrix-brute-xml:
|   Joe:password => Must change password at next logon
|   Luke:summer => Login was successful
|_  Jane:secret => Account is disabled







## Cvs - Brute-Force
_Performs Brute-Force password auditing against CVS pserver authentication_
     
     roothostname: ~ nmap -p 2401 --script cvs-brute <host>

2401/tcp open  cvspserver syn-ack
| cvs-brute:
|   Accounts
|     hotchner:francisco - Account is valid
|     reid:secret - Account is valid
|   Statistics
|_    Performed 544 guesses in 14 seconds, average tps: 38



## Cvs Repository - Brute-Force 
_Attempts to guess the name of the CVS repositories hosted on the remote server_ With knowledge of the correct repository name, usernames and passwords can be guessed_
     
     roothostname: ~ nmap -p 2401 --script cvs-brute-repository <host>

PORT     STATE SERVICE    REASON
2401/tcp open  cvspserver syn-ack
| cvs-brute-repository:
|   Repositories
|     /myrepos
|     /demo
|   Statistics
|_    Performed 14 guesses in 1 seconds, average tps: 14



## Deluge-RPC - Brute-Force
_Performs Brute-Force password auditing against the DelugeRPC daemon_
     
     roothostname: ~ nmap --script deluge-rpc-brute -p 58846 <host>

PORT      STATE SERVICE REASON  TTL
58846/tcp open  unknown syn-ack 0
| deluge-rpc-brute:
|   Accounts
|     admin:default - Valid credentials
|   Statistics
|_    Performed 8 guesses in 1 seconds, average tps: 8



## Domcon - Brute-Force
_Performs Brute-Force password auditing against the Lotus Domino Console_
     
     roothostname: ~ nmap --script domcon-brute -p 2050 <host>

PORT     STATE SERVICE REASON
2050/tcp open  unknown syn-ack
| domcon-brute:
|   Accounts
|_    patrik karlsson:secret => Login correct



## DPAP - Brute-Force
_Performs Brute-Force password auditing against an iPhoto Library_
     
     roothostname: ~ nmap --script dpap-brute -p 8770 <host>

8770/tcp open  apple-iphoto syn-ack
| dpap-brute:
|   Accounts
|     secret => Login correct
|   Statistics
|_    Perfomed 5007 guesses in 6 seconds, average tps: 834









## DRDA - Brute-Force
_Performs password guessing against databases supporting the IBM DB2 protocol such as Informix, DB2 and Derby_
     
     roothostname: ~ 





## FTP - Brute-Force
_Performs Brute-Force password auditing against FTP servers_
     
     roothostname: ~ 



## HTTP - Brute-Force
_Performs Brute-Force password auditing against http basic, digest and ntlm authentication_
     
     roothostname: ~ 



## HTP-Form - Brute-Force
_Performs Brute-Force password auditing against http form-based authentication_
     
     roothostname: ~ 



## HTTP-IIS-Short-Name - Brute-Force
_Attempts to Brute-Force the 8_3 filenames (commonly known as short names) of files and directories in the root folder of vulnerable IIS servers_ This script is an implementation of the PoC "iis shortname scanner"_
     
     roothostname: ~ 



## HTTP-Joomla - Brute-Force
_Performs Brute-Force password auditing against Joomla web CMS installations_
     
     roothostname: ~ 



## HTTP-Proxy - Brute-Force
_Performs Brute-Force password guessing against HTTP proxy servers_
     
     roothostname: ~ 



## HTTP-WordPress - Brute-Force
_Performs Brute-Force password auditing against Wordpress CMS/blog installations_
     
     roothostname: ~ 



## IAX2 - Brute-Force
_Performs Brute-Force password auditing against the Asterisk IAX2 protocol_ Guessing fails when a large number of attempts is made due to the maxcallnumber limit (default 2048)_ In case your getting "ERROR: Too many retries, aborted ___" after a while, this is most likely what's happening_ In order to avoid this problem try: - reducing the size of your dictionary - use the brute delay option to introduce a delay between guesses - split the guessing up in chunks and wait for a while between them_   
     roothostname: ~



## IMAP - Brute-Force
_Performs Brute-Force password auditing against IMAP servers using either LOGIN, PLAIN, CRAM-MD5, DIGEST-MD5 or NTLM authentication_
     
     roothostname: ~ 



## Impress-Remote-Discover
_Tests for the presence of the LibreOffice Impress Remote server_ Checks if a PIN is valid if provided and will bruteforce the PIN if requested_
     
     roothostname: ~ 



## Informix - Brute-Force
_Performs Brute-Force password auditing against IBM Informix Dynamic Server_
     
     roothostname: ~ 



## IPMI - Brute-Force
_Performs Brute-Force password auditing against IPMI RPC server_
     
     roothostname: ~ 



## iRC - Brute-Force
_Performs Brute-Force password auditing against IRC (Internet Relay Chat) servers_
     
     roothostname: ~ 



## IRC-sasl - Brute-Force
_Performs Brute-Force password auditing against IRC (Internet Relay Chat) servers supporting SASL authentication_
     
     roothostname: ~ 



## ISCSI - Brute-Force
_Performs Brute-Force password auditing against iSCSI targets_
     
     roothostname: ~ 



## LDAP - Brute-Force
_Attempts to brute-force LDAP authentication_ By default it uses the built-in username and password lists_ In order to use your own lists use the userdb and passdb script arguments_
     
     roothostname: ~ 



## LU-Enum
_Attempts to enumerate Logical Units (LU) of TN3270E servers_
     
     roothostname: ~ 



## Membase - Brute-Force 
_Performs Brute-Force password auditing against Couchbase Membase servers_
     
     roothostname: ~ 



## Metasploit-MSGRPC - Brute-Force
_Performs Brute-Force username and password auditing against Metasploit msgrpc interface_
     
     roothostname: ~ 



## Metasploit-XMLRPC - Brute-Force
_Performs Brute-Force password auditing against a Metasploit RPC server using the XMLRPC protocol_
     
     roothostname: ~ 



## Mikrotik-RouterOS - Brute-Force
_Performs Brute-Force password auditing against Mikrotik RouterOS devices with the API RouterOS interface enabled_
     
     roothostname: ~ 



## MMouse - Brute-Force
_Performs Brute-Force password auditing against the RPA Tech Mobile Mouse servers_
     
     roothostname: ~ 



## MongoDB - Brute-Force
_ Performs Brute-Force password auditing against the MongoDB database_
     
     roothostname: ~ 



## MS-SQL - Brute-Force
_Performs password guessing against Microsoft SQL Server (ms-sql)_ Works best in conjunction with the broadcast-ms-sql-discover script_
     
     roothostname: ~ 



## MySQL - Brute-Force                         
_Performs password guessing against MySQL_
     
     roothostname: ~ 



## MySQL-enum                              
_Performs valid-user enumeration against MySQL server using a bug discovered and published by Kingcope (http://seclists_org/fulldisclosure/2012/Dec/9)_
     
     roothostname: ~ 



## Nessus - Brute-Force                             
_Performs Brute-Force password auditing against a Nessus vulnerability scanning daemon using the NTP 1_2 protocol_
     
     roothostname: ~ 



## Nessus-XMLRPC - Brute-Force                   
_Performs Brute-Force password auditing against a Nessus vulnerability scanning daemon using the XMLRPC protocol_
     
     roothostname: ~ 



## Netbus - Brute-Force                             
_Performs Brute-Force password auditing against the Netbus backdoor ("remote administration") service_
     
     roothostname: ~ 



## Nexpose - Brute-Force                            
_Performs Brute-Force password auditing against a Nexpose vulnerability scanner using the API 1_1_
     
     roothostname: ~ 



## NJE-Node - Brute-Force                           
_z/OS JES Network Job Entry (NJE) target node name Brute-Force_
     
     roothostname: ~ 



## NJE-Pass - Brute-Force                           
_z/OS JES Network Job Entry (NJE) 'I record' password Brute-Forcer_
     
     roothostname: ~ 



## Nping - Brute-Force                         
_Performs Brute-Force password auditing against an Nping Echo service_
     
     roothostname: ~ 



## OMPv2 - Brute-Force                              
_Performs Brute-Force password auditing against the OpenVAS manager using OMPv2_
     
     roothostname: ~ 



## OpenVAS-OTP - Brute-Force                         
_Performs Brute-Force password auditing against a OpenVAS vulnerability scanner daemon using the OTP 1_0 protocol_
     
     roothostname: ~ 



## Oracle - Brute-Force                             
_Performs Brute-Force password auditing against Oracle servers_
     
     roothostname: ~ 



## Oracle - Brute-Force-stealth                  
_Exploits the CVE-2012-3137 vulnerability, a weakness in Oracle's O5LOGIN authentication scheme_ The vulnerability exists in Oracle 11g R1/R2 and allows linking the session key to a password hash_ When initiating an authentication attempt as a valid user the server will respond with a session key and salt_ Once received the script will disconnect the connection thereby not recording the login attempt_ The session key and salt can then be used to Brute-Force the users password_
     
     roothostname: ~ 



## oracle-sid - Brute-Force                     
_Guesses Oracle instance/SID names against the TNS-listener_
     
     roothostname: ~ 



## pcAnywhere - Brute-Force                     
_Performs Brute-Force password auditing against the pcAnywhere remote access protocol_
     
     roothostname: ~ 



## PostgreSQL - Brute-Force                         
_Performs password guessing against PostgreSQL_
     
     roothostname: ~ 



## POP3 - Brute-Force                              
_Tries to log into a POP3 account by guessing usernames and passwords_
     
     roothostname: ~ 



## Redis - Brute-Force                         
_Performs Brute-Force passwords auditing against a Redis key-value store_
     
     roothostname: ~ 



## RExec - Brute-Force                         
_Performs Brute-Force password auditing against the classic UNIX rexec (remote exec) service_
     
     roothostname: ~ 



## UNIX-RLogin - Brute-Force                            
_Performs Brute-Force password auditing against the classic UNIX rlogin (remote login) service_ This script must be run in privileged mode on UNIX because it must bind to a low source port number_
     
     roothostname: ~ 



## RPcap - Brute-Force                         
_Performs Brute-Force password auditing against the WinPcap Remote Capture Daemon (rpcap)_
     
     roothostname: ~ 



## Rsync - Brute-Force                         
_Performs Brute-Force password auditing against the rsync remote file syncing protocol_
     
     roothostname: ~ 



## RTSP-Url - Brute-Force                           
_Attempts to enumerate RTSP media URLS by testing for common paths on devices such as surveillance IP cameras_
     
     roothostname: ~ 



## SIP - Brute-Force                               
_Performs Brute-Force password auditing against Session Initiation Protocol (SIP) accounts_ This protocol is most commonly associated with VoIP sessions_
     
     roothostname: ~ 



## SMB - Brute-Force                               
_Attempts to guess username/password combinations over SMB, storing discovered combinations for use in other scripts_ Every attempt will be made to get a valid list of users and to verify each username before actually using them_ When a username is discovered, besides being printed, it is also saved in the Nmap registry so other Nmap scripts can use it_ That means that if you're going to run smb - Brute-Force_nse, you should run other smb scripts you want_ This checks passwords in a case-insensitive way, determining case after a password is found, for Windows versions before Vista_
     
     roothostname: ~ 



## SMTP - Brute-Force                              
_Performs Brute-Force password auditing against SMTP servers using either LOGIN, PLAIN, CRAM-MD5, DIGEST-MD5 or NTLM authentication_
     
     roothostname: ~ 



## SNMP - Brute-Force                              
_Attempts to find an SNMP community string by Brute-Force guessing_
     
     roothostname: ~ 



## SOCKS5-Proxy - Brute-Force                         
_Performs Brute-Force password auditing against SOCKS 5 proxy servers_
     
     roothostname: ~ 



## SSH - Brute-Force                               
_Performs brute-force password guessing against ssh servers_
     
     roothostname: ~ 



## SVN - Brute-Force                               
_Performs Brute-Force password auditing against Subversion source code control servers_
     
     roothostname: ~ 



## Telnet - Brute-Force                             
_Performs brute-force password auditing against telnet servers_
     
     roothostname: ~ 



## TSO-Enum                                
_TSO User ID enumerator for IBM mainframes (z/OS)_ The TSO logon panel tells you when a user ID is valid or invalid with the message: IKJ56420I Userid <user ID> not authorized to use TSO_
     
     roothostname: ~ 



## VMWare Authentication Daemon - BruteForce                            
_Performs Brute-Force password auditing against the VMWare Authentication Daemon (vmware-authd)_
     
     roothostname: ~ 



## VNC - Brute-Force                               
_Performs Brute-Force password auditing against VNC servers_
     
     roothostname: ~ 



## VTAM-Enum                               
_Many mainframes use VTAM screens to connect to various applications (CICS, IMS, TSO, and many more)_
     
     roothostname: ~ 



## XMPP - Brute-Force                              
_Performs Brute-Force password auditing against XMPP (Jabber) instant messaging servers_
     
     roothostname: ~ 


## ========================================================================================================================================================
## Port scanning
## ========================================================================================================================================================
nmap -Pn dhound_io                                                                                                                   ## Quick scan
nmap -p 1-65535 -Pn -sV -sS -T4 dhound_io                                                                                            ## Full TCP port scan using with service version detection
nmap -Pn -p 22,80,443 dhound_io                                                                                                      ## Scan particular ports
nmap -p 22 --open -sV 192_168_10_0/24                                                                                                ## Find linux devices in local network
nmap --traceroute -p 80 dhound_io                                                                                                    ## Trace trafic
nmap --traceroute --script traceroute-geolocation_nse -p 80 dhound_io                                                                ## Trace trafic with Geo resolving
nmap --script=asn-query dhound_io                                                                                                    ## WHOIS ISP, Country, Company
nmap --script ssl-cert -p 443 -Pn dhound_io                                                                                          ## Get SSL Certificate
nmap --script ssl-enum-ciphers -p 443 dhound_io                                                                                      ## Test SSL Ciphers
nmap --script ftp - Brute-Force --script-args userdb=users_txt,passdb=passwords_txt -p 21 -Pn dhound_io                                      ## Ftp Brute-Force
nmap --script http - Brute-Force -script-args http - Brute-Force_path=/evifile-bb-demo,userdb=users_txt,passdb=passwords_txt -p 80 -Pn dhound_io     ## HTTP Basic Authentication Brute-Force
nmap -sV --script http-wordpress - Brute-Force --script-args userdb=u,passdb=p_txt,http-wordpress - Brute-Force_hostname=d_nu,thrreads=10 -p 80 url  ## Wordpress Bruteforce
nmap --script default,safe -Pn dhound_io                                                                                             ## Find vulnerabilities in safe mode
nmap --script vuln -Pn dhound_io                                                                                                     ## Find vulnerabilities in unsafe mode
nmap --script dos -Pn dhound_io                                                                                                      ## Run DDos attack
nmap --script exploit -Pn dhound_io                                                                                                  ## Exploit detected vulnerabilities

