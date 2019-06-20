# NMAP BRUTEFORCING

Heard so many people that using nmap for port scanning only, here you get some tips and tricks so you can master nmap via commandline!

### afp-brute                              
__Performs password guessing against Apple Filing Protocol (AFP)__
     root@hostname: ~ nmap -p 548 --script afp-brute <host>

### ajp-brute     
__                        
     root@hostname: ~ nmap -p 8009 <ip> --script ajp-brute

### backorifice-brute                         
__    Performs brute force password auditing against the BackOrifice service__ The backorifice-brute__ports script argument is mandatory (it specifies ports to run the script against)__
     root@hostname: ~ nmap -sU --script backorifice-brute <host> --script-args backorifice-brute__ports=<ports>

### cassandra-brute                     
__  Performs brute force password auditing against the Cassandra database__
     root@hostname: ~ nmap -p 9160 <ip> --script=cassandra-brute

### cics-enum
__    CICS transaction ID enumerator for IBM mainframes__ This script is based on mainframe_brute by Dominic White (https://github__com/sensepost/mainframe_brute)__ However, this script doesn't rely on any third party libraries or tools and instead uses the NSE TN3270 library which emulates a TN3270 screen in lua__
     root@hostname: ~ nmap --script=cics-enum -p 23 <targets>
     root@hostname: ~ nmap --script=cics-enum --script-args=idlist=default_cics__txt cics-enum__command="exit;logon applid(cics42)" cics-enum__path="/home/dade/screenshots/",cics-enum__noSSL=true -p 23 <targets>


### cics-user-brute
__CICS User ID brute forcing script for the CESL login screen__
     root@hostname: ~ nmap --script=cics-user-brute -p 23 <targets>
     root@hostname: ~ nmap --script=cics-user-brute --script-args userdb=users__txt cics-user-brute__commands="exit;logon applid(cics42)" -p 23 <targets>


### cics-user-enum                           
__CICS User ID enumeration script for the CESL/CESN Login screen__
     root@hostname: ~ nmap --script=cics-user-enum -p 23 <targets>
     root@hostname: ~ nmap --script=cics-user-enum --script-args userdb=users__txt cics-user-enum__commands="exit;logon applid(cics42)" -p 23 <targets>



### citrix-brute-xml
__Attempts to guess valid credentials for the Citrix PN Web Agent XML Service__ The XML service authenticates against the local Windows server or the Active Directory__
     root@hostname: ~ nmap --script=citrix-brute-xml --script-args=userdb=<userdb>,passdb=<passdb>,ntdomain=<domain> -p 80,443,8080 <host>

### cvs-brute
__Performs brute force password auditing against CVS pserver authentication__
     root@hostname: ~ nmap -p 2401 --script cvs-brute <host>



### cvs-brute-repository
__Attempts to guess the name of the CVS repositories hosted on the remote server__ With knowledge of the correct repository name, usernames and passwords can be guessed__
     root@hostname: ~ nmap -p 2401 --script cvs-brute-repository <host>


### deluge-rpc-brute
__Performs brute force password auditing against the DelugeRPC daemon__
     root@hostname: ~ nmap --script deluge-rpc-brute -p 58846 <host>


### domcon-brute
__Performs brute force password auditing against the Lotus Domino Console__
     root@hostname: ~ nmap --script domcon-brute -p 2050 <host>
     PORT     STATE SERVICE REASON
     2050/tcp open  unknown syn-ack
    | domcon-brute:
    |   Accounts
    |_    patrik karlsson:secret => Login correct


### dpap-brute
__Performs brute force password auditing against an iPhoto Library__
     root@hostname: ~ nmap -p 50000 --script drda-brute <target>

### drda-brute
__Performs password guessing against databases supporting the IBM DB2 protocol such as Informix, DB2 and Derby
     root@hostname: ~ 

### ftp-brute
__Performs brute force password auditing against FTP servers__
     root@hostname: ~ 

### http-brute
__Performs brute force password auditing against http basic, digest and ntlm authentication__
     root@hostname: ~ 

### http-form-brute
__Performs brute force password auditing against http form-based authentication__
     root@hostname: ~ 

### http-iis-short-name-brute
__Attempts to brute force the 8__3 filenames (commonly known as short names) of files and directories in the root folder of vulnerable IIS servers__ This script is an implementation of the PoC "iis shortname scanner"__
     root@hostname: ~ 

### http-joomla-brute
__Performs brute force password auditing against Joomla web CMS installations__
     root@hostname: ~ 

### http-proxy-brute
__Performs brute force password guessing against HTTP proxy servers__
     root@hostname: ~ 

### http-wordpress-brute
__performs brute force password auditing against Wordpress CMS/blog installations__
     root@hostname: ~ 

### iax2-brute
__Performs brute force password auditing against the Asterisk IAX2 protocol__ Guessing fails when a large number of attempts is made due to the maxcallnumber limit (default 2048)__ In case your getting "ERROR: Too many retries, aborted ______" after a while, this is most likely what's happening__ In order to avoid this problem try: - reducing the size of your dictionary - use the brute delay option to introduce a delay between guesses - split the guessing up in chunks and wait for a while between them
     root@hostname: ~ 

### imap-brute
__Performs brute force password auditing against IMAP servers using either LOGIN, PLAIN, CRAM-MD5, DIGEST-MD5 or NTLM authentication__
     root@hostname: ~ 

### impress-remote-discover
__Tests for the presence of the LibreOffice Impress Remote server__ Checks if a PIN is valid if provided and will bruteforce the PIN if requested__
     root@hostname: ~ 

### informix-brute
__Performs brute force password auditing against IBM Informix Dynamic Server__
     root@hostname: ~ 

### ipmi-brute
__Performs brute force password auditing against IPMI RPC server__
     root@hostname: ~ 

### irc-brute
__Performs brute force password auditing against IRC (Internet Relay Chat) servers__
     root@hostname: ~ 

### irc-sasl-brute
__Performs brute force password auditing against IRC (Internet Relay Chat) servers supporting SASL authentication__
     root@hostname: ~ 

### iscsi-brute
__Performs brute force password auditing against iSCSI targets__
     root@hostname: ~ 

### ldap-brute
__Attempts to brute-force LDAP authentication__ By default it uses the built-in username and password lists__ In order to use your own lists use the userdb and passdb script arguments__
     root@hostname: ~ 

### lu-enum
__Attempts to enumerate Logical Units (LU) of TN3270E servers__
     root@hostname: ~ 

### membase-brute 
__Performs brute force password auditing against Couchbase Membase servers__
     root@hostname: ~ 

### metasploit-msgrpc-brute
__Performs brute force username and password auditing against Metasploit msgrpc interface__
     root@hostname: ~ 

### metasploit-xmlrpc-brute
__Performs brute force password auditing against a Metasploit RPC server using the XMLRPC protocol__
     root@hostname: ~ 

### mikrotik-routeros-brute
__Performs brute force password auditing against Mikrotik RouterOS devices with the API RouterOS interface enabled__
     root@hostname: ~ 

### mmouse-brute
__Performs brute force password auditing against the RPA Tech Mobile Mouse servers__
     root@hostname: ~ 

### mongodb-brute
__ Performs brute force password auditing against the MongoDB database__
     root@hostname: ~ 

### ms-sql-brute
__Performs password guessing against Microsoft SQL Server (ms-sql)__ Works best in conjunction with the broadcast-ms-sql-discover script__
     root@hostname: ~ 

### mysql-brute                         
__Performs password guessing against MySQL__
     root@hostname: ~ 

### mysql-enum                              
__Performs valid-user enumeration against MySQL server using a bug discovered and published by Kingcope (http://seclists__org/fulldisclosure/2012/Dec/9)__
     root@hostname: ~ 

### nessus-brute                             
__Performs brute force password auditing against a Nessus vulnerability scanning daemon using the NTP 1__2 protocol__
     root@hostname: ~ 

### nessus-xmlrpc-brute                   
__Performs brute force password auditing against a Nessus vulnerability scanning daemon using the XMLRPC protocol__
     root@hostname: ~ 

### netbus-brute                             
__Performs brute force password auditing against the Netbus backdoor ("remote administration") service__
     root@hostname: ~ 

### nexpose-brute                            
__Performs brute force password auditing against a Nexpose vulnerability scanner using the API 1__1__
     root@hostname: ~ 

### nje-node-brute                           
__z/OS JES Network Job Entry (NJE) target node name brute force__
     root@hostname: ~ 

### nje-pass-brute                           
__z/OS JES Network Job Entry (NJE) 'I record' password brute forcer__
     root@hostname: ~ 

### nping-brute                         
__Performs brute force password auditing against an Nping Echo service__
     root@hostname: ~ 

### omp2-brute                              
__Performs brute force password auditing against the OpenVAS manager using OMPv2__
     root@hostname: ~ 

### openvas-otp-brute                         
__Performs brute force password auditing against a OpenVAS vulnerability scanner daemon using the OTP 1__0 protocol__
     root@hostname: ~ 

### oracle-brute                             
__Performs brute force password auditing against Oracle servers__
     root@hostname: ~ 

### oracle-brute-stealth                  
__Exploits the CVE-2012-3137 vulnerability, a weakness in Oracle's O5LOGIN authentication scheme__ The vulnerability exists in Oracle 11g R1/R2 and allows linking the session key to a password hash__ When initiating an authentication attempt as a valid user the server will respond with a session key and salt__ Once received the script will disconnect the connection thereby not recording the login attempt__ The session key and salt can then be used to brute force the users password__
     root@hostname: ~ 

### oracle-sid-brute                     
__Guesses Oracle instance/SID names against the TNS-listener__
     root@hostname: ~ 

### pcanywhere-brute                     
__Performs brute force password auditing against the pcAnywhere remote access protocol__
     root@hostname: ~ 

### pgsql-brute                         
__Performs password guessing against PostgreSQL__
     root@hostname: ~ 

### pop3-brute                              
__Tries to log into a POP3 account by guessing usernames and passwords__
     root@hostname: ~ 

### redis-brute                         
__Performs brute force passwords auditing against a Redis key-value store__
     root@hostname: ~ 

### rexec-brute                         
__Performs brute force password auditing against the classic UNIX rexec (remote exec) service__
     root@hostname: ~ 

### rlogin-brute                            
__Performs brute force password auditing against the classic UNIX rlogin (remote login) service__ This script must be run in privileged mode on UNIX because it must bind to a low source port number__
     root@hostname: ~ 

### rpcap-brute                         
__Performs brute force password auditing against the WinPcap Remote Capture Daemon (rpcap)__
     root@hostname: ~ 

### rsync-brute                         
__Performs brute force password auditing against the rsync remote file syncing protocol__
     root@hostname: ~ 

### rtsp-url-brute                           
__Attempts to enumerate RTSP media URLS by testing for common paths on devices such as surveillance IP cameras__
     root@hostname: ~ 

### sip-brute                               
__Performs brute force password auditing against Session Initiation Protocol (SIP) accounts__ This protocol is most commonly associated with VoIP sessions__
     root@hostname: ~ 

### smb-brute                               
__Attempts to guess username/password combinations over SMB, storing discovered combinations for use in other scripts__ Every attempt will be made to get a valid list of users and to verify each username before actually using them__ When a username is discovered, besides being printed, it is also saved in the Nmap registry so other Nmap scripts can use it__ That means that if you're going to run smb-brute__nse, you should run other smb scripts you want__ This checks passwords in a case-insensitive way, determining case after a password is found, for Windows versions before Vista__
     root@hostname: ~ 

### smtp-brute                              
__Performs brute force password auditing against SMTP servers using either LOGIN, PLAIN, CRAM-MD5, DIGEST-MD5 or NTLM authentication__
     root@hostname: ~ 

### snmp-brute                              
__Attempts to find an SNMP community string by brute force guessing__
     root@hostname: ~ 

### socks-brute                         
__Performs brute force password auditing against SOCKS 5 proxy servers__
     root@hostname: ~ 

### ssh-brute                               
__Performs brute-force password guessing against ssh servers__
     root@hostname: ~ 

### svn-brute                               
__Performs brute force password auditing against Subversion source code control servers__
     root@hostname: ~ 

### telnet-brute                             
__Performs brute-force password auditing against telnet servers__
     root@hostname: ~ 

### tso-enum                                
__TSO User ID enumerator for IBM mainframes (z/OS)__ The TSO logon panel tells you when a user ID is valid or invalid with the message: IKJ56420I Userid <user ID> not authorized to use TSO__
     root@hostname: ~ 

### vmauthd-brute                            
__Performs brute force password auditing against the VMWare Authentication Daemon (vmware-authd)__
     root@hostname: ~ 

### vnc-brute                               
__Performs brute force password auditing against VNC servers__
     root@hostname: ~ 

### vtam-enum                               
__Many mainframes use VTAM screens to connect to various applications (CICS, IMS, TSO, and many more)__
     root@hostname: ~ 

### xmpp-brute                              
__Performs brute force password auditing against XMPP (Jabber) instant messaging servers__
     root@hostname: ~ 

### ========================================================================================================================================================

### ========================================================================================================================================================
### Port scanning
### ========================================================================================================================================================
nmap -Pn dhound__io                                                                                                                   ### Quick scan
nmap -p 1-65535 -Pn -sV -sS -T4 dhound__io                                                                                            ### Full TCP port scan using with service version detection
nmap -Pn -p 22,80,443 dhound__io                                                                                                      ### Scan particular ports
nmap -p 22 --open -sV 192__168__10__0/24                                                                                                ### Find linux devices in local network
nmap --traceroute -p 80 dhound__io                                                                                                    ### Trace trafic
nmap --traceroute --script traceroute-geolocation__nse -p 80 dhound__io                                                                ### Trace trafic with Geo resolving
nmap --script=asn-query dhound__io                                                                                                    ### WHOIS ISP, Country, Company
nmap --script ssl-cert -p 443 -Pn dhound__io                                                                                          ### Get SSL Certificate
nmap --script ssl-enum-ciphers -p 443 dhound__io                                                                                      ### Test SSL Ciphers
nmap --script ftp-brute --script-args userdb=users__txt,passdb=passwords__txt -p 21 -Pn dhound__io                                      ### Ftp Brute force
nmap --script http-brute -script-args http-brute__path=/evifile-bb-demo,userdb=users__txt,passdb=passwords__txt -p 80 -Pn dhound__io     ### HTTP Basic Authentication Brute force
nmap -sV --script http-wordpress-brute --script-args userdb=u,passdb=p__txt,http-wordpress-brute__hostname=d__nu,thrreads=10 -p 80 url  ### Wordpress Bruteforce
nmap --script default,safe -Pn dhound__io                                                                                             ### Find vulnerabilities in safe mode
nmap --script vuln -Pn dhound__io                                                                                                     ### Find vulnerabilities in unsafe mode
nmap --script dos -Pn dhound__io                                                                                                      ### Run DDos attack
nmap --script exploit -Pn dhound__io                                                                                                  ### Exploit detected vulnerabilities

