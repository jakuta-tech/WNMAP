# NMAP BRUTEFORCING

Heard so many people that using nmap for port scanning only, here you get some tips and tricks so you can master nmap via commandline!

### afp-brute                              
_Performs password guessing against Apple Filing Protocol (AFP)_
     root@hostname: ~ nmap -p 548 --script afp-brute <host>

### ajp-brute     
_                        
     root@hostname: ~ nmap -p 8009 <ip> --script ajp-brute

### backorifice-brute                         
_    Performs brute force password auditing against the BackOrifice service_ The backorifice-brute_ports script argument is mandatory (it specifies ports to run the script against)_
     root@hostname: ~ nmap -sU --script backorifice-brute <host> --script-args backorifice-brute_ports=<ports>

### cassandra-brute                     
_  Performs brute force password auditing against the Cassandra database_
     root@hostname: ~ nmap -p 9160 <ip> --script=cassandra-brute

### cics-enum
_    CICS transaction ID enumerator for IBM mainframes_ This script is based on mainframe_brute by Dominic White (https://github_com/sensepost/mainframe_brute)_ However, this script doesn't rely on any third party libraries or tools and instead uses the NSE TN3270 library which emulates a TN3270 screen in lua_
     root@hostname: ~ nmap --script=cics-enum -p 23 <targets>
     root@hostname: ~ nmap --script=cics-enum --script-args=idlist=default_cics_txt cics-enum_command="exit;logon applid(cics42)" cics-enum_path="/home/dade/screenshots/",cics-enum_noSSL=true -p 23 <targets>


### cics-user-brute
_CICS User ID brute forcing script for the CESL login screen_
     root@hostname: ~ nmap --script=cics-user-brute -p 23 <targets>
     root@hostname: ~ nmap --script=cics-user-brute --script-args userdb=users_txt cics-user-brute_commands="exit;logon applid(cics42)" -p 23 <targets>


### cics-user-enum                           
_CICS User ID enumeration script for the CESL/CESN Login screen_
     root@hostname: ~ nmap --script=cics-user-enum -p 23 <targets>
     root@hostname: ~ nmap --script=cics-user-enum --script-args userdb=users_txt cics-user-enum_commands="exit;logon applid(cics42)" -p 23 <targets>



### citrix-brute-xml
_Attempts to guess valid credentials for the Citrix PN Web Agent XML Service_ The XML service authenticates against the local Windows server or the Active Directory_
     root@hostname: ~ nmap --script=citrix-brute-xml --script-args=userdb=<userdb>,passdb=<passdb>,ntdomain=<domain> -p 80,443,8080 <host>

### cvs-brute
_Performs brute force password auditing against CVS pserver authentication_
     root@hostname: ~ nmap -p 2401 --script cvs-brute <host>



### cvs-brute-repository
_Attempts to guess the name of the CVS repositories hosted on the remote server_ With knowledge of the correct repository name, usernames and passwords can be guessed_
     root@hostname: ~ nmap -p 2401 --script cvs-brute-repository <host>


### deluge-rpc-brute
_Performs brute force password auditing against the DelugeRPC daemon_
     root@hostname: ~ nmap --script deluge-rpc-brute -p 58846 <host>


### domcon-brute
_Performs brute force password auditing against the Lotus Domino Console_
     root@hostname: ~ nmap --script domcon-brute -p 2050 <host>
     PORT     STATE SERVICE REASON
     2050/tcp open  unknown syn-ack
    | domcon-brute:
    |   Accounts
    |_    patrik karlsson:secret => Login correct


### dpap-brute
_Performs brute force password auditing against an iPhoto Library_
     root@hostname: ~ nmap -p 50000 --script drda-brute <target>

### drda-brute
_Performs password guessing against databases supporting the IBM DB2 protocol such as Informix, DB2 and Derby
     root@hostname: ~ 

### ftp-brute
_Performs brute force password auditing against FTP servers_
     root@hostname: ~ 

### http-brute
_Performs brute force password auditing against http basic, digest and ntlm authentication_
     root@hostname: ~ 

### http-form-brute
_Performs brute force password auditing against http form-based authentication_
     root@hostname: ~ 

### http-iis-short-name-brute
_Attempts to brute force the 8_3 filenames (commonly known as short names) of files and directories in the root folder of vulnerable IIS servers_ This script is an implementation of the PoC "iis shortname scanner"_
     root@hostname: ~ 

### http-joomla-brute
_Performs brute force password auditing against Joomla web CMS installations_
     root@hostname: ~ 

### http-proxy-brute
_Performs brute force password guessing against HTTP proxy servers_
     root@hostname: ~ 

### http-wordpress-brute
_performs brute force password auditing against Wordpress CMS/blog installations_
     root@hostname: ~ 

### iax2-brute
_Performs brute force password auditing against the Asterisk IAX2 protocol_ Guessing fails when a large number of attempts is made due to the maxcallnumber limit (default 2048)_ In case your getting "ERROR: Too many retries, aborted ___" after a while, this is most likely what's happening_ In order to avoid this problem try: - reducing the size of your dictionary - use the brute delay option to introduce a delay between guesses - split the guessing up in chunks and wait for a while between them
     root@hostname: ~ 

### imap-brute
_Performs brute force password auditing against IMAP servers using either LOGIN, PLAIN, CRAM-MD5, DIGEST-MD5 or NTLM authentication_
     root@hostname: ~ 

### impress-remote-discover
_Tests for the presence of the LibreOffice Impress Remote server_ Checks if a PIN is valid if provided and will bruteforce the PIN if requested_
     root@hostname: ~ 

### informix-brute
_Performs brute force password auditing against IBM Informix Dynamic Server_
     root@hostname: ~ 

### ipmi-brute
_Performs brute force password auditing against IPMI RPC server_
     root@hostname: ~ 

### irc-brute
_Performs brute force password auditing against IRC (Internet Relay Chat) servers_
     root@hostname: ~ 

### irc-sasl-brute
_Performs brute force password auditing against IRC (Internet Relay Chat) servers supporting SASL authentication_
     root@hostname: ~ 

### iscsi-brute
_Performs brute force password auditing against iSCSI targets_
     root@hostname: ~ 

### ldap-brute
_Attempts to brute-force LDAP authentication_ By default it uses the built-in username and password lists_ In order to use your own lists use the userdb and passdb script arguments_
     root@hostname: ~ 

### lu-enum
_Attempts to enumerate Logical Units (LU) of TN3270E servers_
     root@hostname: ~ 

### membase-brute 
_Performs brute force password auditing against Couchbase Membase servers_
     root@hostname: ~ 

### metasploit-msgrpc-brute
_Performs brute force username and password auditing against Metasploit msgrpc interface_
     root@hostname: ~ 

### metasploit-xmlrpc-brute
_Performs brute force password auditing against a Metasploit RPC server using the XMLRPC protocol_
     root@hostname: ~ 

### mikrotik-routeros-brute
_Performs brute force password auditing against Mikrotik RouterOS devices with the API RouterOS interface enabled_
     root@hostname: ~ 

### mmouse-brute
_Performs brute force password auditing against the RPA Tech Mobile Mouse servers_
     root@hostname: ~ 

### mongodb-brute
_ Performs brute force password auditing against the MongoDB database_
     root@hostname: ~ 

### ms-sql-brute
_Performs password guessing against Microsoft SQL Server (ms-sql)_ Works best in conjunction with the broadcast-ms-sql-discover script_
     root@hostname: ~ 

### mysql-brute                         
_Performs password guessing against MySQL_
     root@hostname: ~ 

### mysql-enum                              
_Performs valid-user enumeration against MySQL server using a bug discovered and published by Kingcope (http://seclists_org/fulldisclosure/2012/Dec/9)_
     root@hostname: ~ 

### nessus-brute                             
_Performs brute force password auditing against a Nessus vulnerability scanning daemon using the NTP 1_2 protocol_
     root@hostname: ~ 

### nessus-xmlrpc-brute                   
_Performs brute force password auditing against a Nessus vulnerability scanning daemon using the XMLRPC protocol_
     root@hostname: ~ 

### netbus-brute                             
_Performs brute force password auditing against the Netbus backdoor ("remote administration") service_
     root@hostname: ~ 

### nexpose-brute                            
_Performs brute force password auditing against a Nexpose vulnerability scanner using the API 1_1_
     root@hostname: ~ 

### nje-node-brute                           
_z/OS JES Network Job Entry (NJE) target node name brute force_
     root@hostname: ~ 

### nje-pass-brute                           
_z/OS JES Network Job Entry (NJE) 'I record' password brute forcer_
     root@hostname: ~ 

### nping-brute                         
_Performs brute force password auditing against an Nping Echo service_
     root@hostname: ~ 

### omp2-brute                              
_Performs brute force password auditing against the OpenVAS manager using OMPv2_
     root@hostname: ~ 

### openvas-otp-brute                         
_Performs brute force password auditing against a OpenVAS vulnerability scanner daemon using the OTP 1_0 protocol_
     root@hostname: ~ 

### oracle-brute                             
_Performs brute force password auditing against Oracle servers_
     root@hostname: ~ 

### oracle-brute-stealth                  
_Exploits the CVE-2012-3137 vulnerability, a weakness in Oracle's O5LOGIN authentication scheme_ The vulnerability exists in Oracle 11g R1/R2 and allows linking the session key to a password hash_ When initiating an authentication attempt as a valid user the server will respond with a session key and salt_ Once received the script will disconnect the connection thereby not recording the login attempt_ The session key and salt can then be used to brute force the users password_
     root@hostname: ~ 

### oracle-sid-brute                     
_Guesses Oracle instance/SID names against the TNS-listener_
     root@hostname: ~ 

### pcanywhere-brute                     
_Performs brute force password auditing against the pcAnywhere remote access protocol_
     root@hostname: ~ 

### pgsql-brute                         
_Performs password guessing against PostgreSQL_
     root@hostname: ~ 

### pop3-brute                              
_Tries to log into a POP3 account by guessing usernames and passwords_
     root@hostname: ~ 

### redis-brute                         
_Performs brute force passwords auditing against a Redis key-value store_
     root@hostname: ~ 

### rexec-brute                         
_Performs brute force password auditing against the classic UNIX rexec (remote exec) service_
     root@hostname: ~ 

### rlogin-brute                            
_Performs brute force password auditing against the classic UNIX rlogin (remote login) service_ This script must be run in privileged mode on UNIX because it must bind to a low source port number_
     root@hostname: ~ 

### rpcap-brute                         
_Performs brute force password auditing against the WinPcap Remote Capture Daemon (rpcap)_
     root@hostname: ~ 

### rsync-brute                         
_Performs brute force password auditing against the rsync remote file syncing protocol_
     root@hostname: ~ 

### rtsp-url-brute                           
_Attempts to enumerate RTSP media URLS by testing for common paths on devices such as surveillance IP cameras_
     root@hostname: ~ 

### sip-brute                               
_Performs brute force password auditing against Session Initiation Protocol (SIP) accounts_ This protocol is most commonly associated with VoIP sessions_
     root@hostname: ~ 

### smb-brute                               
_Attempts to guess username/password combinations over SMB, storing discovered combinations for use in other scripts_ Every attempt will be made to get a valid list of users and to verify each username before actually using them_ When a username is discovered, besides being printed, it is also saved in the Nmap registry so other Nmap scripts can use it_ That means that if you're going to run smb-brute_nse, you should run other smb scripts you want_ This checks passwords in a case-insensitive way, determining case after a password is found, for Windows versions before Vista_
     root@hostname: ~ 

### smtp-brute                              
_Performs brute force password auditing against SMTP servers using either LOGIN, PLAIN, CRAM-MD5, DIGEST-MD5 or NTLM authentication_
     root@hostname: ~ 

### snmp-brute                              
_Attempts to find an SNMP community string by brute force guessing_
     root@hostname: ~ 

### socks-brute                         
_Performs brute force password auditing against SOCKS 5 proxy servers_
     root@hostname: ~ 

### ssh-brute                               
_Performs brute-force password guessing against ssh servers_
     root@hostname: ~ 

### svn-brute                               
_Performs brute force password auditing against Subversion source code control servers_
     root@hostname: ~ 

### telnet-brute                             
_Performs brute-force password auditing against telnet servers_
     root@hostname: ~ 

### tso-enum                                
_TSO User ID enumerator for IBM mainframes (z/OS)_ The TSO logon panel tells you when a user ID is valid or invalid with the message: IKJ56420I Userid <user ID> not authorized to use TSO_
     root@hostname: ~ 

### vmauthd-brute                            
_Performs brute force password auditing against the VMWare Authentication Daemon (vmware-authd)_
     root@hostname: ~ 

### vnc-brute                               
_Performs brute force password auditing against VNC servers_
     root@hostname: ~ 

### vtam-enum                               
_Many mainframes use VTAM screens to connect to various applications (CICS, IMS, TSO, and many more)_
     root@hostname: ~ 

### xmpp-brute                              
_Performs brute force password auditing against XMPP (Jabber) instant messaging servers_
     root@hostname: ~ 

### ========================================================================================================================================================

### ========================================================================================================================================================
### Port scanning
### ========================================================================================================================================================
nmap -Pn dhound_io                                                                                                                   ### Quick scan
nmap -p 1-65535 -Pn -sV -sS -T4 dhound_io                                                                                            ### Full TCP port scan using with service version detection
nmap -Pn -p 22,80,443 dhound_io                                                                                                      ### Scan particular ports
nmap -p 22 --open -sV 192_168_10_0/24                                                                                                ### Find linux devices in local network
nmap --traceroute -p 80 dhound_io                                                                                                    ### Trace trafic
nmap --traceroute --script traceroute-geolocation_nse -p 80 dhound_io                                                                ### Trace trafic with Geo resolving
nmap --script=asn-query dhound_io                                                                                                    ### WHOIS ISP, Country, Company
nmap --script ssl-cert -p 443 -Pn dhound_io                                                                                          ### Get SSL Certificate
nmap --script ssl-enum-ciphers -p 443 dhound_io                                                                                      ### Test SSL Ciphers
nmap --script ftp-brute --script-args userdb=users_txt,passdb=passwords_txt -p 21 -Pn dhound_io                                      ### Ftp Brute force
nmap --script http-brute -script-args http-brute_path=/evifile-bb-demo,userdb=users_txt,passdb=passwords_txt -p 80 -Pn dhound_io     ### HTTP Basic Authentication Brute force
nmap -sV --script http-wordpress-brute --script-args userdb=u,passdb=p_txt,http-wordpress-brute_hostname=d_nu,thrreads=10 -p 80 url  ### Wordpress Bruteforce
nmap --script default,safe -Pn dhound_io                                                                                             ### Find vulnerabilities in safe mode
nmap --script vuln -Pn dhound_io                                                                                                     ### Find vulnerabilities in unsafe mode
nmap --script dos -Pn dhound_io                                                                                                      ### Run DDos attack
nmap --script exploit -Pn dhound_io                                                                                                  ### Exploit detected vulnerabilities

