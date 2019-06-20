#!/bin/bash

# NMAP BRUTEFORCING
# afp-brute                              
### Performs password guessing against Apple Filing Protocol (AFP).
     root@hostname: ~ nmap -p 548 --script afp-brute <host>

# ajp-brute     
###                         
     root@hostname: ~ nmap -p 8009 <ip> --script ajp-brute

# backorifice-brute                         
###     Performs brute force password auditing against the BackOrifice service. The backorifice-brute.ports script argument is mandatory (it specifies ports to run the script against).
     root@hostname: ~ nmap -sU --script backorifice-brute <host> --script-args backorifice-brute.ports=<ports>

# cassandra-brute                     
###   Performs brute force password auditing against the Cassandra database.
     root@hostname: ~ nmap -p 9160 <ip> --script=cassandra-brute

# cics-enum
###     CICS transaction ID enumerator for IBM mainframes. This script is based on mainframe_brute by Dominic White (https://github.com/sensepost/mainframe_brute). However, this script doesn't rely on any third party libraries or tools and instead uses the NSE TN3270 library which emulates a TN3270 screen in lua.
     root@hostname: ~ nmap --script=cics-enum -p 23 <targets>
     root@hostname: ~ nmap --script=cics-enum --script-args=idlist=default_cics.txt cics-enum.command="exit;logon applid(cics42)" cics-enum.path="/home/dade/screenshots/",cics-enum.noSSL=true -p 23 <targets>


# cics-user-brute
### CICS User ID brute forcing script for the CESL login screen.
     root@hostname: ~ nmap --script=cics-user-brute -p 23 <targets>
     root@hostname: ~ nmap --script=cics-user-brute --script-args userdb=users.txt cics-user-brute.commands="exit;logon applid(cics42)" -p 23 <targets>


# cics-user-enum                           
### CICS User ID enumeration script for the CESL/CESN Login screen.
     root@hostname: ~ nmap --script=cics-user-enum -p 23 <targets>
     root@hostname: ~ nmap --script=cics-user-enum --script-args userdb=users.txt cics-user-enum.commands="exit;logon applid(cics42)" -p 23 <targets>



# citrix-brute-xml
### Attempts to guess valid credentials for the Citrix PN Web Agent XML Service. The XML service authenticates against the local Windows server or the Active Directory.
     root@hostname: ~ nmap --script=citrix-brute-xml --script-args=userdb=<userdb>,passdb=<passdb>,ntdomain=<domain> -p 80,443,8080 <host>

# cvs-brute
### Performs brute force password auditing against CVS pserver authentication.
     root@hostname: ~ nmap -p 2401 --script cvs-brute <host>



# cvs-brute-repository
### Attempts to guess the name of the CVS repositories hosted on the remote server. With knowledge of the correct repository name, usernames and passwords can be guessed.
     root@hostname: ~ nmap -p 2401 --script cvs-brute-repository <host>


# deluge-rpc-brute
### Performs brute force password auditing against the DelugeRPC daemon.
     root@hostname: ~ nmap --script deluge-rpc-brute -p 58846 <host>


# domcon-brute
### Performs brute force password auditing against the Lotus Domino Console.
     root@hostname: ~ nmap --script domcon-brute -p 2050 <host>
     PORT     STATE SERVICE REASON
     2050/tcp open  unknown syn-ack
    | domcon-brute:
    |   Accounts
    |_    patrik karlsson:secret => Login correct


# dpap-brute
### Performs brute force password auditing against an iPhoto Library.
     root@hostname: ~ nmap -p 50000 --script drda-brute <target>

# drda-brute
### Performs password guessing against databases supporting the IBM DB2 protocol such as Informix, DB2 and Derby
     root@hostname: ~ 

# ftp-brute
### Performs brute force password auditing against FTP servers.
     root@hostname: ~ 

# http-brute
### Performs brute force password auditing against http basic, digest and ntlm authentication.
     root@hostname: ~ 

# http-form-brute
### Performs brute force password auditing against http form-based authentication.
     root@hostname: ~ 

# http-iis-short-name-brute
### Attempts to brute force the 8.3 filenames (commonly known as short names) of files and directories in the root folder of vulnerable IIS servers. This script is an implementation of the PoC "iis shortname scanner".
     root@hostname: ~ 

# http-joomla-brute
### Performs brute force password auditing against Joomla web CMS installations.
     root@hostname: ~ 

# http-proxy-brute
### Performs brute force password guessing against HTTP proxy servers.
     root@hostname: ~ 

# http-wordpress-brute
### performs brute force password auditing against Wordpress CMS/blog installations.
     root@hostname: ~ 

# iax2-brute
### Performs brute force password auditing against the Asterisk IAX2 protocol. Guessing fails when a large number of attempts is made due to the maxcallnumber limit (default 2048). In case your getting "ERROR: Too many retries, aborted ..." after a while, this is most likely what's happening. In order to avoid this problem try: - reducing the size of your dictionary - use the brute delay option to introduce a delay between guesses - split the guessing up in chunks and wait for a while between them
     root@hostname: ~ 

# imap-brute
### Performs brute force password auditing against IMAP servers using either LOGIN, PLAIN, CRAM-MD5, DIGEST-MD5 or NTLM authentication.
     root@hostname: ~ 

# impress-remote-discover
### Tests for the presence of the LibreOffice Impress Remote server. Checks if a PIN is valid if provided and will bruteforce the PIN if requested.
     root@hostname: ~ 

# informix-brute
### Performs brute force password auditing against IBM Informix Dynamic Server.
     root@hostname: ~ 

# ipmi-brute
### Performs brute force password auditing against IPMI RPC server.
     root@hostname: ~ 

# irc-brute
### Performs brute force password auditing against IRC (Internet Relay Chat) servers.
     root@hostname: ~ 

# irc-sasl-brute
### Performs brute force password auditing against IRC (Internet Relay Chat) servers supporting SASL authentication.
     root@hostname: ~ 

# iscsi-brute
### Performs brute force password auditing against iSCSI targets.
     root@hostname: ~ 

# ldap-brute
### Attempts to brute-force LDAP authentication. By default it uses the built-in username and password lists. In order to use your own lists use the userdb and passdb script arguments.
     root@hostname: ~ 

# lu-enum
### Attempts to enumerate Logical Units (LU) of TN3270E servers.
     root@hostname: ~ 

# membase-brute 
### Performs brute force password auditing against Couchbase Membase servers.
     root@hostname: ~ 

# metasploit-msgrpc-brute
### Performs brute force username and password auditing against Metasploit msgrpc interface.
     root@hostname: ~ 

# metasploit-xmlrpc-brute
### Performs brute force password auditing against a Metasploit RPC server using the XMLRPC protocol.
     root@hostname: ~ 

# mikrotik-routeros-brute
### Performs brute force password auditing against Mikrotik RouterOS devices with the API RouterOS interface enabled.
     root@hostname: ~ 

# mmouse-brute
### Performs brute force password auditing against the RPA Tech Mobile Mouse servers.
     root@hostname: ~ 

# mongodb-brute
###  Performs brute force password auditing against the MongoDB database.
     root@hostname: ~ 

# ms-sql-brute
### Performs password guessing against Microsoft SQL Server (ms-sql). Works best in conjunction with the broadcast-ms-sql-discover script.
     root@hostname: ~ 

# mysql-brute                         
### Performs password guessing against MySQL.
     root@hostname: ~ 

# mysql-enum                              
### Performs valid-user enumeration against MySQL server using a bug discovered and published by Kingcope (http://seclists.org/fulldisclosure/2012/Dec/9).
     root@hostname: ~ 

# nessus-brute                             
### Performs brute force password auditing against a Nessus vulnerability scanning daemon using the NTP 1.2 protocol.
     root@hostname: ~ 

# nessus-xmlrpc-brute                   
### Performs brute force password auditing against a Nessus vulnerability scanning daemon using the XMLRPC protocol.
     root@hostname: ~ 

# netbus-brute                             
### Performs brute force password auditing against the Netbus backdoor ("remote administration") service.
     root@hostname: ~ 

# nexpose-brute                            
### Performs brute force password auditing against a Nexpose vulnerability scanner using the API 1.1.
     root@hostname: ~ 

# nje-node-brute                           
### z/OS JES Network Job Entry (NJE) target node name brute force.
     root@hostname: ~ 

# nje-pass-brute                           
### z/OS JES Network Job Entry (NJE) 'I record' password brute forcer.
     root@hostname: ~ 

# nping-brute                         
### Performs brute force password auditing against an Nping Echo service.
     root@hostname: ~ 

# omp2-brute                              
### Performs brute force password auditing against the OpenVAS manager using OMPv2.
     root@hostname: ~ 

# openvas-otp-brute                         
### Performs brute force password auditing against a OpenVAS vulnerability scanner daemon using the OTP 1.0 protocol.
     root@hostname: ~ 

# oracle-brute                             
### Performs brute force password auditing against Oracle servers.
     root@hostname: ~ 

# oracle-brute-stealth                  
### Exploits the CVE-2012-3137 vulnerability, a weakness in Oracle's O5LOGIN authentication scheme. The vulnerability exists in Oracle 11g R1/R2 and allows linking the session key to a password hash. When initiating an authentication attempt as a valid user the server will respond with a session key and salt. Once received the script will disconnect the connection thereby not recording the login attempt. The session key and salt can then be used to brute force the users password.
     root@hostname: ~ 

# oracle-sid-brute                     
### Guesses Oracle instance/SID names against the TNS-listener.
     root@hostname: ~ 

# pcanywhere-brute                     
### Performs brute force password auditing against the pcAnywhere remote access protocol.
     root@hostname: ~ 

# pgsql-brute                         
### Performs password guessing against PostgreSQL.
     root@hostname: ~ 

# pop3-brute                              
### Tries to log into a POP3 account by guessing usernames and passwords.
     root@hostname: ~ 

# redis-brute                         
### Performs brute force passwords auditing against a Redis key-value store.
     root@hostname: ~ 

# rexec-brute                         
### Performs brute force password auditing against the classic UNIX rexec (remote exec) service.
     root@hostname: ~ 

# rlogin-brute                            
### Performs brute force password auditing against the classic UNIX rlogin (remote login) service. This script must be run in privileged mode on UNIX because it must bind to a low source port number.
     root@hostname: ~ 

# rpcap-brute                         
### Performs brute force password auditing against the WinPcap Remote Capture Daemon (rpcap).
     root@hostname: ~ 

# rsync-brute                         
### Performs brute force password auditing against the rsync remote file syncing protocol.
     root@hostname: ~ 

# rtsp-url-brute                           
### Attempts to enumerate RTSP media URLS by testing for common paths on devices such as surveillance IP cameras.
     root@hostname: ~ 

# sip-brute                               
### Performs brute force password auditing against Session Initiation Protocol (SIP) accounts. This protocol is most commonly associated with VoIP sessions.
     root@hostname: ~ 

# smb-brute                               
### Attempts to guess username/password combinations over SMB, storing discovered combinations for use in other scripts. Every attempt will be made to get a valid list of users and to verify each username before actually using them. When a username is discovered, besides being printed, it is also saved in the Nmap registry so other Nmap scripts can use it. That means that if you're going to run smb-brute.nse, you should run other smb scripts you want. This checks passwords in a case-insensitive way, determining case after a password is found, for Windows versions before Vista.
     root@hostname: ~ 

# smtp-brute                              
### Performs brute force password auditing against SMTP servers using either LOGIN, PLAIN, CRAM-MD5, DIGEST-MD5 or NTLM authentication.
     root@hostname: ~ 

# snmp-brute                              
### Attempts to find an SNMP community string by brute force guessing.
     root@hostname: ~ 

# socks-brute                         
### Performs brute force password auditing against SOCKS 5 proxy servers.
     root@hostname: ~ 

# ssh-brute                               
### Performs brute-force password guessing against ssh servers.
     root@hostname: ~ 

# svn-brute                               
### Performs brute force password auditing against Subversion source code control servers.
     root@hostname: ~ 

# telnet-brute                             
### Performs brute-force password auditing against telnet servers.
     root@hostname: ~ 

# tso-enum                                
### TSO User ID enumerator for IBM mainframes (z/OS). The TSO logon panel tells you when a user ID is valid or invalid with the message: IKJ56420I Userid <user ID> not authorized to use TSO.
     root@hostname: ~ 

# vmauthd-brute                            
### Performs brute force password auditing against the VMWare Authentication Daemon (vmware-authd).
     root@hostname: ~ 

# vnc-brute                               
### Performs brute force password auditing against VNC servers.
     root@hostname: ~ 

# vtam-enum                               
### Many mainframes use VTAM screens to connect to various applications (CICS, IMS, TSO, and many more).
     root@hostname: ~ 

# xmpp-brute                              
### Performs brute force password auditing against XMPP (Jabber) instant messaging servers.
     root@hostname: ~ 

# ========================================================================================================================================================

# ========================================================================================================================================================
# Port scanning
# ========================================================================================================================================================
nmap -Pn dhound.io                                                                                                                   # Quick scan
nmap -p 1-65535 -Pn -sV -sS -T4 dhound.io                                                                                            # Full TCP port scan using with service version detection
nmap -Pn -p 22,80,443 dhound.io                                                                                                      # Scan particular ports
nmap -p 22 --open -sV 192.168.10.0/24                                                                                                # Find linux devices in local network
nmap --traceroute -p 80 dhound.io                                                                                                    # Trace trafic
nmap --traceroute --script traceroute-geolocation.nse -p 80 dhound.io                                                                # Trace trafic with Geo resolving
nmap --script=asn-query dhound.io                                                                                                    # WHOIS ISP, Country, Company
nmap --script ssl-cert -p 443 -Pn dhound.io                                                                                          # Get SSL Certificate
nmap --script ssl-enum-ciphers -p 443 dhound.io                                                                                      # Test SSL Ciphers
nmap --script ftp-brute --script-args userdb=users.txt,passdb=passwords.txt -p 21 -Pn dhound.io                                      # Ftp Brute force
nmap --script http-brute -script-args http-brute.path=/evifile-bb-demo,userdb=users.txt,passdb=passwords.txt -p 80 -Pn dhound.io     # HTTP Basic Authentication Brute force
nmap -sV --script http-wordpress-brute --script-args userdb=u,passdb=p.txt,http-wordpress-brute.hostname=d.nu,thrreads=10 -p 80 url  # Wordpress Bruteforce
nmap --script default,safe -Pn dhound.io                                                                                             # Find vulnerabilities in safe mode
nmap --script vuln -Pn dhound.io                                                                                                     # Find vulnerabilities in unsafe mode
nmap --script dos -Pn dhound.io                                                                                                      # Run DDos attack
nmap --script exploit -Pn dhound.io                                                                                                  # Exploit detected vulnerabilities

