# nmap

As a pentester, we must understand and know what this extremely powerful tool is capable of, it can do SO Much more then just scanning ports ;-)

### After you installed nmap go get all scripts by below command:

```console
nmap --script-updatedb
```

### AFP - Brute-Force                              

_Performs password guessing against Apple Filing Protocol (AFP)_
     
```console
nmap -p 548 --script afp-brute 192.168.1.12
```

     |PORT    STATE SERVICE
     |548/tcp open  afp
     | afp-brute:
     |_  admin:KenSentMe => Valid credentials

### AJP - Brute-Force                          

_Performs brute force passwords auditing against the Apache JServ protocol. The Apache JServ Protocol is commonly used by web servers to communicate with back-end Java application server containers_

```console
nmap -p 8009 192.168.1.12 --script ajp-brute
```

     |PORT     STATE SERVICE
     |8009/tcp open  ajp13
     | ajp-brute:
     |   Accounts
     |     root:secret - Valid credentials
     |   Statistics
     |_    Performed 1946 guesses in 23 seconds, average tps: 82

### Backorifice - Brute-Force                         
     
```console
nmap -sU --script backorifice-brute 192.168.1.12 --script-args backorifice-brute. 
```

     |PORT       STATE  SERVICE
     |31337/udp  open   BackOrifice
     | backorifice-brute:
     |   Accounts:
     |     michael => Valid credentials
     |   Statistics
     |_    Perfomed 60023 guesses in 467 seconds, average tps: 138


### Cassandra - Brute-Force 

_Performs Brute-Force password auditing against the Cassandra database_
     
```console
nmap -p 9160 192.168.1.12 --script=cassandra-brute
```

     |PORT     STATE SERVICE VERSION
     |9160/tcp open  apani1?
     | cassandra-brute:
     |   Accounts
     |     admin:lover - Valid credentials
     |     admin:lover - Valid credentials
     |   Statistics
     |_    Performed 4581 guesses in 1 seconds, average tps: 4581


### Citrix - Brute-Force-xml

_Attempts to guess valid credentials for the Citrix PN Web Agent XML Service_ The XML service authenticates against the local Windows server or the Active Directory_
     
```console
nmap --script=citrix - Brute-Force-xml --script-args=userdb=<userdb>,passdb=<passdb>,ntdomain=<domain> -p 80,443,8080 192.168.1.12
```

     |PORT     STATE SERVICE    REASON
     |8080/tcp open  http-proxy syn-ack
     | citrix-brute-xml:
     |   Joe:password => Must change password at next logon
     |   Luke:summer => Login was successful
     |_  Jane:secret => Account is disabled


### Cisco - Cvs - Test whether host is vulnerable or not

    nmap -p 4786 -v 192.168.0.1 # By default, it will just test whether host is vulnerable or not
    nmap -p 4786 -v 192.168.0.1 --script ./cisco-siet.nse

### You can pass argument to get config

If you are attacking public ip, make sure to provide your public ip to the script (cisco-siet.addr=<PUBLIC_IP>)

    nmap -p 4786 -v 192.168.0.1 --script ./cisco-siet.nse --script-args "cisco-siet.get"

### Cvs - Brute-Force

_Performs Brute-Force password auditing against CVS pserver authentication_
     
```console
nmap -p 2401 --script cvs-brute 192.168.1.12
```

     |2401/tcp open  cvspserver syn-ack
     | cvs-brute:
     |   Accounts
     |     hotchner:francisco - Account is valid
     |     reid:secret - Account is valid
     |   Statistics
     |_    Performed 544 guesses in 14 seconds, average tps: 38



### Cvs Repository - Brute-Force 

_Attempts to guess the name of the CVS repositories hosted on the remote server_ With knowledge of the correct repository name, usernames and passwords can be guessed_
     
```console
nmap -p 2401 --script cvs-brute-repository 192.168.1.12
```

     |PORT     STATE SERVICE    REASON
     |2401/tcp open  cvspserver syn-ack
     | cvs-brute-repository:
     |   Repositories
     |     /myrepos
     |     /demo
     |   Statistics
     |_    Performed 14 guesses in 1 seconds, average tps: 14



### Deluge-RPC - Brute-Force

_Performs Brute-Force password auditing against the DelugeRPC daemon_
     
```console
nmap --script deluge-rpc-brute -p 58846 192.168.1.12
```

     |PORT      STATE SERVICE REASON  TTL
     |58846/tcp open  unknown syn-ack 0
     | deluge-rpc-brute:
     |   Accounts
     |     admin:default - Valid credentials
     |   Statistics
     |_    Performed 8 guesses in 1 seconds, average tps: 8



### Domcon - Brute-Force

_Performs Brute-Force password auditing against the Lotus Domino Console_
     
```console
nmap --script domcon-brute -p 2050 192.168.1.12
```

     |PORT     STATE SERVICE REASON
     |2050/tcp open  unknown syn-ack
     | domcon-brute:
     |   Accounts
     |_    patrik karlsson:secret => Login correct



### DPAP - Brute-Force

_Performs Brute-Force password auditing against an iPhoto Library_
     
```console
nmap --script dpap-brute -p 8770 192.168.1.12
```

     |PORT     STATE SERVICE REASON
     |8770/tcp open  apple-iphoto syn-ack
     | dpap-brute:
     |   Accounts
     |     secret => Login correct
     |   Statistics
     |_    Perfomed 5007 guesses in 6 seconds, average tps: 834


### DRDA - Brute-Force

_Performs password guessing against databases sup     |PORTing the IBM DB2 protocol such as Informix, DB2 and Derby_
     
```console
nmap -p 50000 --script drda-brute 192.168.1.12
```

     |PORT     STATE SERVICE REASON
     |50000/tcp open  drda
     | drda-brute:
     |_  db2admin:db2admin => Valid credentials




### FTP - Brute-Force

_Performs Brute-Force password auditing against FTP servers_
     
```console
nmap --script ftp-brute -p 21 192.168.1.12
```

     |PORT   STATE SERVICE
     |21/tcp open  ftp
     | ftp-brute:
     |   Accounts
     |     root:root - Valid credentials
     |   Statistics
     |_    Performed 510 guesses in 610 seconds, average tps: 0


### HTTP - Brute-Force

_Performs Brute-Force password auditing against http basic, digest and ntlm authentication_
     
```console
nmap --script http-brute -p 80 192.168.1.12
```

     |PORT     STATE SERVICE REASON
     |80/tcp   open  http    syn-ack
     | http-brute:
     |   Accounts:
     |     user:user - Valid credentials
     |_  Statistics: Performed 123 guesses in 1 seconds, average tps: 123



### HTTP-Form - Brute-Force

_Performs Brute-Force password auditing against http form-based authentication_
     
```console
nmap --script http-form-brute -p 80 192.168.1.12
```

     |PORT     STATE SERVICE REASON
     |80/tcp   open  http    syn-ack
     | http-form-brute:
     |   Accounts
     |     Patrik Karlsson:secret - Valid credentials
     |   Statistics
     |_    Perfomed 60023 guesses in 467 seconds, average tps: 138


### HTTP-IIS-Short-Name - Brute-Force

_Attempts to Brute-Force the 8_3 filenames (commonly known as short names) of files and directories in the root folder of vulnerable IIS servers_ This script is an implementation of the PoC "iis shortname scanner"_
     
```console
nmap -p80 --script http-iis-short-name-brute 192.168.1.12
```

     |PORT   STATE SERVICE
     |80/tcp open  http
     | http-iis-short-name-brute:
     |   VULNERABLE:
     |   Microsoft IIS tilde character "~" short name disclosure and denial of service
     |     State: VULNERABLE (Exploitable)
     |     Description:
     |      Vulnerable IIS servers disclose folder and file names with a Windows 8.3 naming scheme inside the webroot folder.
     |      Shortnames can be used to guess or brute force sensitive filenames. Attackers can exploit this vulnerability to
     |      cause a denial of service condition.
     |
     |     Extra information:
     |
     |   8.3 filenames found:
     |     Folders
     |       admini~1
     |     Files
     |       backup~1.zip
     |       certsb~2.zip
     |       siteba~1.zip
     |
     |     References:
     |       http://soroush.secproject.com/downloadable/microsoft_iis_tilde_character_vulnerability_feature.pdf
     |_      https://github.com/irsdl/IIS-ShortName-Scanner


### HTTP-Joomla - Brute-Force

_Performs Brute-Force password auditing against Joomla web CMS installations_
     
```console
nmap -sV --script http-joomla-brute --script-args 'userdb=users.txt,passdb=passwds.txt,http-joomla-brute.hostname=domain.com,http-joomla-brute.threads=3,brute.firstonly=true' 192.168.1.12
```


     |PORT     STATE SERVICE REASON
     |80/tcp open  http    syn-ack
     | http-joomla-brute:
     |   Accounts
     |     xdeadbee:i79eWBj07g => Login correct
     |   Statistics
     |_    Perfomed 499 guesses in 301 seconds, average tps: 0



### HTTP-Proxy - Brute-Force

_Performs Brute-Force password guessing against HTTP proxy servers_
     
```console
nmap --script http-proxy-brute -p 8080 192.168.1.12
```

     |PORT     STATE SERVICE
     |8080/tcp open  http-proxy
     | http-proxy-brute:
     |   Accounts
     |     patrik:12345 - Valid credentials
     |   Statistics
     |_    Performed 6 guesses in 2 seconds, average tps: 3


### HTTP-WordPress - Brute-Force

_Performs Brute-Force password auditing against Wordpress CMS/blog installations_
     
```console
nmap -sV --script http-wordpress-brute --script-args 'userdb=users.txt,passdb=passwds.txt,http-wordpress-brute.hostname=domain.com,http-wordpress-brute.threads=3,brute.firstonly=true' 192.168.1.12
```

     |PORT     STATE SERVICE REASON
     |80/tcp   open  http    syn-ack
     | http-wordpress-brute:
     |   Accounts
     |     0xdeadb33f:god => Login correct
     |   Statistics
     |_    Perfomed 103 guesses in 17 seconds, average tps: 6




### IAX2 - Brute-Force

_Performs Brute-Force password auditing against the Asterisk IAX2 protocol_ Guessing fails when a large number of attempts is made due to the maxcallnumber limit (default 2048)_ In case your getting "ERROR: Too many retries, aborted ___" after a while, this is most likely what's happening_ In order to avoid this problem try: - reducing the size of your dictionary - use the brute delay option to introduce a delay between guesses - split the guessing up in chunks and wait for a while between them_   

```console
nmap -sU -p 4569 192.168.1.12 --script iax2-brute
```

     | PORT     STATE         SERVICE   
     |4569/udp open     |filtered unknown
     |  iax2-brute:
     |    Accounts
     |      1002:password12 - Valid credentials
     |    Statistics
     _    Performed 1850 guesses in 2 seconds, average tps: 925




### IMAP - Brute-Force

_Performs Brute-Force password auditing against IMAP servers using either LOGIN, PLAIN, CRAM-MD5, DIGEST-MD5 or NTLM authentication_
     
```console
nmap -p 143,993 --script imap-brute 192.168.1.12
```

     |PORT    STATE SERVICE REASON
     |143/tcp open  imap    syn-ack
     | imap-brute:
     |   Accounts
     |     braddock:jules - Valid credentials
     |     lane:sniper - Valid credentials
     |     parker:scorpio - Valid credentials
     |   Statistics
     |_    Performed 62 guesses in 10 seconds, average tps: 6



### Impress-Remote-Discover

_Tests for the presence of the LibreOffice Impress Remote server_ Checks if a PIN is valid if provided and will bruteforce the PIN if requested_
     
```console
nmap -p 1599 --script impress-remote-discover 192.168.1.12
```

     |PORT     STATE SERVICE        Version
     |1599/tcp open  impress-remote LibreOffice Impress remote 4.3.3.2
     | impress-remote-discover:
     |   Impress Version: 4.3.3.2
     |   Remote PIN: 0000
     |_  Client Name used: Firefox OS


### Informix - Brute-Force

_Performs Brute-Force password auditing against IBM Informix Dynamic Server_
     
```console
nmap --script informix-brute -p 9088 192.168.1.12
```

     |PORT     STATE SERVICE
     |9088/tcp open  unknown
     | informix-brute:
     |   Accounts
     |     ifxnoob:ifxnoob => Valid credentials
     |   Statistics
     |_    Perfomed 25024 guesses in 75 seconds, average tps: 320


### IPMI - Brute-Force

_Performs Brute-Force password auditing against IPMI RPC server_
     
```console
nmap -sU --script ipmi-brute -p 623 192.168.1.12
```

     |PORT     STATE  SERVICE REASON
     |623/udp  open     |filtered  unknown
     | ipmi-brute:
     |   Accounts
     |_    admin:admin => Valid credentials



### IRC - Brute-Force

_Performs Brute-Force password auditing against IRC (Internet Relay Chat) servers_
     
```console
nmap --script irc-brute -p 6667 192.168.1.12
```

     |PORT     STATE SERVICE
     |6667/tcp open  irc
     | irc-brute:
     |   Accounts
     |     password - Valid credentials
     |   Statistics
     |_    Performed 1927 guesses in 36 seconds, average tps: 74




### IRC-sasl - Brute-Force

_Performs Brute-Force password auditing against IRC (Internet Relay Chat) servers sup     |PORTing SASL authentication_
     
```console
nmap --script irc-sasl-brute -p 6667 192.168.1.12
```

     |PORT     STATE SERVICE REASON
     |6667/tcp open  irc     syn-ack
     | irc-sasl-brute:
     |   Accounts
     |     root:toor - Valid credentials
     |   Statistics
     |_    Performed 60 guesses in 29 seconds, average tps: 2


### ISCSI - Brute-Force

_Performs Brute-Force password auditing against iSCSI targets_
     
```console
nmap -sV --script=iscsi-brute 192.168.1.12
```

     |PORT     STATE SERVICE
     |3260/tcp open  iscsi   syn-ack
     | iscsi-brute:
     |   Accounts
     |     user:password123456 => Valid credentials
     |   Statistics
     |_    Perfomed 5000 guesses in 7 seconds, average tps: 714




### LDAP - Brute-Force

_Attempts to brute-force LDAP authentication_ By default it uses the built-in username and password lists_ In order to use your own lists use the userdb and passdb script arguments_
     
```console
nmap -p 389 --script ldap-brute --script-args ldap.base='"cn=users,dc=cqure,dc=net"' 192.168.1.12
```

     |389/tcp open  ldap
     | ldap-brute:
     |_  ldaptest:ldaptest => Valid credentials
     |   restrict.ws:restricted1 => Valid credentials, account cannot log in from current host
     |   restrict.time:restricted1 => Valid credentials, account cannot log in at current time
     |   valid.user:valid1 => Valid credentials
     |   expired.user:expired1 => Valid credentials, account expired
     |   disabled.user:disabled1 => Valid credentials, account disabled
     |_  must.change:need2change => Valid credentials, password must be changed at next logon




### LU-Enum

_Attempts to enumerate Logical Units (LU) of TN3270E servers_
     
```console
nmap --script lu-enum --script-args lulist=lus.txt,lu-enum.path="/home/dade/screenshots/" -p 23 -sV <targets>
```

     |PORT     STATE SERVICE REASON  VERSION
     |23/tcp   open  tn3270  syn-ack IBM Telnet TN3270 (TN3270E)
     | lu-enum: 
     |   Logical Units: 
     |     LU:BSLVLU69 - Valid credentials
     |_  Statistics: Performed 7 guesses in 7 seconds, average tps: 1.0




### Membase - Brute-Force 

_Performs Brute-Force password auditing against Couchbase Membase servers_
     
```console
nmap -p 11211 --script membase-brute
```

     |PORT      STATE SERVICE
     |11211/tcp open  unknown
     | membase-brute:
     |   Accounts
     |     buckettest:toledo - Valid credentials
     |   Statistics
     |_    Performed 5000 guesses in 2 seconds, average tps: 2500


### Mikrotik-RouterOS - Brute-Force

_Performs Brute-Force password auditing against Mikrotik RouterOS devices with the API RouterOS interface enabled_
     
```console
nmap -p8728 --script mikrotik-routeros-brute 192.168.1.12
```

     |PORT     STATE SERVICE REASON
     |8728/tcp open  unknown syn-ack
     | mikrotik-routeros-brute:
     |   Accounts
     |     admin:dOsmyvsvJGA967eanX - Valid credentials
     |   Statistics
     |_    Performed 60 guesses in 602 seconds, average tps: 0




### MMouse - Brute-Force

_Performs Brute-Force password auditing against the RPA Tech Mobile Mouse servers_
     
```console
nmap --script mmouse-brute -p 51010 192.168.1.12
```

     |PORT      STATE SERVICE
     |51010/tcp open  unknown
     | mmouse-brute:
     |   Accounts
     |     vanilla - Valid credentials
     |   Statistics
     |_    Performed 1199 guesses in 23 seconds, average tps: 47




### MongoDB - Brute-Force

_ Performs Brute-Force password auditing against the MongoDB database_
     
```console
nmap -p 27017 192.168.1.12 --script mongodb-brute
```

     |PORT      STATE SERVICE
     |27017/tcp open  mongodb
     | mongodb-brute:
     |   Accounts
     |     root:Password1 - Valid credentials
     |   Statistics
     |_    Performed 3542 guesses in 9 seconds, average tps: 393

### MS-SQL - Brute-Force

_Performs password guessing against Microsoft SQL Server (ms-sql)_ Works best in conjunction with the broadcast-ms-sql-discover script_
     
```console
nmap -p 445 --script ms-sql-brute --script-args mssql.instance-all,userdb=customuser.txt,passdb=custompass.txt 192.168.1.12
```
```console
nmap -p 1433 --script ms-sql-brute --script-args userdb=customuser.txt,passdb=custompass.txt 192.168.1.12
```

     |PORT     STATE SERVICE REASON
     | ms-sql-brute:
     |   [192.168.100.128\TEST]
     |     No credentials found
     |     Warnings:
     |       sa: AccountLockedOut
     |   [192.168.100.128\PROD]
     |     Credentials found:
     |       webshop_reader:secret => Login Success
     |       testuser:secret1234 => PasswordMustChange
     |_      lordvader:secret1234 => Login Success



### MySQL - Brute-Force       

_Performs password guessing against MySQL_
     
```console
nmap --script=mysql-brute 192.168.1.12
```

     |PORT     STATE SERVICE REASON
     |3306/tcp open  mysql
     | mysql-brute:
     |   Accounts
     |     root:root - Valid credentials



### MySQL-enum                 

_Performs valid-user enumeration against MySQL server using a bug discovered and published by Kingcope (http://seclists_org/fulldisclosure/2012/Dec/9)_
     
```console
nmap --script=mysql-enum 192.168.1.12
```

     |PORT     STATE SERVICE REASON
     |3306/tcp open  mysql   syn-ack
     | mysql-enum:
     |   Accounts
     |     admin:<empty> - Valid credentials
     |     test:<empty> - Valid credentials
     |     test_mysql:<empty> - Valid credentials
     |   Statistics
     |_    Performed 11 guesses in 1 seconds, average tps: 11



### Nessus-XMLRPC - Brute-Force                   

_Performs Brute-Force password auditing against a Nessus vulnerability scanning daemon using the XMLRPC protocol_
     
```console
nmap -sV --script=nessus-xmlrpc-brute 192.168.1.12
```

     |PORT     STATE SERVICE REASON
     |8834/tcp open  unknown syn-ack
     | nessus-xmlrpc-brute:
     |   Accounts
     |     nessus:nessus - Valid credentials
     |   Statistics
     |_    Performed 1933 guesses in 26 seconds, average tps: 73



### Netbus - Brute-Force     

_Performs Brute-Force password auditing against the Netbus backdoor ("remote administration") service_
     
```console
nmap -p 12345 --script netbus-brute 192.168.1.12
```

     |12345/tcp open  netbus
     |_netbus-brute: password123

### Nexpose - Brute-Force                            

_Performs Brute-Force password auditing against a Nexpose vulnerability scanner using the API 1_1_
     
```console
nmap --script nexpose-brute -p 3780 192.168.1.12
```

     |PORT     STATE SERVICE     REASON  VERSION
     |3780/tcp open  ssl/nexpose syn-ack NeXpose NSC 0.6.4
     | nexpose-brute:
     |   Accounts
     |     nxadmin:nxadmin - Valid credentials
     |   Statistics
     |_    Performed 5 guesses in 1 seconds, average tps: 5


### NJE-Node - Brute-Force

_z/OS JES Network Job Entry (NJE) target node name Brute-Force_
     
```console
nmap -sV --script=nje-node-brute 192.168.1.12
```
```console
nmap --script=nje-node-brute --script-args=hostlist=nje_names.txt -p 175 192.168.1.12
```

     |PORT    STATE SERVICE REASON
     |175/tcp open  nje     syn-ack
     | nje-node-brute:
     |   Node Name:
     |     POTATO:CACTUS - Valid credentials
     |_  Statistics: Performed 6 guesses in 14 seconds, average tps: 0

### NJE-Pass - Brute-Force                           

_z/OS JES Network Job Entry (NJE) 'I record' password Brute-Forcer_
     
```console
nmap -sV --script=nje-pass-brute --script-args=ohost='POTATO',rhost='CACTUS' 192.168.1.12
```
```console
nmap --script=nje-pass-brute --script-args=ohost='POTATO',rhost='CACTUS',sleep=5 -p 175 192.168.1.12
```

     |PORT    STATE SERVICE VERSION
     |175/tcp open  nje     IBM Network Job Entry (JES)
     | nje-pass-brute:
     |   NJE Password:
     |     Password:A - Valid credentials
     |_  Statistics: Performed 8 guesses in 12 seconds, average tps: 0

### Nping - Brute-Force                         

_Performs Brute-Force password auditing against an Nping Echo service_
     
```console
nmap -p 9929 --script nping-brute 192.168.1.12
```

     |9929/tcp open  nping-echo
     | nping-brute:
     |   Accounts
     |     123abc => Valid credentials
     |   Statistics
     |_    Perfomed 204 guesses in 204 seconds, average tps: 1

### OMPv2 - Brute-Force                              

_Performs Brute-Force password auditing against the OpenVAS manager using OMPv2_
     
```console
nmap -p 9390 --script omp2-brute 192.168.1.12
```

     |PORT     STATE SERVICE REASON
     |9390/tcp open  openvas syn-ack
     | omp2-brute:
     |   Accounts
     |_    admin:secret => Valid credentials



### OpenVAS-OTP - Brute-Force

_Performs Brute-Force password auditing against a OpenVAS vulnerability scanner daemon using the OTP 1_0 protocol_
     
```console
nmap -sV --script=openvas-otp-brute 192.168.1.12
```

     |PORT     STATE SERVICE    REASON  VERSION
     |9391/tcp open  ssl/openvas syn-ack
     | openvas-otp-brute:
     |   Accounts
     |     openvas:openvas - Valid credentials
     |   Statistics
     '-.>   Performed 4 guesses in 4 seconds, average tps: 1

### Oracle - Brute-Force                

_Performs Brute-Force password auditing against Oracle servers_
     
```console
nmap --script oracle-brute -p 1521 --script-args oracle-brute.sid=ORCL 192.168.1.12
```

     |PORT     STATE  SERVICE REASON
     |1521/tcp open  oracle  syn-ack
     | oracle-brute:
     |   Accounts
     |     system:powell => Account locked
     |     haxxor:haxxor => Valid credentials
     |   Statistics
     |_    Perfomed 157 guesses in 8 seconds, average tps: 19



### Oracle - Brute-Force-stealth    

_Exploits the CVE-2012-3137 vulnerability, a weakness in Oracle's O5LOGIN authentication scheme_ The vulnerability exists in Oracle 11g R1/R2 and allows linking the session key to a password hash_ When initiating an authentication attempt as a valid user the server will respond with a session key and salt_ Once received the script will disconnect the connection thereby not recording the login attempt_ The session key and salt can then be used to Brute-Force the users password_
     
```console
nmap --script oracle-brute-stealth -p 1521 --script-args oracle-brute-stealth.sid=ORCL 192.168.1.12
```

     |PORT     STATE  SERVICE REASON
     |1521/tcp open  oracle  syn-ack
     | oracle-brute-stealth:
     |   Accounts
     |     dummy:$o5logon$1245C95384E15E7F0C893FCD1893D8E19078170867E892CE86DF90880E09FAD3B4832CBCFDAC1A821D2EA8E3D2209DB6*4202433F49DE9AE72AE2 - Hashed valid or invalid credentials
     |     nmap:$o5logon$D1B28967547DBA3917D7B129E339F96156C8E2FE5593D42540992118B3475214CA0F6580FD04C2625022054229CAAA8D*7BCF2ACF08F15F75B579 - Hashed valid or invalid credentials
     |   Statistics
     |_    Performed 2 guesses in 1 seconds, average tps: 2


### oracle-sid - Brute-Force                     

_Guesses Oracle instance/SID names against the TNS-listener_
     
```console
nmap --script=oracle-sid-brute --script-args=oraclesids=/path/to/sidfile -p 1521-1560 192.168.1.12
```
```console
nmap --script=oracle-sid-brute -p 1521-1560 192.168.1.12
```

     |PORT     STATE SERVICE REASON
     |1521/tcp open  oracle  syn-ack
     | oracle-sid-brute:
     |   orcl
     |   prod
     |_  devel

### pcAnywhere - Brute-Force                     

_Performs Brute-Force password auditing against the pcAnywhere remote access protocol_
     
```console
nmap --script=pcanywhere-brute 192.168.1.12
```

     |5631/tcp open  pcanywheredata syn-ack
     | pcanywhere-brute:
     |   Accounts
     |     administrator:administrator - Valid credentials
     |   Statistics
     |_    Performed 2 guesses in 55 seconds, average tps: 0




### PostgreSQL - Brute-Force               

_Performs password guessing against PostgreSQL_
     
```console
nmap -p 5432 --script pgsql-brute 192.168.1.12
```

     |5432/tcp open  pgsql
     | pgsql-brute:
     |   root:<empty> => Valid credentials
     |_  test:test => Valid credentials




### POP3 - Brute-Force   

_Tries to log into a POP3 account by guessing usernames and passwords_
     
```console
nmap -sV --script=pop3-brute 192.168.1.12
```

     |PORT    STATE SERVICE
     |110/tcp open  pop3
     | pop3-brute-     |PORTed:
     | Accounts:
     |  user:pass => Login correct
     | Statistics:
     |_ Performed 8 scans in 1 seconds, average tps: 8

### Redis - Brute-Force                         
_Performs Brute-Force passwords auditing against a Redis key-value store_
     
```console
nmap -p 6379 192.168.1.12 --script redis-brute
```

     |PORT     STATE SERVICE
     |6379/tcp open  unknown
     | redis-brute:
     |   Accounts
     |     toledo - Valid credentials
     |   Statistics
     |_    Performed 5000 guesses in 3 seconds, average tps: 1666

### RExec - Brute-Force                         

_Performs Brute-Force password auditing against the classic UNIX rexec (remote exec) service_
     
```console
nmap -p 512 --script rexec-brute 192.168.1.12
```

     |PORT    STATE SERVICE
     |512/tcp open  exec
     | rexec-brute:
     |   Accounts
     |     nmap:test - Valid credentials
     |   Statistics
     |_    Performed 16 guesses in 7 seconds, average tps: 2


### UNIX-RLogin - Brute-Force     

_Performs Brute-Force password auditing against the classic UNIX rlogin (remote login) service_ This script must be run in privileged mode on UNIX because it must bind to a low source      |PORT number_
     
```console
nmap -p 513 --script rlogin-brute 192.168.1.12
```

     |PORT    STATE SERVICE
     |513/tcp open  login
     | rlogin-brute:
     |   Accounts
     |     nmap:test - Valid credentials
     |   Statistics
     |_    Performed 4 guesses in 5 seconds, average tps: 0


### RPcap - Brute-Force        

_Performs Brute-Force password auditing against the WinPcap Remote Capture Daemon (rpcap)_
     
```console
nmap -p 2002 192.168.1.12 --script rpcap-brute
```

     |PORT     STATE SERVICE REASON
     |2002/tcp open  globe   syn-ack
     | rpcap-brute:
     |   Accounts
     |     monkey:Password1 - Valid credentials
     |   Statistics
     |_    Performed 3540 guesses in 3 seconds, average tps: 1180


### Rsync - Brute-Force                         

_Performs Brute-Force password auditing against the rsync remote file syncing protocol_
     
```console
nmap -p 873 --script rsync-brute --script-args 'rsync-brute.module=www' 192.168.1.12
```

     |PORT    STATE SERVICE REASON
     |873/tcp open  rsync   syn-ack
     | rsync-brute:
     |   Accounts
     |     user1:laptop - Valid credentials
     |     user2:password - Valid credentials
     |   Statistics
     |_    Performed 1954 guesses in 20 seconds, average tps: 97





### RTSP-Url - Brute-Force     

_Attempts to enumerate RTSP media URLS by testing for common paths on devices such as surveillance IP cameras_
     
```console
nmap --script rtsp-url-brute -p 554 192.168.1.12
```

     |PORT    STATE SERVICE
     |554/tcp open  rtsp
     | rtsp-url-brute:
     |   discovered:
     |     rtsp://camera.example.com/mpeg4
     |   other responses:
     |     401:
     |_      rtsp://camera.example.com/live/mpeg4






### SMB - Brute-Force                               
_Attempts to guess username/password combinations over SMB, storing discovered combinations for use in other scripts_ Every attempt will be made to get a valid list of users and to verify each username before actually using them_ When a username is discovered, besides being printed, it is also saved in the Nmap registry so other Nmap scripts can use it_ That means that if you're going to run smb - Brute-Force_nse, you should run other smb scripts you want_ This checks passwords in a case-insensitive way, determining case after a password is found, for Windows versions before Vista_
     
```console
nmap -sU -sS --script smb-brute.nse -p U:137,T:139 192.168.1.12
```

     | smb-brute:
     |   bad name:test => Valid credentials
     |   consoletest:test => Valid credentials, password must be changed at next logon
     |   guest:<anything> => Valid credentials, account disabled
     |   mixcase:BuTTeRfLY1 => Valid credentials
     |   test:password1 => Valid credentials, account expired
     |   this:password => Valid credentials, account cannot log in at current time
     |   thisisaverylong:password => Valid credentials
     |   thisisaverylongname:password => Valid credentials
     |   thisisaverylongnamev:password => Valid credentials
     |_  web:TeSt => Valid credentials, account disabled


### SMTP - Brute-Force        

_Performs Brute-Force password auditing against SMTP servers using either LOGIN, PLAIN, CRAM-MD5, DIGEST-MD5 or NTLM authentication_
     
```console
nmap -p 25 --script smtp-brute 192.168.1.12
```

     |PORT    STATE SERVICE REASON
     |25/tcp  open  stmp    syn-ack
     | smtp-brute:
     |   Accounts
     |     braddock:jules - Valid credentials
     |     lane:sniper - Valid credentials
     |     parker:scorpio - Valid credentials
     |   Statistics
     |_    Performed 1160 guesses in 41 seconds, average tps: 33




### SNMP - Brute-Force                 

_Attempts to find an SNMP community string by Brute-Force guessing_
     
```console
nmap --script socks-brute -p 1080 192.168.1.12
```

     |PORT     STATE SERVICE
     |1080/tcp open  socks
     | socks-brute:
     |   Accounts
     |     patrik:12345 - Valid credentials
     |   Statistics
     |_    Performed 1921 guesses in 6 seconds, average tps: 320



### SSH - Brute-Force                               

_Performs brute-force password guessing against ssh servers_
     
```console
nmap -p 22 --script ssh-brute --script-args userdb=users.lst,passdb=pass.lst --script-args ssh-brute.timeout=4s 192.168.1.12
```

     |22/ssh open  ssh
     | ssh-brute:
     |  Accounts
     |    username:password
     |  Statistics
     |_   Performed 32 guesses in 25 seconds.

### SVN - Brute-Force                               

_Performs Brute-Force password auditing against Subversion source code control servers_
     
```console
nmap --script svn-brute --script-args svn-brute.repo=/svn/ -p 3690 192.168.1.12
```

     |PORT     STATE SERVICE REASON
     |3690/tcp open  svn     syn-ack
     | svn-brute:
     |   Accounts
     |_    patrik:secret => Login correct

### Telnet - Brute-Force                             

_Performs brute-force password auditing against telnet servers_
     
```console
nmap -p 23 --script telnet-brute --script-args userdb=myusers.lst,passdb=mypwds.lst,telnet-brute.timeout=8s 192.168.1.12
```

     |23/tcp open  telnet
     | telnet-brute:
     |   Accounts
     |     wkurtz:colonel
     |   Statistics
     |_    Performed 15 guesses in 19 seconds, average tps: 0




### TSO-Enu

_TSO User ID enumerator for IBM mainframes (z/OS)_ The TSO logon panel tells you when a user ID is valid or invalid with the message: IKJ56420I Userid <user ID> not authorized to use TSO_
     
```console
nmap -sV -p 9923 10.32.70.10 --script tso-enum --script-args userdb=tso_users.txt,tso-enum.commands="logon applid(tso)"
```

     |PORT   STATE SERVICE VERSION
     |23/tcp open  tn3270  IBM Telnet TN3270
     | tso-enum:
     |   TSO User ID:
     |     TSO User:RAZOR -  Valid User ID
     |     TSO User:BLADE -  Valid User ID
     |     TSO User:PLAGUE -  Valid User ID
     |_  Statistics: Performed 6 guesses in 3 seconds, average tps: 2


### VMWare Authentication Daemon - BruteForce     

_Performs Brute-Force password auditing against the VMWare Authentication Daemon (vmware-authd)_
     
```console
nmap -p 902 192.168.1.12 --script vmauthd-brute
```

     |PORT    STATE SERVICE
     |902/tcp open  iss-realsecure
     | vmauthd-brute:
     |   Accounts
     |     root:00000 - Valid credentials
     |   Statistics
     |_    Performed 183 guesses in 40 seconds, average tps: 4


### VNC - Brute-Force           

_Performs Brute-Force password auditing against VNC servers_
     
```console
nmap --script vnc-brute -p 5900 192.168.1.12
```

     |PORT     STATE  SERVICE REASON
     |5900/tcp open   vnc     syn-ack
     | vnc-brute:
     |   Accounts
     |_    123456 => Valid credentials



### VTAM-Enum                   

_Many mainframes use VTAM screens to connect to various applications (CICS, IMS, TSO, and many more)_
     
```console
nmap --script vtam-enum --script-args idlist=defaults.txt,vtam-enum.command="exit;logon applid(logos)",vtam-enum.macros=truevtam-enum.path="/home/dade/screenshots/" -p 23 -sV <targets>
```

     |PORT   STATE SERVICE VERSION
     |23/tcp open  tn3270  IBM Telnet TN3270
     | vtam-enum:
     |   VTAM Application ID:
     |     applid:TSO - Valid credentials
     |     applid:CICSTS51 - Valid credentials
     |_  Statistics: Performed 14 guesses in 5 seconds, average tps: 2




### XMPP - Brute-Force                              

_Performs Brute-Force password auditing against XMPP (Jabber) instant messaging servers_
     
```console
nmap -p 5222 --script xmpp-brute 192.168.1.12
```

     |PORT     STATE SERVICE
     |5222/tcp open  xmpp-client
     | xmpp-brute:
     |   Accounts
     |     CampbellJ:arthur321 - Valid credentials
     |     CampbellA:joan123 - Valid credentials
     |     WalkerA:auggie123 - Valid credentials
     |   Statistics
     |_    Performed 6237 guesses in 5 seconds, average tps: 1247

#### REQUIREMENTS

A device of any kind ;]

#### CONTACT 

If you have problems, questions, ideas or suggestions please contact me by posting to wuseman@nr1.nu

#### WEB SITE

Visit my websites and profiles for the latest info and updated tools

https://github.com/wuseman/ && https://nr1.nu && https://stackoverflow.com/users/9887151/wuseman

#### END!







