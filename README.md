# NMAP BRUTEFORCING

As a pentester, we must understand and know what this extremely powerful tool is capable of, it can do SO Much more then just scanning ports ;-)


### OPTIONS SUMMARY

     root@hostname: ~/ # Usage: nmap [Scan Type(s)] [Options] {target specification}

### TARGET SPECIFICATION:
     root@hostname: ~/ nmap -iL <inputfilename>: Input from list of hosts/networks
     root@hostname: ~/ nmap -iR <num hosts>: Choose random targets
     root@hostname: ~/ nmap --exclude <host1[,host2][,host3],...>: Exclude hosts/networks
     root@hostname: ~/ nmap --excludefile <exclude_file>: Exclude list from file

### HOST DISCOVERY:
     root@hostname: ~/ nmap -sL: List Scan - simply list targets to scan
     root@hostname: ~/ nmap -sn: Ping Scan - disable port scan
     root@hostname: ~/ nmap -Pn: Treat all hosts as online -- skip host discovery
     root@hostname: ~/ nmap -PS/PA/PU/PY[portlist]: TCP SYN/ACK, UDP or SCTP discovery to given ports
     root@hostname: ~/ nmap -PE/PP/PM: ICMP echo, timestamp, and netmask request discovery probes
     root@hostname: ~/ nmap -PO[protocol list]: IP Protocol Ping
     root@hostname: ~/ nmap -n/-R: Never do DNS resolution/Always resolve [default: sometimes]
     root@hostname: ~/ nmap --dns-servers <serv1[,serv2],...>: Specify custom DNS servers
     root@hostname: ~/ nmap --system-dns: Use OS's DNS resolver
     root@hostname: ~/ nmap --traceroute: Trace hop path to each host

#### SCAN TECHNIQUES:
     root@hostname: ~/ nmap -sS/sT/sA/sW/sM: TCP SYN/Connect()/ACK/Window/Maimon scans
     root@hostname: ~/ nmap -sU: UDP Scan
     root@hostname: ~/ nmap -sN/sF/sX: TCP Null, FIN, and Xmas scans
     root@hostname: ~/ nmap --scanflags <flags>: Customize TCP scan flags
     root@hostname: ~/ nmap -sI <zombie host[:probeport]>: Idle scan
     root@hostname: ~/ nmap -sY/sZ: SCTP INIT/COOKIE-ECHO scans
     root@hostname: ~/ nmap -sO: IP protocol scan
     root@hostname: ~/ nmap -b <FTP relay host>: FTP bounce scan

### SCAN TECHNIQUES:
     root@hostname: ~/ nmap -sS/sT/sA/sW/sM: TCP SYN/Connect()/ACK/Window/Maimon scans
     root@hostname: ~/ nmap -sU: UDP Scan
     root@hostname: ~/ nmap -sN/sF/sX: TCP Null, FIN, and Xmas scans
     root@hostname: ~/ nmap --scanflags <flags>: Customize TCP scan flags
     root@hostname: ~/ nmap -sI <zombie host[:probeport]>: Idle scan
     root@hostname: ~/ nmap -sY/sZ: SCTP INIT/COOKIE-ECHO scans
     root@hostname: ~/ nmap -sO: IP protocol scan
     root@hostname: ~/ nmap -b <FTP relay host>: FTP bounce scan

### PORT SPECIFICATION AND SCAN ORDER:
     root@hostname: ~/ nmap -p <port ranges>: Only scan specified ports
     root@hostname: ~/ nmap --exclude-ports <port ranges>: Exclude the specified ports from scanning
     root@hostname: ~/ nmap -F: Fast mode - Scan fewer ports than the default scan
     root@hostname: ~/ nmap -r: Scan ports consecutively - don't randomize
     root@hostname: ~/ nmap --top-ports <number>: Scan <number> most common ports
     root@hostname: ~/ nmap --port-ratio <ratio>: Scan ports more common than <ratio>

#### SERVICE/VERSION DETECTION:
     root@hostname: ~/ nmap -sV: Probe open ports to determine service/version info
     root@hostname: ~/ nmap --version-intensity <level>: Set from 0 (light) to 9 (try all probes)
     root@hostname: ~/ nmap --version-light: Limit to most likely probes (intensity 2)
     root@hostname: ~/ nmap --version-all: Try every single probe (intensity 9)
     root@hostname: ~/ nmap --version-trace: Show detailed version scan activity (for debugging)

### SCRIPT SCAN:
     root@hostname: ~/ nmap -sC: equivalent to --script=default
     root@hostname: ~/ nmap --script=<Lua scripts>: <Lua scripts> is a comma separated list of
     root@hostname: ~/ nmap --script-args=<n1=v1,[n2=v2,...]>: provide arguments to scripts
     root@hostname: ~/ nmap --script-args-file=filename: provide NSE script args in a file
     root@hostname: ~/ nmap --script-trace: Show all data sent and received
     root@hostname: ~/ nmap --script-updatedb: Update the script database.
     root@hostname: ~/ nmap --script-help=<Lua scripts>: Show help about scripts.

##### OBS:  <Lua scripts> is a comma-separated list of script-files or script-categories.

#### OS DETECTION:
     root@hostname: ~/ nmap -O: Enable OS detection
     root@hostname: ~/ nmap --osscan-limit: Limit OS detection to promising targets
     root@hostname: ~/ nmap --osscan-guess: Guess OS more aggressively
           
### TIMING AND PERFORMANCE:

####### _Options which take <time> are in seconds, or append 'ms' (milliseconds)_
####### _'s' (seconds), 'm' (minutes), or 'h' (hours) to the value (e.g. 30m)_
 
    root@hostname: ~/ nmap -T<0-5>: Set timing template (higher is faster)
    root@hostname: ~/ nmap --min-hostgroup/max-hostgroup <size>: Parallel host scan group sizes
    root@hostname: ~/ nmap --min-parallelism/max-parallelism <numprobes>: Probe parallelization
    root@hostname: ~/ nmap --min-rtt-timeout/max-rtt-timeout/initial-rtt-timeout <time>: Specifies
    root@hostname: ~/ nmap --max-retries <tries>: Caps number of port scan probe retransmissions.
    root@hostname: ~/ nmap --host-timeout <time>: Give up on target after this long
    root@hostname: ~/ nmap --scan-delay/--max-scan-delay <time>: Adjust delay between probes
    root@hostname: ~/ nmap --min-rate <number>: Send packets no slower than <number> per second
    root@hostname: ~/ nmap --max-rate <number>: Send packets no faster than <number> per second

### FIREWALL/IDS EVASION AND SPOOFING:

     root@hostname: ~/ nmap -f; --mtu <val>: fragment packets (optionally w/given MTU)
     root@hostname: ~/ nmap -D <decoy1,decoy2[,ME],...>: Cloak a scan with decoys
     root@hostname: ~/ nmap -S <IP_Address>: Spoof source address
     root@hostname: ~/ nmap -e <iface>: Use specified interface
     root@hostname: ~/ nmap  -g/--source-port <portnum>: Use given port number
     root@hostname: ~/ nmap --proxies <url1,[url2],...>: Relay connections through HTTP/SOCKS4 proxies
     root@hostname: ~/ nmap --data <hex string>: Append a custom payload to sent packets
     root@hostname: ~/ nmap --data-string <string>: Append a custom ASCII string to sent packets
     root@hostname: ~/ nmap --data-length <num>: Append random data to sent packets
     root@hostname: ~/ nmap --ip-options <options>: Send packets with specified ip options
     root@hostname: ~/ nmap --ttl <val>: Set IP time-to-live field
     root@hostname: ~/ nmap --spoof-mac <mac address/prefix/vendor name>: Spoof your MAC address
     root@hostname: ~/ nmap --badsum: Send packets with a bogus TCP/UDP/SCTP checksum

### MISC:
     root@hostname: ~/ nmap -6: Enable IPv6 scanning
     root@hostname: ~/ nmap -A: Enable OS detection, version detection, script scanning, and traceroute
     root@hostname: ~/ nmap --datadir <dirname>: Specify custom Nmap data file location
     root@hostname: ~/ nmap --send-eth/--send-ip: Send using raw ethernet frames or IP packets
     root@hostname: ~/ nmap --privileged: Assume that the user is fully privileged
     root@hostname: ~/ nmap --unprivileged: Assume the user lacks raw socket privileges
     root@hostname: ~/ nmap -V: Print version number
     root@hostname: ~/ nmap -h: Print this help summary page.

# INSTALL NMAP

#### Install nmap on Gentoo Linux
###### Enable all useflags for get all features availabe, zenmap is required if you want include the GUI for NMAP

      echo "net-analyzer/nmap libssh2 ncat ndiff nmap-update nping system-lua zenmap" >> /etc/portage/package.use/nmap
      emerge --ask net-analyzer/nmap

#### Installation on Debian Linux

       apt -qq install nmap -y

#### Installation on Kali Linux (PRE INSTALLED)

       apt -qq install nmap -y

#### Installation on Ubuntu Linux

       apt -qq install nmap -y

#### Installation on Windows 

       Download: https://nmap.org/dist/nmap-7.70-setup.exe
       Place the file in a folder, open properties and copy the location of nmap, open powershell and now
       cd <location of nmap>
       nmap --help


#### For openSUSE Leap 42.3 run the following as root:
zypper addrepo https://download.opensuse.org/repositories/network:utilities/openSUSE_Leap_42.3/network:utilities.repo

#### For openSUSE Leap 15.1 run the following as root:
zypper addrepo https://download.opensuse.org/repositories/network:utilities/openSUSE_Leap_15.1/network:utilities.repo

#### For openSUSE Leap 15.0 run the following as root:
zypper addrepo https://download.opensuse.org/repositories/network:utilities/openSUSE_Leap_15.0/network:utilities.repo

#### For openSUSE Factory PowerPC run the following as root:
zypper addrepo https://download.opensuse.org/repositories/network:utilities/openSUSE_Factory_PowerPC/network:utilities.repo

#### For openSUSE Factory ARM run the following as root:

zypper addrepo https://download.opensuse.org/repositories/network:utilities/openSUSE_Factory_ARM/network:utilities.repo

#### For openSUSE Factory run the following as root:
zypper addrepo https://download.opensuse.org/repositories/network:utilities/openSUSE_Factory/network:utilities.repo

#### And then: 
zypper refresh
zypper install nmap

### After installation, get all scripts by below command:

     root@hostname: ~/ # nmap --script-updatedb


### AFP - Brute-Force                              
_Performs password guessing against Apple Filing Protocol (AFP)_
     
     root@hostname: ~/ # nmap -p 548 --script afp-brute 192.168.1.12

     |PORT    STATE SERVICE
     |548/tcp open  afp
     | afp-brute:
     |_  admin:KenSentMe => Valid credentials



### AJP - Brute-Force                          
_Performs brute force passwords auditing against the Apache JServ protocol. The Apache JServ Protocol is commonly used by web servers to communicate with back-end Java application server containers_

     root@hostname: ~/ # nmap -p 8009 192.168.1.12 --script ajp-brute

     |PORT     STATE SERVICE
     |8009/tcp open  ajp13
     | ajp-brute:
     |   Accounts
     |     root:secret - Valid credentials
     |   Statistics
     |_    Performed 1946 guesses in 23 seconds, average tps: 82



### Backorifice - Brute-Force                         
     
     root@hostname: ~/ # nmap -sU --script backorifice-brute 192.168.1.12 --script-args backorifice-brute. 

     |PORT       STATE  SERVICE
     |31337/udp  open   BackOrifice
     | backorifice-brute:
     |   Accounts:
     |     michael => Valid credentials
     |   Statistics
     |_    Perfomed 60023 guesses in 467 seconds, average tps: 138


### Cassandra - Brute-Force                     
_Performs Brute-Force password auditing against the Cassandra database_
     
     root@hostname: ~/ # nmap -p 9160 192.168.1.12 --script=cassandra-brute

     |PORT     STATE SERVICE VERSION
     |9160/tcp open  apani1?
     | cassandra-brute:
     |   Accounts
     |     admin:lover - Valid credentials
     |     admin:lover - Valid credentials
     |   Statistics
     |_    Performed 4581 guesses in 1 seconds, average tps: 4581


### Cics-enum
_CICS transaction ID enumerator for IBM mainframes_ This script is based on mainframe_brute by Dominic White (https://github_com/sensepost/mainframe_brute)_ However, this script doesn't rely on any third party libraries or tools and instead uses the NSE TN3270 library which emulates a TN3270 screen in lua_
     
     root@hostname: ~/ # nmap --script=cics-enum -p 23 <targets>
     root@hostname: ~/ # nmap --script=cics-enum --script-args=idlist=default_cics.txt,cics-enum.command="exit;logon applid(cics42)",cics-enum.path="/home/dade/screenshots/",cics-enum.noSSL=true -p 23 <targets>

     |PORT   STATE SERVICE
     |23/tcp open  tn3270
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



### Cics-User - Brute-Force
_CICS User ID brute forcing script for the CESL login screen_
     
      root@hostname: ~/ # nmap --script=cics-user-brute -p 23 <targets>
      root@hostname: ~/ # nmap --script=cics-user-brute --script-args userdb=users.txt cics-user-brute.commands="exit;logon applid(cics42)" -p 23 <targets>

     |PORT   STATE SERVICE
     |23/tcp open  tn3270
     | cics-user-brute:
     |   Accounts:
     |     PLAGUE: Valid - CICS User ID
     |_  Statistics: Performed 31 guesses in 114 seconds, average tps: 0



### Cics-User-Enum                           
_CICS User ID enumeration script for the CESL/CESN Login screen_
     
     root@hostname: ~/ # nmap --script=cics-user-enum -p 23 <targets>
     root@hostname: ~/ # nmap --script=cics-user-enum --script-args userdb=users_txt cics-user-enum_commands="exit;logon applid(cics42)" -p 23 <targets>
     
     |PORT   STATE SERVICE
     |23/tcp open  tn3270
     | cics-user-enum:
     |   Accounts:
     |     PLAGUE: Valid - CICS User ID
     |_  Statistics: Performed 31 guesses in 114 seconds, average tps: 0



### Citrix - Brute-Force-xml
_Attempts to guess valid credentials for the Citrix PN Web Agent XML Service_ The XML service authenticates against the local Windows server or the Active Directory_
     
     root@hostname: ~/ # nmap --script=citrix - Brute-Force-xml --script-args=userdb=<userdb>,passdb=<passdb>,ntdomain=<domain> -p 80,443,8080 192.168.1.12

     |PORT     STATE SERVICE    REASON
     |8080/tcp open  http-proxy syn-ack
     | citrix-brute-xml:
     |   Joe:password => Must change password at next logon
     |   Luke:summer => Login was successful
     |_  Jane:secret => Account is disabled







### Cvs - Brute-Force
_Performs Brute-Force password auditing against CVS pserver authentication_
     
     root@hostname: ~/ # nmap -p 2401 --script cvs-brute 192.168.1.12

     |2401/tcp open  cvspserver syn-ack
     | cvs-brute:
     |   Accounts
     |     hotchner:francisco - Account is valid
     |     reid:secret - Account is valid
     |   Statistics
     |_    Performed 544 guesses in 14 seconds, average tps: 38



### Cvs Repository - Brute-Force 
_Attempts to guess the name of the CVS repositories hosted on the remote server_ With knowledge of the correct repository name, usernames and passwords can be guessed_
     
     root@hostname: ~/ # nmap -p 2401 --script cvs-brute-repository 192.168.1.12

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
     
     root@hostname: ~/ # nmap --script deluge-rpc-brute -p 58846 192.168.1.12

     |PORT      STATE SERVICE REASON  TTL
     |58846/tcp open  unknown syn-ack 0
     | deluge-rpc-brute:
     |   Accounts
     |     admin:default - Valid credentials
     |   Statistics
     |_    Performed 8 guesses in 1 seconds, average tps: 8



### Domcon - Brute-Force
_Performs Brute-Force password auditing against the Lotus Domino Console_
     
     root@hostname: ~/ # nmap --script domcon-brute -p 2050 192.168.1.12

     |PORT     STATE SERVICE REASON
     |2050/tcp open  unknown syn-ack
     | domcon-brute:
     |   Accounts
     |_    patrik karlsson:secret => Login correct



### DPAP - Brute-Force
_Performs Brute-Force password auditing against an iPhoto Library_
     
     root@hostname: ~/ # nmap --script dpap-brute -p 8770 192.168.1.12

     |PORT     STATE SERVICE REASON
     |8770/tcp open  apple-iphoto syn-ack
     | dpap-brute:
     |   Accounts
     |     secret => Login correct
     |   Statistics
     |_    Perfomed 5007 guesses in 6 seconds, average tps: 834


### DRDA - Brute-Force
_Performs password guessing against databases sup     |PORTing the IBM DB2 protocol such as Informix, DB2 and Derby_
     
     root@hostname: ~/ # nmap -p 50000 --script drda-brute 192.168.1.12

     |PORT     STATE SERVICE REASON
     |50000/tcp open  drda
     | drda-brute:
     |_  db2admin:db2admin => Valid credentials




### FTP - Brute-Force
_Performs Brute-Force password auditing against FTP servers_
     
     root@hostname: ~/ # nmap --script ftp-brute -p 21 192.168.1.12

     |PORT   STATE SERVICE
     |21/tcp open  ftp
     | ftp-brute:
     |   Accounts
     |     root:root - Valid credentials
     |   Statistics
     |_    Performed 510 guesses in 610 seconds, average tps: 0


### HTTP - Brute-Force
_Performs Brute-Force password auditing against http basic, digest and ntlm authentication_
     
     root@hostname: ~/ # nmap --script http-brute -p 80 192.168.1.12

     |PORT     STATE SERVICE REASON
     |80/tcp   open  http    syn-ack
     | http-brute:
     |   Accounts:
     |     user:user - Valid credentials
     |_  Statistics: Performed 123 guesses in 1 seconds, average tps: 123



### HTTP-Form - Brute-Force
_Performs Brute-Force password auditing against http form-based authentication_
     
     root@hostname: ~/ # nmap --script http-form-brute -p 80 192.168.1.12

     |PORT     STATE SERVICE REASON
     |80/tcp   open  http    syn-ack
     | http-form-brute:
     |   Accounts
     |     Patrik Karlsson:secret - Valid credentials
     |   Statistics
     |_    Perfomed 60023 guesses in 467 seconds, average tps: 138


### HTTP-IIS-Short-Name - Brute-Force
_Attempts to Brute-Force the 8_3 filenames (commonly known as short names) of files and directories in the root folder of vulnerable IIS servers_ This script is an implementation of the PoC "iis shortname scanner"_
     
     root@hostname: ~/ # nmap -p80 --script http-iis-short-name-brute 192.168.1.12

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
     
     root@hostname: ~/ # nmap -sV --script http-joomla-brute --script-args 'userdb=users.txt,passdb=passwds.txt,http-joomla-brute.hostname=domain.com,http-joomla-brute.threads=3,brute.firstonly=true' 192.168.1.12


     |PORT     STATE SERVICE REASON
     |80/tcp open  http    syn-ack
     | http-joomla-brute:
     |   Accounts
     |     xdeadbee:i79eWBj07g => Login correct
     |   Statistics
     |_    Perfomed 499 guesses in 301 seconds, average tps: 0



### HTTP-Proxy - Brute-Force
_Performs Brute-Force password guessing against HTTP proxy servers_
     
     root@hostname: ~/ # nmap --script http-proxy-brute -p 8080 192.168.1.12

     |PORT     STATE SERVICE
     |8080/tcp open  http-proxy
     | http-proxy-brute:
     |   Accounts
     |     patrik:12345 - Valid credentials
     |   Statistics
     |_    Performed 6 guesses in 2 seconds, average tps: 3


### HTTP-WordPress - Brute-Force
_Performs Brute-Force password auditing against Wordpress CMS/blog installations_
     
     root@hostname: ~/ # nmap -sV --script http-wordpress-brute --script-args 'userdb=users.txt,passdb=passwds.txt,http-wordpress-brute.hostname=domain.com,http-wordpress-brute.threads=3,brute.firstonly=true' 192.168.1.12

     |PORT     STATE SERVICE REASON
     |80/tcp   open  http    syn-ack
     | http-wordpress-brute:
     |   Accounts
     |     0xdeadb33f:god => Login correct
     |   Statistics
     |_    Perfomed 103 guesses in 17 seconds, average tps: 6




### IAX2 - Brute-Force
_Performs Brute-Force password auditing against the Asterisk IAX2 protocol_ Guessing fails when a large number of attempts is made due to the maxcallnumber limit (default 2048)_ In case your getting "ERROR: Too many retries, aborted ___" after a while, this is most likely what's happening_ In order to avoid this problem try: - reducing the size of your dictionary - use the brute delay option to introduce a delay between guesses - split the guessing up in chunks and wait for a while between them_   
 
     root@hostname: ~ nmap -sU -p 4569 192.168.1.12 --script iax2-brute

     | PORT     STATE         SERVICE   
     |4569/udp open     |filtered unknown
     |  iax2-brute:
     |    Accounts
     |      1002:password12 - Valid credentials
     |    Statistics
     _    Performed 1850 guesses in 2 seconds, average tps: 925




### IMAP - Brute-Force
_Performs Brute-Force password auditing against IMAP servers using either LOGIN, PLAIN, CRAM-MD5, DIGEST-MD5 or NTLM authentication_
     
     root@hostname: ~/ # nmap -p 143,993 --script imap-brute 192.168.1.12

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
     
     root@hostname: ~/ # nmap -p 1599 --script impress-remote-discover 192.168.1.12

     |PORT     STATE SERVICE        Version
     |1599/tcp open  impress-remote LibreOffice Impress remote 4.3.3.2
     | impress-remote-discover:
     |   Impress Version: 4.3.3.2
     |   Remote PIN: 0000
     |_  Client Name used: Firefox OS


### Informix - Brute-Force
_Performs Brute-Force password auditing against IBM Informix Dynamic Server_
     
     root@hostname: ~/ # nmap --script informix-brute -p 9088 192.168.1.12

     |PORT     STATE SERVICE
     |9088/tcp open  unknown
     | informix-brute:
     |   Accounts
     |     ifxnoob:ifxnoob => Valid credentials
     |   Statistics
     |_    Perfomed 25024 guesses in 75 seconds, average tps: 320

Summary
-------
  x The Driver class contains the driver implementation used by the brute
    library





### IPMI - Brute-Force
_Performs Brute-Force password auditing against IPMI RPC server_
     
     root@hostname: ~/ # nmap -sU --script ipmi-brute -p 623 192.168.1.12


     |PORT     STATE  SERVICE REASON
     |623/udp  open     |filtered  unknown
     | ipmi-brute:
     |   Accounts
     |_    admin:admin => Valid credentials



### IRC - Brute-Force
_Performs Brute-Force password auditing against IRC (Internet Relay Chat) servers_
     
     root@hostname: ~/ # nmap --script irc-brute -p 6667 192.168.1.12

     |PORT     STATE SERVICE
     |6667/tcp open  irc
     | irc-brute:
     |   Accounts
     |     password - Valid credentials
     |   Statistics
     |_    Performed 1927 guesses in 36 seconds, average tps: 74




### IRC-sasl - Brute-Force
_Performs Brute-Force password auditing against IRC (Internet Relay Chat) servers sup     |PORTing SASL authentication_
     
     root@hostname: ~/ # nmap --script irc-sasl-brute -p 6667 192.168.1.12

     |PORT     STATE SERVICE REASON
     |6667/tcp open  irc     syn-ack
     | irc-sasl-brute:
     |   Accounts
     |     root:toor - Valid credentials
     |   Statistics
     |_    Performed 60 guesses in 29 seconds, average tps: 2


### ISCSI - Brute-Force
_Performs Brute-Force password auditing against iSCSI targets_
     
     root@hostname: ~/ # nmap -sV --script=iscsi-brute 192.168.1.12

     |PORT     STATE SERVICE
     |3260/tcp open  iscsi   syn-ack
     | iscsi-brute:
     |   Accounts
     |     user:password123456 => Valid credentials
     |   Statistics
     |_    Perfomed 5000 guesses in 7 seconds, average tps: 714




### LDAP - Brute-Force
_Attempts to brute-force LDAP authentication_ By default it uses the built-in username and password lists_ In order to use your own lists use the userdb and passdb script arguments_
     
     root@hostname: ~/ # nmap -p 389 --script ldap-brute --script-args ldap.base='"cn=users,dc=cqure,dc=net"' 192.168.1.12

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
     
     root@hostname: ~/ # nmap --script lu-enum --script-args lulist=lus.txt,lu-enum.path="/home/dade/screenshots/" -p 23 -sV <targets>

     |PORT     STATE SERVICE REASON  VERSION
     |23/tcp   open  tn3270  syn-ack IBM Telnet TN3270 (TN3270E)
     | lu-enum: 
     |   Logical Units: 
     |     LU:BSLVLU69 - Valid credentials
     |_  Statistics: Performed 7 guesses in 7 seconds, average tps: 1.0




### Membase - Brute-Force 
_Performs Brute-Force password auditing against Couchbase Membase servers_
     
     root@hostname: ~/ # nmap -p 11211 --script membase-brute

     |PORT      STATE SERVICE
     |11211/tcp open  unknown
     | membase-brute:
     |   Accounts
     |     buckettest:toledo - Valid credentials
     |   Statistics
     |_    Performed 5000 guesses in 2 seconds, average tps: 2500


### Metasploit-MSGRPC - Brute-Force
_Performs Brute-Force username and password auditing against Metasploit msgrpc interface_
     





### Metasploit-XMLRPC - Brute-Force
_Performs Brute-Force password auditing against a Metasploit RPC server using the XMLRPC protocol_
     
     root@hostname: ~/ # nmap --script metasploit-msgrpc-brute -p 55553 192.168.1.12

     |PORT      STATE SERVICE REASON
     |55553/tcp open  unknown syn-ack
     | metasploit-msgrpc-brute:
     |   Accounts
     |     root:root - Valid credentials
     |   Statistics
     |_    Performed 10 guesses in 10 seconds, average tps: 1



### Mikrotik-RouterOS - Brute-Force
_Performs Brute-Force password auditing against Mikrotik RouterOS devices with the API RouterOS interface enabled_
     
     root@hostname: ~/ # nmap -p8728 --script mikrotik-routeros-brute 192.168.1.12

     |PORT     STATE SERVICE REASON
     |8728/tcp open  unknown syn-ack
     | mikrotik-routeros-brute:
     |   Accounts
     |     admin:dOsmyvsvJGA967eanX - Valid credentials
     |   Statistics
     |_    Performed 60 guesses in 602 seconds, average tps: 0




### MMouse - Brute-Force
_Performs Brute-Force password auditing against the RPA Tech Mobile Mouse servers_
     
     root@hostname: ~/ # nmap --script mmouse-brute -p 51010 192.168.1.12

     |PORT      STATE SERVICE
     |51010/tcp open  unknown
     | mmouse-brute:
     |   Accounts
     |     vanilla - Valid credentials
     |   Statistics
     |_    Performed 1199 guesses in 23 seconds, average tps: 47




### MongoDB - Brute-Force
_ Performs Brute-Force password auditing against the MongoDB database_
     
     root@hostname: ~/ # nmap -p 27017 192.168.1.12 --script mongodb-brute

     |PORT      STATE SERVICE
     |27017/tcp open  mongodb
     | mongodb-brute:
     |   Accounts
     |     root:Password1 - Valid credentials
     |   Statistics
     |_    Performed 3542 guesses in 9 seconds, average tps: 393





### MS-SQL - Brute-Force
_Performs password guessing against Microsoft SQL Server (ms-sql)_ Works best in conjunction with the broadcast-ms-sql-discover script_
     
     root@hostname: ~/ # nmap -p 445 --script ms-sql-brute --script-args mssql.instance-all,userdb=customuser.txt,passdb=custompass.txt 192.168.1.12
     root@hostname: ~/ # nmap -p 1433 --script ms-sql-brute --script-args userdb=customuser.txt,passdb=custompass.txt 192.168.1.12

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
     
     root@hostname: ~/ # nmap --script=mysql-brute 192.168.1.12

     |PORT     STATE SERVICE REASON
     |3306/tcp open  mysql
     | mysql-brute:
     |   Accounts
     |     root:root - Valid credentials



### MySQL-enum                              
_Performs valid-user enumeration against MySQL server using a bug discovered and published by Kingcope (http://seclists_org/fulldisclosure/2012/Dec/9)_
     
     root@hostname: ~/ # nmap --script=mysql-enum 192.168.1.12

     |PORT     STATE SERVICE REASON
     |3306/tcp open  mysql   syn-ack
     | mysql-enum:
     |   Accounts
     |     admin:<empty> - Valid credentials
     |     test:<empty> - Valid credentials
     |     test_mysql:<empty> - Valid credentials
     |   Statistics
     |_    Performed 11 guesses in 1 seconds, average tps: 11




### Nessus - Brute-Force                             
_Performs Brute-Force password auditing against a Nessus vulnerability scanning daemon using the NTP 1_2 protocol_
     
     root@hostname: ~/ # 

     |PORT     STATE SERVICE
     |1241/tcp open  nessus
     | nessus-brute:
     |   Accounts
     |     nessus:nessus - Valid credentials
     |   Statistics
     |_    Performed 35 guesses in 75 seconds, average tps: 0

This script does not appear to perform well when run using multiple threads
Although, it's very slow running under a single thread it does work as intended



### Nessus-XMLRPC - Brute-Force                   
_Performs Brute-Force password auditing against a Nessus vulnerability scanning daemon using the XMLRPC protocol_
     
     root@hostname: ~/ # nmap -sV --script=nessus-xmlrpc-brute 192.168.1.12

     |PORT     STATE SERVICE REASON
     |8834/tcp open  unknown syn-ack
     | nessus-xmlrpc-brute:
     |   Accounts
     |     nessus:nessus - Valid credentials
     |   Statistics
     |_    Performed 1933 guesses in 26 seconds, average tps: 73



### Netbus - Brute-Force                             
_Performs Brute-Force password auditing against the Netbus backdoor ("remote administration") service_
     
     root@hostname: ~/ # nmap -p 12345 --script netbus-brute 192.168.1.12

     |12345/tcp open  netbus
     |_netbus-brute: password123




### Nexpose - Brute-Force                            
_Performs Brute-Force password auditing against a Nexpose vulnerability scanner using the API 1_1_
     
     root@hostname: ~/ # nmap --script nexpose-brute -p 3780 192.168.1.12

     |PORT     STATE SERVICE     REASON  VERSION
     |3780/tcp open  ssl/nexpose syn-ack NeXpose NSC 0.6.4
     | nexpose-brute:
     |   Accounts
     |     nxadmin:nxadmin - Valid credentials
     |   Statistics
     |_    Performed 5 guesses in 1 seconds, average tps: 5




### NJE-Node - Brute-Force                           
_z/OS JES Network Job Entry (NJE) target node name Brute-Force_
     
     root@hostname: ~/ # nmap -sV --script=nje-node-brute 192.168.1.12
     root@hostname: ~/ # nmap --script=nje-node-brute --script-args=hostlist=nje_names.txt -p 175 192.168.1.12

     |PORT    STATE SERVICE REASON
     |175/tcp open  nje     syn-ack
     | nje-node-brute:
     |   Node Name:
     |     POTATO:CACTUS - Valid credentials
     |_  Statistics: Performed 6 guesses in 14 seconds, average tps: 0




### NJE-Pass - Brute-Force                           
_z/OS JES Network Job Entry (NJE) 'I record' password Brute-Forcer_
     
     root@hostname: ~/ # nmap -sV --script=nje-pass-brute --script-args=ohost='POTATO',rhost='CACTUS' 192.168.1.12
     root@hostname: ~/ # nmap --script=nje-pass-brute --script-args=ohost='POTATO',rhost='CACTUS',sleep=5 -p 175 192.168.1.12

     |PORT    STATE SERVICE VERSION
     |175/tcp open  nje     IBM Network Job Entry (JES)
     | nje-pass-brute:
     |   NJE Password:
     |     Password:A - Valid credentials
     |_  Statistics: Performed 8 guesses in 12 seconds, average tps: 0





### Nping - Brute-Force                         
_Performs Brute-Force password auditing against an Nping Echo service_
     
     root@hostname: ~/ # nmap -p 9929 --script nping-brute 192.168.1.12

     |9929/tcp open  nping-echo
     | nping-brute:
     |   Accounts
     |     123abc => Valid credentials
     |   Statistics
     |_    Perfomed 204 guesses in 204 seconds, average tps: 1





### OMPv2 - Brute-Force                              
_Performs Brute-Force password auditing against the OpenVAS manager using OMPv2_
     
     root@hostname: ~/ # nmap -p 9390 --script omp2-brute 192.168.1.12

     |PORT     STATE SERVICE REASON
     |9390/tcp open  openvas syn-ack
     | omp2-brute:
     |   Accounts
     |_    admin:secret => Valid credentials



### OpenVAS-OTP - Brute-Force                         
_Performs Brute-Force password auditing against a OpenVAS vulnerability scanner daemon using the OTP 1_0 protocol_
     
     root@hostname: ~/ # nmap -sV --script=openvas-otp-brute 192.168.1.12

PORT     STATE SERVICE    REASON  VERSION
     |9391/tcp open  ssl/openvas syn-ack
     | openvas-otp-brute:
     |   Accounts
     |     openvas:openvas - Valid credentials
     |   Statistics
     '-.>   Performed 4 guesses in 4 seconds, average tps: 1

### Oracle - Brute-Force                             
_Performs Brute-Force password auditing against Oracle servers_
     
     root@hostname: ~/ # nmap --script oracle-brute -p 1521 --script-args oracle-brute.sid=ORCL 192.168.1.12

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
     
     root@hostname: ~/ # nmap --script oracle-brute-stealth -p 1521 --script-args oracle-brute-stealth.sid=ORCL 192.168.1.12

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
     
     root@hostname: ~/ # nmap --script=oracle-sid-brute --script-args=oraclesids=/path/to/sidfile -p 1521-1560 192.168.1.12
     root@hostname: ~/ # nmap --script=oracle-sid-brute -p 1521-1560 192.168.1.12

     |PORT     STATE SERVICE REASON
     |1521/tcp open  oracle  syn-ack
     | oracle-sid-brute:
     |   orcl
     |   prod
     |_  devel




### pcAnywhere - Brute-Force                     
_Performs Brute-Force password auditing against the pcAnywhere remote access protocol_
     
     root@hostname: ~/ # nmap --script=pcanywhere-brute 192.168.1.12

     |5631/tcp open  pcanywheredata syn-ack
     | pcanywhere-brute:
     |   Accounts
     |     administrator:administrator - Valid credentials
     |   Statistics
     |_    Performed 2 guesses in 55 seconds, average tps: 0




### PostgreSQL - Brute-Force                         
_Performs password guessing against PostgreSQL_
     
     root@hostname: ~/ # nmap -p 5432 --script pgsql-brute 192.168.1.12

     |5432/tcp open  pgsql
     | pgsql-brute:
     |   root:<empty> => Valid credentials
     |_  test:test => Valid credentials




### POP3 - Brute-Force                              
_Tries to log into a POP3 account by guessing usernames and passwords_
     
     root@hostname: ~/ # nmap -sV --script=pop3-brute 192.168.1.12

     |PORT    STATE SERVICE
     |110/tcp open  pop3
     | pop3-brute-     |PORTed:
     | Accounts:
     |  user:pass => Login correct
     | Statistics:
     |_ Performed 8 scans in 1 seconds, average tps: 8






### Redis - Brute-Force                         
_Performs Brute-Force passwords auditing against a Redis key-value store_
     
     root@hostname: ~/ # nmap -p 6379 192.168.1.12 --script redis-brute

     |PORT     STATE SERVICE
     |6379/tcp open  unknown
     | redis-brute:
     |   Accounts
     |     toledo - Valid credentials
     |   Statistics
     |_    Performed 5000 guesses in 3 seconds, average tps: 1666





### RExec - Brute-Force                         
_Performs Brute-Force password auditing against the classic UNIX rexec (remote exec) service_
     
     root@hostname: ~/ # nmap -p 512 --script rexec-brute 192.168.1.12

     |PORT    STATE SERVICE
     |512/tcp open  exec
     | rexec-brute:
     |   Accounts
     |     nmap:test - Valid credentials
     |   Statistics
     |_    Performed 16 guesses in 7 seconds, average tps: 2


### UNIX-RLogin - Brute-Force                            
_Performs Brute-Force password auditing against the classic UNIX rlogin (remote login) service_ This script must be run in privileged mode on UNIX because it must bind to a low source      |PORT number_
     
     root@hostname: ~/ # nmap -p 513 --script rlogin-brute 192.168.1.12

     |PORT    STATE SERVICE
     |513/tcp open  login
     | rlogin-brute:
     |   Accounts
     |     nmap:test - Valid credentials
     |   Statistics
     |_    Performed 4 guesses in 5 seconds, average tps: 0





### RPcap - Brute-Force                         
_Performs Brute-Force password auditing against the WinPcap Remote Capture Daemon (rpcap)_
     
     root@hostname: ~/ # nmap -p 2002 192.168.1.12 --script rpcap-brute

     |PORT     STATE SERVICE REASON
     |2002/tcp open  globe   syn-ack
     | rpcap-brute:
     |   Accounts
     |     monkey:Password1 - Valid credentials
     |   Statistics
     |_    Performed 3540 guesses in 3 seconds, average tps: 1180





### Rsync - Brute-Force                         
_Performs Brute-Force password auditing against the rsync remote file syncing protocol_
     
     root@hostname: ~/ # nmap -p 873 --script rsync-brute --script-args 'rsync-brute.module=www' 192.168.1.12

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
     
     root@hostname: ~/ # nmap --script rtsp-url-brute -p 554 192.168.1.12

     |PORT    STATE SERVICE
     |554/tcp open  rtsp
     | rtsp-url-brute:
     |   discovered:
     |     rtsp://camera.example.com/mpeg4
     |   other responses:
     |     401:
     |_      rtsp://camera.example.com/live/mpeg4





### SIP - Brute-Force                               
_Performs Brute-Force password auditing against Session Initiation Protocol (SIP) accounts_ This protocol is most commonly associated with VoIP sessions_
     
     root@hostname: ~/ # 



### SMB - Brute-Force                               
_Attempts to guess username/password combinations over SMB, storing discovered combinations for use in other scripts_ Every attempt will be made to get a valid list of users and to verify each username before actually using them_ When a username is discovered, besides being printed, it is also saved in the Nmap registry so other Nmap scripts can use it_ That means that if you're going to run smb - Brute-Force_nse, you should run other smb scripts you want_ This checks passwords in a case-insensitive way, determining case after a password is found, for Windows versions before Vista_
     
     root@hostname: ~/ # nmap -sU -sS --script smb-brute.nse -p U:137,T:139 192.168.1.12

Host script results:
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
     
     root@hostname: ~/ # nmap -p 25 --script smtp-brute 192.168.1.12

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
     
     root@hostname: ~/ # nmap --script socks-brute -p 1080 192.168.1.12

     |PORT     STATE SERVICE
     |1080/tcp open  socks
     | socks-brute:
     |   Accounts
     |     patrik:12345 - Valid credentials
     |   Statistics
     |_    Performed 1921 guesses in 6 seconds, average tps: 320




### SOCKS5-Proxy - Brute-Force                         
_Performs Brute-Force password auditing against SOCKS 5 proxy servers_
     
     root@hostname: ~/ # 



### SSH - Brute-Force                               
_Performs brute-force password guessing against ssh servers_
     
     root@hostname: ~/ #   nmap -p 22 --script ssh-brute --script-args userdb=users.lst,passdb=pass.lst --script-args ssh-brute.timeout=4s 192.168.1.12

     |22/ssh open  ssh
     | ssh-brute:
     |  Accounts
     |    username:password
     |  Statistics
     |_   Performed 32 guesses in 25 seconds.

### SVN - Brute-Force                               
_Performs Brute-Force password auditing against Subversion source code control servers_
     
     root@hostname: ~/ # nmap --script svn-brute --script-args svn-brute.repo=/svn/ -p 3690 192.168.1.12

     |PORT     STATE SERVICE REASON
     |3690/tcp open  svn     syn-ack
     | svn-brute:
     |   Accounts
     |_    patrik:secret => Login correct

Summary
-------
  x The svn class contains the code needed to perform CRAM-MD5
    authentication
  x The Driver class contains the driver implementation used by the brute
    library




### Telnet - Brute-Force                             
_Performs brute-force password auditing against telnet servers_
     
     root@hostname: ~/ #   nmap -p 23 --script telnet-brute --script-args userdb=myusers.lst,passdb=mypwds.lst,telnet-brute.timeout=8s 192.168.1.12

     |23/tcp open  telnet
     | telnet-brute:
     |   Accounts
     |     wkurtz:colonel
     |   Statistics
     |_    Performed 15 guesses in 19 seconds, average tps: 0




### TSO-Enum                                
_TSO User ID enumerator for IBM mainframes (z/OS)_ The TSO logon panel tells you when a user ID is valid or invalid with the message: IKJ56420I Userid <user ID> not authorized to use TSO_
     
     root@hostname: ~/ # nmap -sV -p 9923 10.32.70.10 --script tso-enum --script-args userdb=tso_users.txt,tso-enum.commands="logon applid(tso)"

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
     
     root@hostname: ~/ # nmap -p 902 192.168.1.12 --script vmauthd-brute

     |PORT    STATE SERVICE
     |902/tcp open  iss-realsecure
     | vmauthd-brute:
     |   Accounts
     |     root:00000 - Valid credentials
     |   Statistics
     |_    Performed 183 guesses in 40 seconds, average tps: 4


### VNC - Brute-Force                               
_Performs Brute-Force password auditing against VNC servers_
     
     root@hostname: ~/ # nmap --script vnc-brute -p 5900 192.168.1.12

     |PORT     STATE  SERVICE REASON
     |5900/tcp open   vnc     syn-ack
     | vnc-brute:
     |   Accounts
     |_    123456 => Valid credentials



### VTAM-Enum                               
_Many mainframes use VTAM screens to connect to various applications (CICS, IMS, TSO, and many more)_
     
     root@hostname: ~/ # nmap --script vtam-enum --script-args idlist=defaults.txt,vtam-enum.command="exit;logon applid(logos)",vtam-enum.macros=truevtam-enum.path="/home/dade/screenshots/" -p 23 -sV <targets>

     |PORT   STATE SERVICE VERSION
     |23/tcp open  tn3270  IBM Telnet TN3270
     | vtam-enum:
     |   VTAM Application ID:
     |     applid:TSO - Valid credentials
     |     applid:CICSTS51 - Valid credentials
     |_  Statistics: Performed 14 guesses in 5 seconds, average tps: 2




### XMPP - Brute-Force                              
_Performs Brute-Force password auditing against XMPP (Jabber) instant messaging servers_
     
     root@hostname: ~/ # nmap -p 5222 --script xmpp-brute 192.168.1.12

     |PORT     STATE SERVICE
     |5222/tcp open  xmpp-client
     | xmpp-brute:
     |   Accounts
     |     CampbellJ:arthur321 - Valid credentials
     |     CampbellA:joan123 - Valid credentials
     |     WalkerA:auggie123 - Valid credentials
     |   Statistics
     |_    Performed 6237 guesses in 5 seconds, average tps: 1247



# NMAP RANDOM TIPS AND TRICKS FROM WUSEMAN
### ========================================

### Net Discover
     root@hostname: ~/ # nmap -sP 192.168.1.*

#### Quick scan
     root@hostname: ~/ # nmap -Pn dhound_io                                                                                                                   

#### Fast Scan
     root@hostname: ~/ # nmap -T4 -F 192.168.0.164

#### Full TCP Port scan using with service version detection
     root@hostname: ~/ # nmap -p 1-65535 -Pn -sV -sS -T4 dhound_io       

# Get a list of ssh servers on the local subnet
nmap -p 22 open -sV 192.168.2.0/24


#### Scan particular ports
     root@hostname: ~/ # nmap -Pn -p 22,80,443 dhound_io   

#### Find linux devices in local network                                                             
     root@hostname: ~/ # nmap -p 22 --open -sV 192.168.1.0/24                                                                                                

#### Trace trafic
     root@hostname: ~/ # nmap --traceroute -p 80 dhound_io                                                                                                   

#### Trace trafic with Geo resolving
     root@hostname: ~/ # nmap --traceroute --script traceroute-geolocation_nse -p 80 dhound_io                                                                

#### WHOIS ISP, Country, Company
     root@hostname: ~/ # nmap --script=asn-query dhound_io                                                                                                    

#### Get SSL Certificate
     root@hostname: ~/ # nmap --script ssl-cert -p 443 -Pn dhound_io                                                                                          

#### Test SSL Ciphers
     root@hostname: ~/ # nmap --script ssl-enum-ciphers -p 443 dhound_io                                                                                      

#### Ftp Brute-Force
     root@hostname: ~/ # nmap --script ftp - Brute-Force --script-args userdb=users_txt,passdb=passwords_txt -p 21 -Pn dhound_io                                      

#### HTTP Basic Authentication Brute-Force
     root@hostname: ~/ # nmap --script http - Brute-Force -script-args http - Brute-Force_path=/evifile-bb-demo,userdb=users_txt,passdb=passwords_txt -p 80 -Pn dhound_io     

#### Find vulnerabilities in safe mode
     root@hostname: ~/ # nmap --script default,safe -Pn dhound_io                                                                                             

#### Find vulnerabilities in unsafe mode
     root@hostname: ~/ # nmap --script vuln -Pn dhound_io                                                                                                     

#### Run DDos attack
     root@hostname: ~/ # nmap --script dos -Pn dhound_io                                                                                                      

#### Exploit detected vulnerabilities
     root@hostname: ~/ #      root@hostname: ~/ # nmap --script exploit -Pn dhound_io                                                                                                  

#### Find unused IPs on a given subnet
     root@hostname: ~/ # nmap -sP <subnet>.* | egrep -o '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' > results.txt ; for IP in {1..254} ; do echo "<subnet>.${IP}" ; done >> results.txt ; cat results.txt | sort -n -t . -k 1,1 -k 2,2 -k 3,3 -k 4,4 | uniq -u

#### nmap scan hosts for IP, MAC Address and device Vendor/Manufacturer
     root@hostname: ~/ # nmap -sP 10.0.0.0/8 | grep -v "Host" | tail -n +3 | tr '\n' ' ' | sed 's|Nmap|\nNmap|g' | grep "MAC Address" | cut -d " " -f5,8-15

#### A list of IPs (only) that are online in a specific subnet.
     root@hostname: ~/ # nmap -sP  192.168.1.0/24 | awk "/^Host/"'{ print $3 }' |nawk -F'[()]' '{print $2}'

# Display only hosts up in network
     root@hostname: ~/ # nmap -sP -PR -oG - `/sbin/ip -4 addr show | awk '/inet/ {print $2}' | sed 1d`

# NMAP_UNDERGROUND_VECTRA
     root@hostname: ~/ # nmap -sS -O -v -oS - 192.168.2.0/24

#### Scan Network for Rogue APs.
     root@hostname: ~/ # nmap -A -p1-85,113,443,8080-8100 -T4 min-hostgroup 50 max-rtt-timeout 2000 initial-rtt-timeout 300 max-retries 3 host-timeout 20m max-scan-delay 1000 -oA wapscan 10.0.0.0/8

#### The NMAP command you can use scan for the Conficker virus on your LAN
     root@hostname: ~/ # nmap -PN -T4 -p139,445 -n -v script=smb-check-vulns script-args safe=1 192.168.0.1-254

#### nmap IP block and autogenerate comprehensive Nagios service checks
     root@hostname: ~/ # nmap -sS -O -oX /tmp/nmap.xml 10.1.1.0/24 -v -v && perl nmap2nagios.pl -v -r /tmp/10net.xml -o /etc/nagios/10net.cfg

#### List of reverse DNS records for a subnet
     root@hostname: ~/ # nmap -R -sL 209.85.229.99/27 | awk '{if($3=="not")print"("$2") no PTR";else print$3" is "$2}' | grep '('

#### list all opened ports on host
     root@hostname: ~/ # nmap -p 1-65535 open localhost

#### Get list of servers with a specific port open
     root@hostname: ~/ # nmap -sT -p 80 -oG - 192.168.1.* | grep open

#### Scan computers OS and open services on all network
     root@hostname: ~/ # nmap -O 192.168.1.12/24

#### Get info about remote host ports and OS detection
     root@hostname: ~/ # nmap -sS -P0 -sV -O 192.168.1.12

#### Getting a list of active addresses in your own network.
     root@hostname: ~/ # nmap -n -sP -oG - 10.10.10.*/32 | grep ": Up" | cut -d' ' -f2

#### Nmap find open TCP/IP ports for a target that is blocking ping
     root@hostname: ~/ # nmap -sT -PN -vv <target ip>

#### Getting a list of active addresses in your own network.
     root@hostname: ~/ # nmap -n -sP -oG - 10.10.10.*/32 | grep ": Up" | cut -d' ' -f2

#### script broadcast-pppoe-discover
     root@hostname: ~/ # nmap -T4 script broadcast-pppoe-discover 192.168.122.0/24

#### nmap IP block and autogenerate comprehensive Nagios service checks
     root@hostname: ~/ # nmap -sS -O -oX /tmp/nmap.xml 10.1.1.0/24 -v -v && perl nmap2nagios.pl -v -r /tmp/10net.xml -o /etc/nagios/10net.cfg

#### The NMAP command you can use scan for the Conficker virus on your LAN
     root@hostname: ~/ # nmap -PN -T4 -p139,445 -n -v script=smb-check-vulns script-args safe=1 192.168.0.1-254

#### nmap  discorvery network on port 80
     root@hostname: ~/ # nmap -p 80 -T5 -n -min-parallelism 100 open 192.168.1.0/24


#### nmap all my hosts in EC2
     root@hostname: ~/ # nmap -P0 -sV `aws output json ec2 describe-addresses | jq -r '.Addresses[].PublicIp'` | tee /dev/shm/nmap-output.txt

#### List services running on each open port
     root@hostname: ~/ # nmap -T Aggressive -A -v 127.0.0.1 -p 1-65000

#### Nmap list IPs in a network and saves in a txt
     root@hostname: ~/ # nmap -sP 192.168.1.0/24 | grep "Nmap scan report for"| cut -d' ' -f 5  > ips.txt

#### count of down available ips
     root@hostname: ~/ # nmap -v -sP 192.168.10.0/24 | grep down | wc -l

####  Locate random web servers for browsing.
     root@hostname: ~/ # nmap -Pn -sS -p 80 -iR 0 --open to




#### network interface and routing summary

     root@hostname: ~/ ####      wuseman@thinkpad ~ $ nmap  --iflist

     Starting Nmap 7.70 ( https://nmap.org ) at 2019-06-20 19:11 -00
     ************************INTERFACES************************
     DEV  (SHORT) IP/MASK                                 TYPE     UP   MTU   MAC
     eth0 (eth0)  192.168.1.1204/24                        ethernet up   1500  11:22:33:44:55:66
     eth0 (eth0)  fe80::88ee:75zz:qe6c:8111/64            ethernet up   1500  11:22:33:44:55:66
     eth0 (eth0)  fd91:3eea:8968:0:56ee:75ff:fe6e:8784/64 ethernet up   1500  11:22:33:44:55:66
     eth0 (eth0)  qz91:3ena::277/128                      ethernet up   1500  54:EE:75:6E:87:84
     lo   (lo)    127.0.0.1/8                             loopback up   65536
     lo   (lo)    ::1/128                                 loopback up   65536
     sit0 (sit0)  (none)/0                                other    down 1480
     
     **************************ROUTES**************************
     DST/MASK                                 DEV  METRIC GATEWAY
     192.168.1.0/24                           eth0 202
     0.0.0.0/0                                eth0 202    192.168.0.1
     ::1/128                                  lo   0
     fe80::88ee:75zz:qe6c:8111/64                  eth0 0
     fd91:3eea:8968:0:56ee:75ff:fe6e:8784/64 eth0 0
     fd91:1eea:1111:9:1563:av53:3acd:ac0f/128 eth0 0
     fe80::56ee:75ff:fe6e:8784/128            eth0 0
     fd91:3eea:8968::/64                      eth0 202
     fe80::/64                                eth0 256
     ff00::/8                                 eth0 256

#### Conficker Detection with NMAP
     root@hostname: ~/ # nmap -PN -d -p445 -script=smb-check-vulns script-args=safe=1 IP-RANGES


#### TCP Syn and UDP Scan
     root@hostname: ~/ # nmap -sS -sU -PN 192.168.1.121

#### TCP SYN and UDP scan for all ports (requires root)
     root@hostname: ~/ # nmap -sS -sU -PN -p 1-65535 192.168.1.121

#### TCP Window Scan

     root@hostname: ~/ # nmap -sW 192.168.1.121

#### TCP Maimon Scan
     root@hostname: ~/ # nmap -sM 192.168.1.121

#### SCTP COOKIE ECHO Scan
     root@hostname: ~/ # nmap --sZ 192.168.1.121

#### Attack a target with a zombie host
     root@hostname: ~/ # nmap -sI Zombie:113 -Pn -p20-80,110-180 -r -packet-trace -v 192.168.1.121

#### FTP Bounce Scan

     root@hostname: ~/ # nmap -T0 -b username:password@ftpserver.tld:21 victim.tld 192.168.1.121

#### Fragmentation
###### Nmap will split into small small packets for bypassing firewall. This technique is very old, still it will work if there is a misconfiguration of firewall.
     root@hostname: ~/ # nmap -f host

#### Decoy scan:
###### Here Nmap will generate random 10 IPs and it will scan the target using 10 IP and source.
     root@hostname: ~/ # nmap -D RND:10 TARGET

#### Here decoys are specified by the attacker.
     root@hostname: ~/ # nmap -D decoy1,decoy2,decoy3 192.168.1.121

#### Randomize Target Scan Order:
###### The The -randomize-hosts option is used to randomize the scanning order of the specified targets. The -randomize-hosts option helps prevent scans of multiple targets from being detected by firewalls and intrusion detection systems.
     root@hostname: ~/ # nmap -randomize-hosts targets

#### Spoof MAC address:
###### Specifically the -spoof-mac option gives you the ability to choose a MAC address from a specific vendor, 
     root@hostname: ~/ # nmap -sT -PN -spoof-mac aa:bb:cc:dd:ee:ff192.168.1.121

#### SSL Post-processor Scan
     root@hostname: ~/ # nmap -Pn -sSV -T4 -F 192.168.1.121

#### HTTP User Agent:
     root@hostname: ~/ nmap -p80 -script http-methods -script-args http.useragent=”Mozilla 5″ 192.168.1.121

#### HTTP pipelining
     root@hostname: ~/ nmap -p80 -script http-methods -script-args http.pipeline=25 192.168.1.121

#### HTTP-Proxy scanning with Nmap:
     root@hostname: ~/ nmap -script http-open-proxy -p8080 192.168.1.12

#### Different pattern:
###### We may use a different pattern by a specified URL to target for scanning. It can be done by a specified NSE Script. Follow the below command:
     root@hostname: ~/  nmap -script http-open-proxy -script-args http-open-proxy.url=http://whatsmyip.org,http-open-.pattern=”Your IP address is” -p8080 192.168.1.12

#### Discovering interesting files and directories on admin accounts:
     root@hostname: ~/ nmap -script http-enum -p80 192.168.1.12

#### Discovering LUA scripts
     root@hostname: ~/ nmap --script http-enum http-enum.displayall -p80 — 192.168.1.12

#### Check what http methods is supported:
     root@hostname: ~/ nmap -p80 -script http-methods -script-args http.pipeline=25 192.168.1.1

     PORT   STATE SERVICE
     80/tcp open  http
     | http-methods: 
     |_  Supported Methods: GET HEAD POST
     MAC Address: E1:B0:E1:B2:71:61 (Technicolor)









