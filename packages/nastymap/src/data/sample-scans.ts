/**
 * Sample Nmap XML Scans for testing, demonstration, and offline exploration.
 */

export const ENTERPRISE_NETWORK_XML = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<nmaprun scanner="nmap" args="nmap -sS -sV -O -A --traceroute -T4 -p 21,22,23,53,80,88,139,389,443,445,3306,3389,5432,8080,9100 10.0.0.0/20 192.168.1.0/24" start="1779124000" startstr="Tue Aug 18 16:00:00 2026" version="7.94" xmloutputversion="1.05">
<scaninfo type="syn" protocol="tcp" numservices="15" services="21,22,23,53,80,88,139,389,443,445,3306,3389,5432,8080,9100"/>
<verbose level="1"/>
<debugging level="0"/>

<!-- 1. Gateway Firewall -->
<host starttime="1779124001" endtime="1779124005">
  <status state="up" reason="arp-response" reason_ttl="0"/>
  <address addr="192.168.1.1" addrtype="ipv4" vendor="Netgate"/>
  <address addr="00:08:A2:0E:12:34" addrtype="mac" vendor="Netgate pfSense"/>
  <hostnames>
    <hostname name="pfsense-gateway.corp.local" type="PTR"/>
  </hostnames>
  <ports>
    <port protocol="tcp" portid="22"><state state="open" reason="syn-ack"/><service name="ssh" product="OpenSSH" version="9.3" extrainfo="FreeBSD; protocol 2.0" method="probed" conf="10"><cpe>cpe:/a:openbsd:openssh:9.3</cpe><cpe>cpe:/o:freebsd:freebsd</cpe></service></port>
    <port protocol="tcp" portid="80"><state state="open" reason="syn-ack"/><service name="http" product="nginx" version="1.24.0" method="probed" conf="10"/></port>
    <port protocol="tcp" portid="443"><state state="open" reason="syn-ack"/><service name="https" product="nginx" version="1.24.0" tunnel="ssl" method="probed" conf="10"/><script id="ssl-cert" output="Subject: commonName=pfsense-gateway.corp.local&#xa;Issuer: Corp Internal CA"/></port>
    <port protocol="tcp" portid="53"><state state="open" reason="syn-ack"/><service name="domain" product="Unbound" version="1.19.0" method="probed" conf="10"/></port>
  </ports>
  <os>
    <portused state="open" proto="tcp" portid="22"/>
    <osmatch name="FreeBSD 14.0-RELEASE" accuracy="98" line="12340">
      <osclass type="firewall" vendor="FreeBSD" osfamily="FreeBSD" osgen="14.X" accuracy="98"><cpe>cpe:/o:freebsd:freebsd:14</cpe></osclass>
    </osmatch>
  </os>
  <distance value="1"/>
  <trace port="443" proto="tcp">
    <hop ttl="1" ipaddr="192.168.1.1" rtt="0.42" host="pfsense-gateway.corp.local"/>
  </trace>
  <uptime seconds="3456000" lastboot="Thu Jul 9 08:00:00 2026"/>
  <times srtt="420" rttvar="150" to="100000"/>
</host>

<!-- 2. Core Backbone Router -->
<host starttime="1779124002" endtime="1779124006">
  <status state="up" reason="syn-ack" reason_ttl="254"/>
  <address addr="10.0.0.1" addrtype="ipv4" vendor="Cisco Systems"/>
  <hostnames>
    <hostname name="core-sw-01.corp.local" type="PTR"/>
  </hostnames>
  <ports>
    <port protocol="tcp" portid="22"><state state="open" reason="syn-ack"/><service name="ssh" product="Cisco SSH" version="1.25" extrainfo="Cisco IOS; protocol 2.0" method="probed" conf="10"/></port>
    <port protocol="tcp" portid="443"><state state="open" reason="syn-ack"/><service name="https" product="Cisco IOS HTTP server" method="probed" conf="10"/></port>
  </ports>
  <os>
    <osmatch name="Cisco IOS 15.6 - 15.9 (Catalyst 9300)" accuracy="99">
      <osclass type="router" vendor="Cisco" osfamily="IOS" osgen="15.X" accuracy="99"><cpe>cpe:/o:cisco:ios:15</cpe></osclass>
    </osmatch>
  </os>
  <distance value="2"/>
  <trace port="22" proto="tcp">
    <hop ttl="1" ipaddr="192.168.1.1" rtt="0.45" host="pfsense-gateway.corp.local"/>
    <hop ttl="2" ipaddr="10.0.0.1" rtt="1.15" host="core-sw-01.corp.local"/>
  </trace>
  <uptime seconds="12500000" lastboot="Mon Mar 23 10:00:00 2026"/>
  <times srtt="1150" rttvar="320" to="100000"/>
</host>

<!-- 3. Primary Domain Controller (Windows Server 2022) -->
<host starttime="1779124003" endtime="1779124008">
  <status state="up" reason="syn-ack" reason_ttl="126"/>
  <address addr="10.0.10.10" addrtype="ipv4"/>
  <hostnames>
    <hostname name="DC01.corp.local" type="PTR"/>
    <hostname name="CORP-DC01" type="user"/>
  </hostnames>
  <ports>
    <port protocol="tcp" portid="53"><state state="open" reason="syn-ack"/><service name="domain" product="Microsoft DNS" version="6.0.3905" method="probed" conf="10"/></port>
    <port protocol="tcp" portid="88"><state state="open" reason="syn-ack"/><service name="kerberos-sec" product="Microsoft Windows Kerberos" method="probed" conf="10"/></port>
    <port protocol="tcp" portid="139"><state state="open" reason="syn-ack"/><service name="netbios-ssn" product="Microsoft Windows NetBIOS" method="probed" conf="10"/></port>
    <port protocol="tcp" portid="389"><state state="open" reason="syn-ack"/><service name="ldap" product="Microsoft Windows Active Directory LDAP" method="probed" conf="10"/></port>
    <port protocol="tcp" portid="445"><state state="open" reason="syn-ack"/><service name="microsoft-ds" product="Windows Server 2022 Datacenter 20348 microsoft-ds" method="probed" conf="10"/></port>
    <port protocol="tcp" portid="3389"><state state="open" reason="syn-ack"/><service name="ms-wbt-server" product="Microsoft Terminal Services" method="probed" conf="10"/><script id="rdp-ntlm-info" output="Target_Name: CORP&#xa;NetBIOS_Domain_Name: CORP&#xa;NetBIOS_Computer_Name: DC01"/></port>
  </ports>
  <os>
    <osmatch name="Microsoft Windows Server 2022" accuracy="100">
      <osclass type="general purpose" vendor="Microsoft" osfamily="Windows" osgen="2022" accuracy="100"><cpe>cpe:/o:microsoft:windows_server_2022</cpe></osclass>
    </osmatch>
  </os>
  <distance value="3"/>
  <trace port="445" proto="tcp">
    <hop ttl="1" ipaddr="192.168.1.1" rtt="0.52" host="pfsense-gateway.corp.local"/>
    <hop ttl="2" ipaddr="10.0.0.1" rtt="1.20" host="core-sw-01.corp.local"/>
    <hop ttl="3" ipaddr="10.0.10.10" rtt="1.85" host="DC01.corp.local"/>
  </trace>
  <uptime seconds="543210" lastboot="Mon Aug 12 12:00:00 2026"/>
  <times srtt="1850" rttvar="410" to="100000"/>
</host>

<!-- 4. Linux Production Web & App Server -->
<host starttime="1779124004" endtime="1779124009">
  <status state="up" reason="syn-ack" reason_ttl="62"/>
  <address addr="10.0.10.20" addrtype="ipv4"/>
  <hostnames>
    <hostname name="web-prod-01.corp.local" type="PTR"/>
  </hostnames>
  <ports>
    <port protocol="tcp" portid="22"><state state="open" reason="syn-ack"/><service name="ssh" product="OpenSSH" version="9.6p1 Ubuntu 3ubuntu13" extrainfo="Ubuntu Linux; protocol 2.0" method="probed" conf="10"/></port>
    <port protocol="tcp" portid="80"><state state="open" reason="syn-ack"/><service name="http" product="Apache httpd" version="2.4.58" extrainfo="(Ubuntu)" method="probed" conf="10"/><script id="http-title" output="Enterprise Portal Login"/></port>
    <port protocol="tcp" portid="443"><state state="open" reason="syn-ack"/><service name="https" product="Apache httpd" version="2.4.58" tunnel="ssl" method="probed" conf="10"/></port>
    <port protocol="tcp" portid="8080"><state state="open" reason="syn-ack"/><service name="http-proxy" product="Node.js Express App" version="20.11" method="probed" conf="10"/></port>
  </ports>
  <os>
    <osmatch name="Linux 6.2 - 6.8 (Ubuntu 24.04 LTS)" accuracy="99">
      <osclass type="general purpose" vendor="Linux" osfamily="Linux" osgen="6.X" accuracy="99"><cpe>cpe:/o:linux:linux_kernel:6</cpe></osclass>
    </osmatch>
  </os>
  <distance value="3"/>
  <trace port="80" proto="tcp">
    <hop ttl="1" ipaddr="192.168.1.1" rtt="0.48" host="pfsense-gateway.corp.local"/>
    <hop ttl="2" ipaddr="10.0.0.1" rtt="1.18" host="core-sw-01.corp.local"/>
    <hop ttl="3" ipaddr="10.0.10.20" rtt="1.72" host="web-prod-01.corp.local"/>
  </trace>
  <uptime seconds="1987654" lastboot="Sat Jul 25 15:30:00 2026"/>
  <times srtt="1720" rttvar="280" to="100000"/>
</host>

<!-- 5. PostgreSQL Database Cluster -->
<host starttime="1779124005" endtime="1779124010">
  <status state="up" reason="syn-ack" reason_ttl="62"/>
  <address addr="10.0.10.30" addrtype="ipv4"/>
  <hostnames>
    <hostname name="db-cluster-primary.corp.local" type="PTR"/>
  </hostnames>
  <ports>
    <port protocol="tcp" portid="22"><state state="open" reason="syn-ack"/><service name="ssh" product="OpenSSH" version="9.6p1" method="probed" conf="10"/></port>
    <port protocol="tcp" portid="5432"><state state="open" reason="syn-ack"/><service name="postgresql" product="PostgreSQL DB" version="16.2" method="probed" conf="10"/></port>
  </ports>
  <os>
    <osmatch name="Linux 6.5 (Debian 12 Bookworm)" accuracy="97">
      <osclass type="general purpose" vendor="Linux" osfamily="Linux" osgen="6.X" accuracy="97"><cpe>cpe:/o:linux:linux_kernel:6</cpe></osclass>
    </osmatch>
  </os>
  <distance value="3"/>
  <trace port="5432" proto="tcp">
    <hop ttl="1" ipaddr="192.168.1.1" rtt="0.50" host="pfsense-gateway.corp.local"/>
    <hop ttl="2" ipaddr="10.0.0.1" rtt="1.22" host="core-sw-01.corp.local"/>
    <hop ttl="3" ipaddr="10.0.10.30" rtt="1.65" host="db-cluster-primary.corp.local"/>
  </trace>
  <times srtt="1650" rttvar="310" to="100000"/>
</host>

<!-- 6. Developer macOS Workstation -->
<host starttime="1779124006" endtime="1779124011">
  <status state="up" reason="syn-ack" reason_ttl="62"/>
  <address addr="10.0.20.105" addrtype="ipv4" vendor="Apple Inc."/>
  <hostnames>
    <hostname name="macbook-pro-alex.corp.local" type="PTR"/>
  </hostnames>
  <ports>
    <port protocol="tcp" portid="22"><state state="open" reason="syn-ack"/><service name="ssh" product="OpenSSH" version="9.4" extrainfo="Apple_SecureTransport" method="probed" conf="10"/></port>
    <port protocol="tcp" portid="8080"><state state="open" reason="syn-ack"/><service name="http" product="Vite Dev Server" version="5.1.4" method="probed" conf="8"/></port>
  </ports>
  <os>
    <osmatch name="Apple macOS Sonoma 14.4 (Darwin 23.4)" accuracy="96">
      <osclass type="general purpose" vendor="Apple" osfamily="macOS" osgen="14.X" accuracy="96"><cpe>cpe:/o:apple:macos:14</cpe></osclass>
    </osmatch>
  </os>
  <distance value="3"/>
  <trace port="22" proto="tcp">
    <hop ttl="1" ipaddr="192.168.1.1" rtt="0.49" host="pfsense-gateway.corp.local"/>
    <hop ttl="2" ipaddr="10.0.0.1" rtt="1.21" host="core-sw-01.corp.local"/>
    <hop ttl="3" ipaddr="10.0.20.105" rtt="2.95" host="macbook-pro-alex.corp.local"/>
  </trace>
  <times srtt="2950" rttvar="540" to="100000"/>
</host>

<!-- 7. Finance Department Windows 11 PC -->
<host starttime="1779124007" endtime="1779124012">
  <status state="up" reason="syn-ack" reason_ttl="126"/>
  <address addr="10.0.20.142" addrtype="ipv4" vendor="Dell Inc."/>
  <hostnames>
    <hostname name="FIN-W11-042.corp.local" type="PTR"/>
  </hostnames>
  <ports>
    <port protocol="tcp" portid="139"><state state="open" reason="syn-ack"/><service name="netbios-ssn" product="Microsoft Windows" method="probed" conf="10"/></port>
    <port protocol="tcp" portid="445"><state state="open" reason="syn-ack"/><service name="microsoft-ds" product="Windows 11 Enterprise" method="probed" conf="10"/></port>
    <port protocol="tcp" portid="3389"><state state="open" reason="syn-ack"/><service name="ms-wbt-server" product="Microsoft Terminal Services" method="probed" conf="10"/></port>
  </ports>
  <os>
    <osmatch name="Microsoft Windows 11 23H2" accuracy="95">
      <osclass type="general purpose" vendor="Microsoft" osfamily="Windows" osgen="11" accuracy="95"><cpe>cpe:/o:microsoft:windows_11</cpe></osclass>
    </osmatch>
  </os>
  <distance value="3"/>
  <trace port="445" proto="tcp">
    <hop ttl="1" ipaddr="192.168.1.1" rtt="0.48" host="pfsense-gateway.corp.local"/>
    <hop ttl="2" ipaddr="10.0.0.1" rtt="1.24" host="core-sw-01.corp.local"/>
    <hop ttl="3" ipaddr="10.0.20.142" rtt="3.12" host="FIN-W11-042.corp.local"/>
  </trace>
  <times srtt="3120" rttvar="620" to="100000"/>
</host>

<!-- 8. Office Network Printer (HP LaserJet) -->
<host starttime="1779124008" endtime="1779124013">
  <status state="up" reason="syn-ack" reason_ttl="62"/>
  <address addr="10.0.30.50" addrtype="ipv4" vendor="Hewlett-Packard"/>
  <hostnames>
    <hostname name="hp-laserjet-fl2.corp.local" type="PTR"/>
  </hostnames>
  <ports>
    <port protocol="tcp" portid="80"><state state="open" reason="syn-ack"/><service name="http" product="HP Embedded Web Server" version="2.4" method="probed" conf="10"/></port>
    <port protocol="tcp" portid="443"><state state="open" reason="syn-ack"/><service name="https" product="HP EWS SSL" tunnel="ssl" method="probed" conf="10"/></port>
    <port protocol="tcp" portid="9100"><state state="open" reason="syn-ack"/><service name="jetdirect" product="HP JetDirect RAW Print" method="probed" conf="10"/></port>
  </ports>
  <os>
    <osmatch name="HP LaserJet Enterprise MFP" accuracy="94">
      <osclass type="printer" vendor="HP" osfamily="embedded" accuracy="94"><cpe>cpe:/h:hp:laserjet</cpe></osclass>
    </osmatch>
  </os>
  <distance value="3"/>
  <trace port="9100" proto="tcp">
    <hop ttl="1" ipaddr="192.168.1.1" rtt="0.48" host="pfsense-gateway.corp.local"/>
    <hop ttl="2" ipaddr="10.0.0.1" rtt="1.22" host="core-sw-01.corp.local"/>
    <hop ttl="3" ipaddr="10.0.30.50" rtt="4.10" host="hp-laserjet-fl2.corp.local"/>
  </trace>
  <times srtt="4100" rttvar="800" to="100000"/>
</host>

<runstats>
  <finished time="1779124020" timestr="Tue Aug 18 16:00:20 2026" elapsed="20.45" summary="Nmap done at Tue Aug 18 16:00:20 2026; 8 IP addresses (8 hosts up) scanned in 20.45 seconds" exit="success"/>
  <hosts up="8" down="0" total="8"/>
</runstats>
</nmaprun>`;

export const GLOBAL_PERIMETER_XML = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<nmaprun scanner="nmap" args="nmap -sS -sV -O -A --traceroute -T4 1.1.1.1 8.8.8.8 45.33.32.156 52.95.110.1 20.108.12.4 138.201.55.2 133.242.18.9 103.28.248.1" start="1779125000" startstr="Tue Aug 18 16:15:00 2026" version="7.94" xmloutputversion="1.05">
<scaninfo type="syn" protocol="tcp" numservices="8" services="22,53,80,443,853,3389,8080,8443"/>
<verbose level="1"/>
<debugging level="0"/>

<!-- 1. Cloudflare Public DNS (Sydney/Global Anycast) -->
<host starttime="1779125001" endtime="1779125005">
  <status state="up" reason="syn-ack" reason_ttl="58"/>
  <address addr="1.1.1.1" addrtype="ipv4"/>
  <hostnames>
    <hostname name="one.one.one.one" type="PTR"/>
  </hostnames>
  <ports>
    <port protocol="tcp" portid="53"><state state="open" reason="syn-ack"/><service name="domain" product="Cloudflare DNS" method="probed" conf="10"/></port>
    <port protocol="tcp" portid="80"><state state="open" reason="syn-ack"/><service name="http" product="cloudflare" method="probed" conf="10"/></port>
    <port protocol="tcp" portid="443"><state state="open" reason="syn-ack"/><service name="https" product="cloudflare" tunnel="ssl" method="probed" conf="10"/></port>
    <port protocol="tcp" portid="853"><state state="open" reason="syn-ack"/><service name="domain-s" product="DNS-over-TLS" method="probed" conf="10"/></port>
  </ports>
  <os>
    <osmatch name="Linux 5.15 - 6.1 (Cloudflare Edge OS)" accuracy="97">
      <osclass type="load balancer" vendor="Linux" osfamily="Linux" osgen="5.X" accuracy="97"/>
    </osmatch>
  </os>
  <distance value="4"/>
  <trace port="443" proto="tcp">
    <hop ttl="1" ipaddr="192.168.1.1" rtt="0.65" host="local-gw"/>
    <hop ttl="2" ipaddr="96.120.10.1" rtt="8.12" host="isp-edge-gw.com"/>
    <hop ttl="3" ipaddr="172.70.0.1" rtt="14.30" host="cloudflare-peering.net"/>
    <hop ttl="4" ipaddr="1.1.1.1" rtt="15.80" host="one.one.one.one"/>
  </trace>
  <times srtt="15800" rttvar="2100" to="100000"/>
</host>

<!-- 2. Google Public DNS (Mountain View, CA) -->
<host starttime="1779125002" endtime="1779125006">
  <status state="up" reason="syn-ack" reason_ttl="59"/>
  <address addr="8.8.8.8" addrtype="ipv4"/>
  <hostnames>
    <hostname name="dns.google" type="PTR"/>
  </hostnames>
  <ports>
    <port protocol="tcp" portid="53"><state state="open" reason="syn-ack"/><service name="domain" product="Google DNS" method="probed" conf="10"/></port>
    <port protocol="tcp" portid="443"><state state="open" reason="syn-ack"/><service name="https" product="Google HTTPS" tunnel="ssl" method="probed" conf="10"/></port>
    <port protocol="tcp" portid="853"><state state="open" reason="syn-ack"/><service name="domain-s" product="DNS-over-TLS" method="probed" conf="10"/></port>
  </ports>
  <os>
    <osmatch name="Linux 5.10 (Google Borg OS)" accuracy="98">
      <osclass type="general purpose" vendor="Linux" osfamily="Linux" accuracy="98"/>
    </osmatch>
  </os>
  <distance value="4"/>
  <trace port="53" proto="tcp">
    <hop ttl="1" ipaddr="192.168.1.1" rtt="0.68" host="local-gw"/>
    <hop ttl="2" ipaddr="96.120.10.1" rtt="8.25" host="isp-edge-gw.com"/>
    <hop ttl="3" ipaddr="108.170.245.1" rtt="18.90" host="google-core-backbone.net"/>
    <hop ttl="4" ipaddr="8.8.8.8" rtt="21.40" host="dns.google"/>
  </trace>
  <times srtt="21400" rttvar="1800" to="100000"/>
</host>

<!-- 3. Nmap Project Official Scanme (Fremont, CA) -->
<host starttime="1779125003" endtime="1779125007">
  <status state="up" reason="syn-ack" reason_ttl="53"/>
  <address addr="45.33.32.156" addrtype="ipv4"/>
  <hostnames>
    <hostname name="scanme.nmap.org" type="PTR"/>
  </hostnames>
  <ports>
    <port protocol="tcp" portid="22"><state state="open" reason="syn-ack"/><service name="ssh" product="OpenSSH" version="8.2p1 Ubuntu 4ubuntu0.9" extrainfo="Ubuntu Linux; protocol 2.0" method="probed" conf="10"/></port>
    <port protocol="tcp" portid="80"><state state="open" reason="syn-ack"/><service name="http" product="Apache httpd" version="2.4.41" extrainfo="(Ubuntu)" method="probed" conf="10"/><script id="http-title" output="Go ahead and ScanMe!"/></port>
    <port protocol="tcp" portid="8080"><state state="open" reason="syn-ack"/><service name="http" product="Apache" version="2.4.41" method="probed" conf="10"/></port>
  </ports>
  <os>
    <osmatch name="Linux 5.4 (Ubuntu 20.04)" accuracy="95">
      <osclass type="general purpose" vendor="Linux" osfamily="Linux" osgen="5.X" accuracy="95"/>
    </osmatch>
  </os>
  <distance value="5"/>
  <trace port="80" proto="tcp">
    <hop ttl="1" ipaddr="192.168.1.1" rtt="0.70" host="local-gw"/>
    <hop ttl="2" ipaddr="96.120.10.1" rtt="8.30" host="isp-edge-gw.com"/>
    <hop ttl="3" ipaddr="68.86.90.1" rtt="22.10" host="linode-fremont.net"/>
    <hop ttl="4" ipaddr="173.230.159.1" rtt="35.60" host="linode-core-router"/>
    <hop ttl="5" ipaddr="45.33.32.156" rtt="38.90" host="scanme.nmap.org"/>
  </trace>
  <times srtt="38900" rttvar="4200" to="100000"/>
</host>

<!-- 4. Amazon AWS US East (Ashburn, VA) -->
<host starttime="1779125004" endtime="1779125008">
  <status state="up" reason="syn-ack" reason_ttl="49"/>
  <address addr="52.95.110.1" addrtype="ipv4"/>
  <hostnames>
    <hostname name="aws-us-east-1.amazon.com" type="PTR"/>
  </hostnames>
  <ports>
    <port protocol="tcp" portid="80"><state state="open" reason="syn-ack"/><service name="http" product="Amazon CloudFront" method="probed" conf="10"/></port>
    <port protocol="tcp" portid="443"><state state="open" reason="syn-ack"/><service name="https" product="Amazon CloudFront" tunnel="ssl" method="probed" conf="10"/></port>
  </ports>
  <os>
    <osmatch name="Amazon Linux 2023" accuracy="94">
      <osclass type="general purpose" vendor="Amazon" osfamily="Linux" accuracy="94"/>
    </osmatch>
  </os>
  <distance value="5"/>
  <trace port="443" proto="tcp">
    <hop ttl="1" ipaddr="192.168.1.1" rtt="0.66" host="local-gw"/>
    <hop ttl="2" ipaddr="96.120.10.1" rtt="8.15" host="isp-edge-gw.com"/>
    <hop ttl="3" ipaddr="52.93.28.1" rtt="28.40" host="aws-transit.net"/>
    <hop ttl="4" ipaddr="52.95.1.1" rtt="42.50" host="aws-iad-edge.net"/>
    <hop ttl="5" ipaddr="52.95.110.1" rtt="48.10" host="aws-us-east-1.amazon.com"/>
  </trace>
  <times srtt="48100" rttvar="3900" to="100000"/>
</host>

<!-- 5. Microsoft Azure Europe (Dublin, Ireland) -->
<host starttime="1779125005" endtime="1779125009">
  <status state="up" reason="syn-ack" reason_ttl="47"/>
  <address addr="20.108.12.4" addrtype="ipv4"/>
  <hostnames>
    <hostname name="azure-eu-west.cloudapp.azure.com" type="PTR"/>
  </hostnames>
  <ports>
    <port protocol="tcp" portid="80"><state state="open" reason="syn-ack"/><service name="http" product="Microsoft-HTTPAPI/2.0" method="probed" conf="10"/></port>
    <port protocol="tcp" portid="443"><state state="open" reason="syn-ack"/><service name="https" product="Microsoft IIS" version="10.0" tunnel="ssl" method="probed" conf="10"/></port>
  </ports>
  <os>
    <osmatch name="Microsoft Windows Server 2022 (Azure VM)" accuracy="96">
      <osclass type="general purpose" vendor="Microsoft" osfamily="Windows" accuracy="96"/>
    </osmatch>
  </os>
  <distance value="6"/>
  <trace port="443" proto="tcp">
    <hop ttl="1" ipaddr="192.168.1.1" rtt="0.67" host="local-gw"/>
    <hop ttl="2" ipaddr="96.120.10.1" rtt="8.10" host="isp-edge-gw.com"/>
    <hop ttl="3" ipaddr="64.125.12.1" rtt="35.40" host="transatlantic-cable-lon.net"/>
    <hop ttl="4" ipaddr="104.44.10.1" rtt="85.20" host="msft-dublin-edge.net"/>
    <hop ttl="5" ipaddr="104.44.20.1" rtt="92.40" host="azure-core-router"/>
    <hop ttl="6" ipaddr="20.108.12.4" rtt="96.50" host="azure-eu-west.cloudapp.azure.com"/>
  </trace>
  <times srtt="96500" rttvar="8200" to="100000"/>
</host>

<!-- 6. Hetzner Datacenter (Nuremberg, Germany) -->
<host starttime="1779125006" endtime="1779125010">
  <status state="up" reason="syn-ack" reason_ttl="48"/>
  <address addr="138.201.55.2" addrtype="ipv4"/>
  <hostnames>
    <hostname name="static.55.201.138.clients.your-server.de" type="PTR"/>
  </hostnames>
  <ports>
    <port protocol="tcp" portid="22"><state state="open" reason="syn-ack"/><service name="ssh" product="OpenSSH" version="9.2p1 Debian 2+deb12u2" method="probed" conf="10"/></port>
    <port protocol="tcp" portid="80"><state state="open" reason="syn-ack"/><service name="http" product="nginx" version="1.22.1" method="probed" conf="10"/></port>
    <port protocol="tcp" portid="443"><state state="open" reason="syn-ack"/><service name="https" product="nginx" version="1.22.1" tunnel="ssl" method="probed" conf="10"/></port>
  </ports>
  <os>
    <osmatch name="Linux 6.1 (Debian 12 Bookworm)" accuracy="98">
      <osclass type="general purpose" vendor="Linux" osfamily="Linux" osgen="6.X" accuracy="98"/>
    </osmatch>
  </os>
  <distance value="6"/>
  <trace port="22" proto="tcp">
    <hop ttl="1" ipaddr="192.168.1.1" rtt="0.65" host="local-gw"/>
    <hop ttl="2" ipaddr="96.120.10.1" rtt="8.20" host="isp-edge-gw.com"/>
    <hop ttl="3" ipaddr="80.249.208.1" rtt="42.80" host="ams-ix.hetzner.com"/>
    <hop ttl="4" ipaddr="213.239.245.1" rtt="102.30" host="core-nbg1.hetzner.com"/>
    <hop ttl="5" ipaddr="213.239.224.1" rtt="108.50" host="spine-nbg1.hetzner.com"/>
    <hop ttl="6" ipaddr="138.201.55.2" rtt="112.40" host="static.55.201.138.clients.your-server.de"/>
  </trace>
  <times srtt="112400" rttvar="9100" to="100000"/>
</host>

<!-- 7. SAKURA Internet Server (Tokyo, Japan) -->
<host starttime="1779125007" endtime="1779125011">
  <status state="up" reason="syn-ack" reason_ttl="44"/>
  <address addr="133.242.18.9" addrtype="ipv4"/>
  <hostnames>
    <hostname name="tokyo-node-01.sakura.ne.jp" type="PTR"/>
  </hostnames>
  <ports>
    <port protocol="tcp" portid="22"><state state="open" reason="syn-ack"/><service name="ssh" product="OpenSSH" version="8.7p1" extrainfo="Red Hat Enterprise Linux" method="probed" conf="10"/></port>
    <port protocol="tcp" portid="80"><state state="open" reason="syn-ack"/><service name="http" product="Apache httpd" version="2.4.53" method="probed" conf="10"/></port>
    <port protocol="tcp" portid="443"><state state="open" reason="syn-ack"/><service name="https" product="Apache httpd" version="2.4.53" tunnel="ssl" method="probed" conf="10"/></port>
  </ports>
  <os>
    <osmatch name="Red Hat Enterprise Linux 9.2 (RHEL 9)" accuracy="97">
      <osclass type="general purpose" vendor="Red Hat" osfamily="Linux" osgen="9.X" accuracy="97"/>
    </osmatch>
  </os>
  <distance value="7"/>
  <trace port="443" proto="tcp">
    <hop ttl="1" ipaddr="192.168.1.1" rtt="0.68" host="local-gw"/>
    <hop ttl="2" ipaddr="96.120.10.1" rtt="8.15" host="isp-edge-gw.com"/>
    <hop ttl="3" ipaddr="206.223.119.1" rtt="28.90" host="equinix-sjc.sakura.ad.jp"/>
    <hop ttl="4" ipaddr="157.17.130.1" rtt="125.40" host="transpacific-tyo.net"/>
    <hop ttl="5" ipaddr="133.242.0.1" rtt="138.20" host="sakura-core-tyo"/>
    <hop ttl="6" ipaddr="133.242.1.1" rtt="142.10" host="sakura-dist-tyo"/>
    <hop ttl="7" ipaddr="133.242.18.9" rtt="146.50" host="tokyo-node-01.sakura.ne.jp"/>
  </trace>
  <times srtt="146500" rttvar="11200" to="100000"/>
</host>

<!-- 8. Singtel Gateway (Singapore) -->
<host starttime="1779125008" endtime="1779125012">
  <status state="up" reason="syn-ack" reason_ttl="43"/>
  <address addr="103.28.248.1" addrtype="ipv4"/>
  <hostnames>
    <hostname name="sg-core-gw01.singtel.com" type="PTR"/>
  </hostnames>
  <ports>
    <port protocol="tcp" portid="80"><state state="open" reason="syn-ack"/><service name="http" product="nginx" version="1.24.0" method="probed" conf="10"/></port>
    <port protocol="tcp" portid="443"><state state="open" reason="syn-ack"/><service name="https" product="nginx" version="1.24.0" tunnel="ssl" method="probed" conf="10"/></port>
  </ports>
  <os>
    <osmatch name="Cisco IOS XR 7.5 (ASR 9000)" accuracy="98">
      <osclass type="router" vendor="Cisco" osfamily="IOS" accuracy="98"/>
    </osmatch>
  </os>
  <distance value="7"/>
  <trace port="443" proto="tcp">
    <hop ttl="1" ipaddr="192.168.1.1" rtt="0.64" host="local-gw"/>
    <hop ttl="2" ipaddr="96.120.10.1" rtt="8.10" host="isp-edge-gw.com"/>
    <hop ttl="3" ipaddr="206.223.119.1" rtt="29.10" host="equinix-sjc.singtel.net"/>
    <hop ttl="4" ipaddr="180.87.12.1" rtt="155.30" host="singtel-submarine-sin"/>
    <hop ttl="5" ipaddr="203.208.150.1" rtt="172.60" host="sin-core-bb01.singtel.com"/>
    <hop ttl="6" ipaddr="203.208.170.1" rtt="178.40" host="sin-dist-bb02.singtel.com"/>
    <hop ttl="7" ipaddr="103.28.248.1" rtt="182.30" host="sg-core-gw01.singtel.com"/>
  </trace>
  <times srtt="182300" rttvar="12400" to="100000"/>
</host>

<runstats>
  <finished time="1779125025" timestr="Tue Aug 18 16:15:25 2026" elapsed="25.10" summary="Nmap done at Tue Aug 18 16:15:25 2026; 8 IP addresses (8 hosts up) scanned in 25.10 seconds" exit="success"/>
  <hosts up="8" down="0" total="8"/>
</runstats>
</nmaprun>`;

export const SECURITY_BREACH_BEFORE_XML = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<nmaprun scanner="nmap" args="nmap -sS -sV -O 10.0.10.0/24" start="1779037200" startstr="Mon Aug 17 16:00:00 2026" version="7.94" xmloutputversion="1.05">
<verbose level="1"/>
<host>
  <status state="up"/>
  <address addr="10.0.10.1" addrtype="ipv4"/>
  <hostnames><hostname name="router-gw.corp.local" type="PTR"/></hostnames>
  <ports>
    <port protocol="tcp" portid="22"><state state="open"/><service name="ssh" product="OpenSSH" version="9.0"/></port>
    <port protocol="tcp" portid="443"><state state="open"/><service name="https" product="nginx" version="1.22.0"/></port>
  </ports>
  <os><osmatch name="Cisco IOS 15.6" accuracy="98"/></os>
  <times srtt="1200"/>
</host>
<host>
  <status state="up"/>
  <address addr="10.0.10.10" addrtype="ipv4"/>
  <hostnames><hostname name="auth-server.corp.local" type="PTR"/></hostnames>
  <ports>
    <port protocol="tcp" portid="88"><state state="open"/><service name="kerberos-sec" product="Microsoft Kerberos"/></port>
    <port protocol="tcp" portid="389"><state state="open"/><service name="ldap" product="Microsoft Active Directory"/></port>
    <port protocol="tcp" portid="445"><state state="open"/><service name="microsoft-ds" product="Windows Server 2022"/></port>
  </ports>
  <os><osmatch name="Windows Server 2022" accuracy="100"/></os>
  <times srtt="1800"/>
</host>
<host>
  <status state="up"/>
  <address addr="10.0.10.30" addrtype="ipv4"/>
  <hostnames><hostname name="db-cluster.corp.local" type="PTR"/></hostnames>
  <ports>
    <port protocol="tcp" portid="22"><state state="open"/><service name="ssh" product="OpenSSH" version="9.2p1"/></port>
    <port protocol="tcp" portid="5432"><state state="open"/><service name="postgresql" product="PostgreSQL" version="15.4"/></port>
  </ports>
  <os><osmatch name="Debian 12" accuracy="99"/></os>
  <times srtt="1600"/>
</host>
</nmaprun>`;

export const SECURITY_BREACH_AFTER_XML = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<nmaprun scanner="nmap" args="nmap -sS -sV -O 10.0.10.0/24" start="1779124000" startstr="Tue Aug 18 16:00:00 2026" version="7.94" xmloutputversion="1.05">
<verbose level="1"/>
<!-- 1. Router: Unsecured Telnet Port 23 has been re-enabled! -->
<host>
  <status state="up"/>
  <address addr="10.0.10.1" addrtype="ipv4"/>
  <hostnames><hostname name="router-gw.corp.local" type="PTR"/></hostnames>
  <ports>
    <port protocol="tcp" portid="22"><state state="open"/><service name="ssh" product="OpenSSH" version="9.0"/></port>
    <port protocol="tcp" portid="23"><state state="open"/><service name="telnet" product="Cisco Telnetd" extrainfo="CRITICAL: Unencrypted login enabled!"/></port>
    <port protocol="tcp" portid="443"><state state="open"/><service name="https" product="nginx" version="1.22.0"/></port>
  </ports>
  <os><osmatch name="Cisco IOS 15.6" accuracy="98"/></os>
  <times srtt="1200"/>
</host>

<!-- 2. Auth Server: Unchanged -->
<host>
  <status state="up"/>
  <address addr="10.0.10.10" addrtype="ipv4"/>
  <hostnames><hostname name="auth-server.corp.local" type="PTR"/></hostnames>
  <ports>
    <port protocol="tcp" portid="88"><state state="open"/><service name="kerberos-sec" product="Microsoft Kerberos"/></port>
    <port protocol="tcp" portid="389"><state state="open"/><service name="ldap" product="Microsoft Active Directory"/></port>
    <port protocol="tcp" portid="445"><state state="open"/><service name="microsoft-ds" product="Windows Server 2022"/></port>
  </ports>
  <os><osmatch name="Windows Server 2022" accuracy="100"/></os>
  <times srtt="1800"/>
</host>

<!-- 3. DB Server: Backdoor Port 4444 (Metasploit reverse shell) detected! -->
<host>
  <status state="up"/>
  <address addr="10.0.10.30" addrtype="ipv4"/>
  <hostnames><hostname name="db-cluster.corp.local" type="PTR"/></hostnames>
  <ports>
    <port protocol="tcp" portid="22"><state state="open"/><service name="ssh" product="OpenSSH" version="9.2p1"/></port>
    <port protocol="tcp" portid="4444"><state state="open"/><service name="meterpreter" product="Metasploit Reverse Shell" extrainfo="ALERT: Active Backdoor"/></port>
    <port protocol="tcp" portid="5432"><state state="open"/><service name="postgresql" product="PostgreSQL" version="15.4"/></port>
  </ports>
  <os><osmatch name="Debian 12" accuracy="99"/></os>
  <times srtt="1950"/>
</host>

<!-- 4. Rogue Host: Unknown attacker laptop plugged into switch! -->
<host>
  <status state="up"/>
  <address addr="10.0.10.99" addrtype="ipv4" vendor="Raspberry Pi Trading"/>
  <hostnames><hostname name="rogue-pi-implant.corp.local" type="PTR"/></hostnames>
  <ports>
    <port protocol="tcp" portid="22"><state state="open"/><service name="ssh" product="OpenSSH" version="9.4p1"/></port>
    <port protocol="tcp" portid="8080"><state state="open"/><service name="http" product="Cobalt Strike TeamServer C2" extrainfo="CRITICAL MALWARE C2"/></port>
  </ports>
  <os><osmatch name="Kali Linux 2024.1" accuracy="99"/></os>
  <times srtt="3400"/>
</host>
</nmaprun>`;

export const SAMPLE_SCANS = {
  enterprise: {
    id: 'enterprise',
    name: 'Enterprise Multi-Subnet (Traceroute & Mixed OS)',
    description: 'Corporate network with Cisco routers, pfSense firewall, Windows Domain Controller, Linux servers, macOS, and printers with traceroute hops.',
    xml: ENTERPRISE_NETWORK_XML,
  },
  global: {
    id: 'global',
    name: 'Global Perimeter (Public GeoIP World Map)',
    description: 'Worldwide internet infrastructure across USA, Europe, Japan, Singapore, and Australia with international traceroute latency paths.',
    xml: GLOBAL_PERIMETER_XML,
  },
  breachDiff: {
    id: 'breachDiff',
    name: 'Security Breach Diff (Before vs After Incident)',
    description: 'Comparison demonstrating newly opened backdoor port 4444, rogue implant 10.0.10.99, and enabled telnet port 23.',
    xml: SECURITY_BREACH_AFTER_XML,
    xmlA: SECURITY_BREACH_BEFORE_XML,
    xmlB: SECURITY_BREACH_AFTER_XML,
  },
};
