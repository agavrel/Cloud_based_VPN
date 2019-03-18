# Cloud_based_VPN
How to setup a VPN on the cloud


### Digital Ocean Subscription

First you need to create an account on [Digital Ocean](https://m.do.co/c/794f5962b4a6) (referral link) :

You will need to enter your credit card details but will be provided with $100 for 60 days.

* You need to click on "Droplet" and select New,
* Then switch to the cheapest (the one at $5 per month, by default they select the $40 one).
* Select IPv6 in options.
* Select a server close from your home country
* then you will be emailed with login and passwords of your VM cloud-based.

```c++
Droplet Name: {what you entered}
IP Address: XXX.XXX.XXX.XXX
Username: root
Password: {26 hexadecimal digits}
```

> I am not advocating especially in favor of Digital Ocean but they offer a very good service pricewise. Any other Cloud services like AWS or Google Cloud or whatever would do it is up to your choice

### SSH to the Cloud Server

```c++
ssh -v {root id}@{IPv4 of your Droplet}
```
like for example:
```c++
ssh -v root@167.99.66.250
```

### Install ShadowSocks; [Credit](https://mighil.com/how-to-setup-shadowsocks-server-on-digitalocean-vps/)

> Why using ShadowSocks instead of OpenVPN (My original choice) ? Well in fact you can even access Twitch or Netflix and break through the Great Firewall while being in China !  

Once you have logged in to the server/droplet (see SSH to the Cloud Server), run the following command to update the packages:
```c++
apt-get update
```

Now, run the following commands to install Python
```c++
apt-get install python-pip
```

Then Shadowsocks :
```c++
pip install -U git+https://github.com/shadowsocks/shadowsocks.git@master
```

Check this link if any [issue](https://github.com/shadowsocks/shadowsocks/issues/646)  

Now install M2Crypto, which is the most complete Python wrapper for OpenSSL featuring RSA, DSA, DH, EC, HMACs, message digests, symmetric ciphers (including AES). Run the following commands to install M2Crypto:

```c++
apt-get install python-m2crypto
apt-get install build-essential
```

Since salsa20 and chacha20 are fast stream cyphers. Optimized salsa20/chacha20 implementation on x86_64 is even 2x faster than rc4 (but slightly slower on ARM). You must install libsodium to use them:

```c++
wget https://github.com/jedisct1/libsodium/releases/download/1.0.10/libsodium-1.0.10.tar.gz
tar xf libsodium-1.0.10.tar.gz && cd libsodium-1.0.10
./configure && make && make install
ldconfig
```

After finishing up the steps above, we must create a .json file (config file) for Shadowsocks.

```c++
sudo vi /etc/shadowsocks.json
```
containing the following:
```json
{
"server":"{server IPv4 like XXX.XXX.XXX.XXX}",
"server_port":8000,
"local_port":1080,
"password":"{password of your choice}",
"timeout":600,
"method":"{desired encryption method}"
}
```
You can choose any encryption method from [here](http://www.shadowsocks.org/en/spec/Stream-Ciphers.html) like for example:
```json
{
"server":"128.199.180.160",
"server_port":8000,
"local_port":1080,
"password":"gof4st",
"timeout":600,
"method":"aes-128-cfb"
}
```

For multiple users:
```json
{
    "server":"138.68.30.42",
    "port_password": {
        "443": "gof4ster",
        "8000": "gof4ster",
        "8383": "gof4ster",
        "8384": "gof4ster"
    },
    "local_port":1080,
    "timeout":600,
    "method":"chacha20"
}
```

You can choose any encryption method from [here](http://www.shadowsocks.org/en/spec/Stream-Ciphers.html).

> I prefer to use aes-128-cfb to aes-256-cfb since 128 is good enough to be secured so as long as security is not critical you can select 128.

you can then start your shadowsocks server with:
```c++
ssserver -c /etc/shadowsocks.json -d start
```

You can check the Shadowsocks log file, which is located in /var/log/shadowsocks.log to make sure everything is okay.  
```c++
less /var/log/shadowsocks.log
```

Now that you are almost done, we need to make sure Shadowsocks server will be started automatically during system reboots. Edit the file named /etc/rc.local to do so.  

Open up /etc/rc.local
```c++
vi /etc/rc.local
```

and add the following content before the exit 0 line to make sure that everytime the server reboots it starts the shadowsocks server automatically:
```c++
/usr/bin/python /usr/local/bin/ssserver -c /etc/shadowsocks.json -d start
```

> Note: In the future, use this command: “ssserver -c /etc/shadowsocks.json -d stop” to stop the Shadowsocks server. and “ssserver -c /etc/shadowsocks.json -d restart” to restart.

you can retrieve your configuration file using scp command with
```c++
scp {root username}@{IP}:/etc/shadowsocks.json /home/{your local machine username}
```


like for example:
```c++
scp root@159.89.204.125:/etc/shadowsocks.json /home/agavrel
```

you will be prompted to enter your password


Download the client:
https://github.com/shadowsocks/shadowsocks-qt5/releases

To install the client required packages on your personal laptop:
```c++
sudo apt install cmake &&
sudo apt install qtbase5 &&
sudo apt install libqrencode &&
sudo apt install libqtshadowsocks &&
sudo apt install libzbar0 &&
sudo apt install libappindicator1 &&
sudo apt install libsuitesparse-dev &&

```

Install Qt
```c++
sudo apt install qt5-default
```

Install Botan
```c++
sudo apt-get update -y
sudo apt-get install -y botan
```

and the client itself:
```c++
mkdir build && cd build &&
cmake .. -DCMAKE_INSTALL_PREFIX=/usr &&
make -j4 &&
sudo make install
```

---

### Install OpenVPN

conf is located in
```c++
vi /etc/openvpn/server.conf
```

```c++
mkdir openvpn &&
cd openvpn &&
wget https://raw.githubusercontent.com/Nyr/openvpn-install/master/openvpn-install.sh &&
chmod 777 openvpn-install.sh &&
bash openvpn-install.sh
```

The script will ask you a few questions, choose the following:

* IP adress : XXX.XXX.XXX.XXX (let the default one, which is the IP of the Cloud server)
* Which protocol do you want to use : UDP
* Which DNS do you want to use: 1.1.1.1 (cloudflare, [the fastest](https://medium.com/@nykolas.z/dns-resolvers-performance-compared-cloudflare-x-google-x-quad9-x-opendns-149e803734e5))
* Client: vpnconfig


### Pritunl - The VPn Client

This is what you will use to connect to the VPN.

Download the client that suits your OS:
https://client.pritunl.com/

* [For MAC](https://github.com/pritunl/pritunl-client-electron/releases/download/1.0.1953.32/Pritunl.pkg.zip)
* [For Windows](https://github.com/pritunl/pritunl-client-electron/releases/download/1.0.1953.32/Pritunl.exe)  
* [For Android](https://play.google.com/store/apps/details?id=net.openvpn.openvpn)
For Ubuntun 18.04 :
```c++
sudo tee /etc/apt/sources.list.d/pritunl.list << EOF
deb http://repo.pritunl.com/stable/apt bionic main
EOF

sudo apt-key adv --keyserver hkp://keyserver.ubuntu.com --recv 7568D9BB55FF9E5287D586017AE645C0CF8E292A
sudo apt-get update
sudo apt-get install pritunl-client-electron
```

Then open it and select "Import Profile", open the file with ".opvn" extension that you got using Filezilla.


Check current IP of your computer before and after connecting to the Cloud based VPM with (first for IPv4 and second for IPv6) :
```c++
curl https://ipinfo.io/ip &&
curl https://ifconfig.co
```

Finally click in the top right corner of the app (the 3 dash) and select connect. You are now using the VPN !

---

### Miscellaneous commands

##### Check udp ports

```c++
nmap -sUV -T4 -F --version-intensity 0 scanme.nmap.org
```
best should be 123
https://hackertarget.com/nmap-cheatsheet-a-quick-reference-guide/

---

##### Check, edit OpenVPN config and restart the service

```c++
cat /etc/openvpn/server.conf
vi /etc/openvpn/server.conf
systemctl restart openvpn@server.service
```

---

##### Download file from remote server

```c++
scp root@159.89.204.125:client1.ovpn /home/st4ck
```

---

##### Create a Smart DNS Proxy (Netflix, Twitch etc)

SSH to your Droplet (located in the US)

```c++
ssh root@68.183.170.102
```c++

Install docker by either geting the drolet with the image or installing it with wget

https://marketplace.digitalocean.com/apps/docker

```c++
wget -qO- https://get.docker.com/ | sh && chmod 777 sh && ./sh

```

and then run the following script:

```c++
cd /opt && git clone https://github.com/ab77/netflix-proxy.git && cd netflix-proxy && ./build.sh
```


If you want to share your system with friends and family, you can authorise their home IP address(s) using the netflix-proxy admin site, located at http://<ipaddr>:8080/, where ipaddr is the public IP address of your VPS. Login using admin account with the password you recorded during the build. If you've forgotten your admin credentials  
https://github.com/ab77/netflix-proxy/blob/master/README.md

Point your DNS at the Droplet IP and watch Netflix out of region.

Install the resolvconf package.
```c++
sudo apt install resolvconf
```

Edit /etc/resolvconf/resolv.conf.d/head and add the following:
```c++
# Make edits to /etc/resolvconf/resolv.conf.d/head.
nameserver 8.8.4.4
nameserver 8.8.8.8
```

--dn "CN=134.209.60.144" --san "134.209.60.144"

. . .
conn ikev2-vpn
    . . .
    left=%any
    leftid=@134.209.60.144
    leftcert=server-cert.pem
    leftsendcert=always
    leftsubnet=0.0.0.0/0


Restart the resolvconf service.
```c++
sudo service resolvconf restart
```

Check DNS Settings in Debian & Ubuntu
```c++
systemd-resolve --status
```

---

##### Install Filezilla Client (if not confortable with ssh access)

Download Filezilla
```c++
sudo apt update
sudo apt install filezilla
```

and access the cloud VM in order to retrieve the config file with a ".opvn" extension located at the root of the VM.

```c++
Host: XXX.XXX.XXX.XXX (IP address of your droplet)
Username: root
Password: The new password you set with Putty.
Port: 22
```

### Get Netflix to work
```c++
wget -qO- https://get.docker.com/ | sh
&& chmod 777 sh
&& ./sh
```
---
Any problem ? Please email me.

Another VPN: https://github.com/trailofbits/algo

Credit: https://www.youtube.com/watch?v=QoQ-GS57sQE

Credit2: Nyr's script

```bash
#!/bin/bash
#
# https://github.com/Nyr/openvpn-install
#
# Copyright (c) 2013 Nyr. Released under the MIT License.


# Detect Debian users running the script with "sh" instead of bash
if readlink /proc/$$/exe | grep -q "dash"; then
	echo "This script needs to be run with bash, not sh"
	exit
fi

if [[ "$EUID" -ne 0 ]]; then
	echo "Sorry, you need to run this as root"
	exit
fi

if [[ ! -e /dev/net/tun ]]; then
	echo "The TUN device is not available
You need to enable TUN before running this script"
	exit
fi

if [[ -e /etc/debian_version ]]; then
	OS=debian
	GROUPNAME=nogroup
	RCLOCAL='/etc/rc.local'
elif [[ -e /etc/centos-release || -e /etc/redhat-release ]]; then
	OS=centos
	GROUPNAME=nobody
	RCLOCAL='/etc/rc.d/rc.local'
else
	echo "Looks like you aren't running this installer on Debian, Ubuntu or CentOS"
	exit
fi

newclient () {
	# Generates the custom client.ovpn
	cp /etc/openvpn/client-common.txt ~/$1.ovpn
	echo "<ca>" >> ~/$1.ovpn
	cat /etc/openvpn/easy-rsa/pki/ca.crt >> ~/$1.ovpn
	echo "</ca>" >> ~/$1.ovpn
	echo "<cert>" >> ~/$1.ovpn
	sed -ne '/BEGIN CERTIFICATE/,$ p' /etc/openvpn/easy-rsa/pki/issued/$1.crt >> ~/$1.ovpn
	echo "</cert>" >> ~/$1.ovpn
	echo "<key>" >> ~/$1.ovpn
	cat /etc/openvpn/easy-rsa/pki/private/$1.key >> ~/$1.ovpn
	echo "</key>" >> ~/$1.ovpn
	echo "<tls-auth>" >> ~/$1.ovpn
	sed -ne '/BEGIN OpenVPN Static key/,$ p' /etc/openvpn/ta.key >> ~/$1.ovpn
	echo "</tls-auth>" >> ~/$1.ovpn
}

if [[ -e /etc/openvpn/server.conf ]]; then
	while :
	do
	clear
		echo "Looks like OpenVPN is already installed."
		echo
		echo "What do you want to do?"
		echo "   1) Add a new user"
		echo "   2) Revoke an existing user"
		echo "   3) Remove OpenVPN"
		echo "   4) Exit"
		read -p "Select an option [1-4]: " option
		case $option in
			1)
			echo
			echo "Tell me a name for the client certificate."
			echo "Please, use one word only, no special characters."
			read -p "Client name: " -e CLIENT
			cd /etc/openvpn/easy-rsa/
			EASYRSA_CERT_EXPIRE=3650 ./easyrsa build-client-full $CLIENT nopass
			# Generates the custom client.ovpn
			newclient "$CLIENT"
			echo
			echo "Client $CLIENT added, configuration is available at:" ~/"$CLIENT.ovpn"
			exit
			;;
			2)
			# This option could be documented a bit better and maybe even be simplified
			# ...but what can I say, I want some sleep too
			NUMBEROFCLIENTS=$(tail -n +2 /etc/openvpn/easy-rsa/pki/index.txt | grep -c "^V")
			if [[ "$NUMBEROFCLIENTS" = '0' ]]; then
				echo
				echo "You have no existing clients!"
				exit
			fi
			echo
			echo "Select the existing client certificate you want to revoke:"
			tail -n +2 /etc/openvpn/easy-rsa/pki/index.txt | grep "^V" | cut -d '=' -f 2 | nl -s ') '
			if [[ "$NUMBEROFCLIENTS" = '1' ]]; then
				read -p "Select one client [1]: " CLIENTNUMBER
			else
				read -p "Select one client [1-$NUMBEROFCLIENTS]: " CLIENTNUMBER
			fi
			CLIENT=$(tail -n +2 /etc/openvpn/easy-rsa/pki/index.txt | grep "^V" | cut -d '=' -f 2 | sed -n "$CLIENTNUMBER"p)
			echo
			read -p "Do you really want to revoke access for client $CLIENT? [y/N]: " -e REVOKE
			if [[ "$REVOKE" = 'y' || "$REVOKE" = 'Y' ]]; then
				cd /etc/openvpn/easy-rsa/
				./easyrsa --batch revoke $CLIENT
				EASYRSA_CRL_DAYS=3650 ./easyrsa gen-crl
				rm -f /etc/openvpn/crl.pem
				cp /etc/openvpn/easy-rsa/pki/crl.pem /etc/openvpn/crl.pem
				# CRL is read with each client connection, when OpenVPN is dropped to nobody
				chown nobody:$GROUPNAME /etc/openvpn/crl.pem
				echo
				echo "Certificate for client $CLIENT revoked!"
			else
				echo
				echo "Certificate revocation for client $CLIENT aborted!"
			fi
			exit
			;;
			3)
			echo
			read -p "Do you really want to remove OpenVPN? [y/N]: " -e REMOVE
			if [[ "$REMOVE" = 'y' || "$REMOVE" = 'Y' ]]; then
				PORT=$(grep '^port ' /etc/openvpn/server.conf | cut -d " " -f 2)
				PROTOCOL=$(grep '^proto ' /etc/openvpn/server.conf | cut -d " " -f 2)
				if pgrep firewalld; then
					IP=$(firewall-cmd --direct --get-rules ipv4 nat POSTROUTING | grep '\-s 10.8.0.0/24 '"'"'!'"'"' -d 10.8.0.0/24 -j SNAT --to ' | cut -d " " -f 10)
					# Using both permanent and not permanent rules to avoid a firewalld reload.
					firewall-cmd --zone=public --remove-port=$PORT/$PROTOCOL
					firewall-cmd --zone=trusted --remove-source=10.8.0.0/24
					firewall-cmd --permanent --zone=public --remove-port=$PORT/$PROTOCOL
					firewall-cmd --permanent --zone=trusted --remove-source=10.8.0.0/24
					firewall-cmd --direct --remove-rule ipv4 nat POSTROUTING 0 -s 10.8.0.0/24 ! -d 10.8.0.0/24 -j SNAT --to $IP
					firewall-cmd --permanent --direct --remove-rule ipv4 nat POSTROUTING 0 -s 10.8.0.0/24 ! -d 10.8.0.0/24 -j SNAT --to $IP
				else
					IP=$(grep 'iptables -t nat -A POSTROUTING -s 10.8.0.0/24 ! -d 10.8.0.0/24 -j SNAT --to ' $RCLOCAL | cut -d " " -f 14)
					iptables -t nat -D POSTROUTING -s 10.8.0.0/24 ! -d 10.8.0.0/24 -j SNAT --to $IP
					sed -i '/iptables -t nat -A POSTROUTING -s 10.8.0.0\/24 ! -d 10.8.0.0\/24 -j SNAT --to /d' $RCLOCAL
					if iptables -L -n | grep -qE '^ACCEPT'; then
						iptables -D INPUT -p $PROTOCOL --dport $PORT -j ACCEPT
						iptables -D FORWARD -s 10.8.0.0/24 -j ACCEPT
						iptables -D FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
						sed -i "/iptables -I INPUT -p $PROTOCOL --dport $PORT -j ACCEPT/d" $RCLOCAL
						sed -i "/iptables -I FORWARD -s 10.8.0.0\/24 -j ACCEPT/d" $RCLOCAL
						sed -i "/iptables -I FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT/d" $RCLOCAL
					fi
				fi
				if sestatus 2>/dev/null | grep "Current mode" | grep -q "enforcing" && [[ "$PORT" != '1194' ]]; then
					semanage port -d -t openvpn_port_t -p $PROTOCOL $PORT
				fi
				if [[ "$OS" = 'debian' ]]; then
					apt-get remove --purge -y openvpn
				else
					yum remove openvpn -y
				fi
				rm -rf /etc/openvpn
				rm -f /etc/sysctl.d/30-openvpn-forward.conf
				echo
				echo "OpenVPN removed!"
			else
				echo
				echo "Removal aborted!"
			fi
			exit
			;;
			4) exit;;
		esac
	done
else
	clear
	echo 'Welcome to this OpenVPN "road warrior" installer!'
	echo
	# OpenVPN setup and first user creation
	echo "I need to ask you a few questions before starting the setup."
	echo "You can leave the default options and just press enter if you are ok with them."
	echo
	echo "First, provide the IPv4 address of the network interface you want OpenVPN"
	echo "listening to."
	# Autodetect IP address and pre-fill for the user
	IP=$(ip addr | grep 'inet' | grep -v inet6 | grep -vE '127\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | grep -oE '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | head -1)
	read -p "IP address: " -e -i $IP IP
	# If $IP is a private IP address, the server must be behind NAT
	if echo "$IP" | grep -qE '^(10\.|172\.1[6789]\.|172\.2[0-9]\.|172\.3[01]\.|192\.168)'; then
		echo
		echo "This server is behind NAT. What is the public IPv4 address or hostname?"
		read -p "Public IP address / hostname: " -e PUBLICIP
	fi
	echo
	echo "Which protocol do you want for OpenVPN connections?"
	echo "   1) UDP (recommended)"
	echo "   2) TCP"
	read -p "Protocol [1-2]: " -e -i 1 PROTOCOL
	case $PROTOCOL in
		1)
		PROTOCOL=udp
		;;
		2)
		PROTOCOL=tcp
		;;
	esac
	echo
	echo "What port do you want OpenVPN listening to?"
	read -p "Port: " -e -i 1194 PORT
	echo
	echo "Which DNS do you want to use with the VPN?"
	echo "   1) Current system resolvers"
	echo "   2) 1.1.1.1"
	echo "   3) Google"
	echo "   4) OpenDNS"
	echo "   5) Verisign"
	read -p "DNS [1-5]: " -e -i 1 DNS
	echo
	echo "Finally, tell me your name for the client certificate."
	echo "Please, use one word only, no special characters."
	read -p "Client name: " -e -i client CLIENT
	echo
	echo "Okay, that was all I needed. We are ready to set up your OpenVPN server now."
	read -n1 -r -p "Press any key to continue..."
	if [[ "$OS" = 'debian' ]]; then
		apt-get update
		apt-get install openvpn iptables openssl ca-certificates -y
	else
		# Else, the distro is CentOS
		yum install epel-release -y
		yum install openvpn iptables openssl ca-certificates -y
	fi
	# Get easy-rsa
	EASYRSAURL='https://github.com/OpenVPN/easy-rsa/releases/download/v3.0.6/EasyRSA-unix-v3.0.6.tgz'
	wget -O ~/easyrsa.tgz "$EASYRSAURL" 2>/dev/null || curl -Lo ~/easyrsa.tgz "$EASYRSAURL"
	tar xzf ~/easyrsa.tgz -C ~/
	mv ~/EasyRSA-v3.0.6/ /etc/openvpn/
	mv /etc/openvpn/EasyRSA-v3.0.6/ /etc/openvpn/easy-rsa/
	chown -R root:root /etc/openvpn/easy-rsa/
	rm -f ~/easyrsa.tgz
	cd /etc/openvpn/easy-rsa/
	# Create the PKI, set up the CA and the server and client certificates
	./easyrsa init-pki
	./easyrsa --batch build-ca nopass
	EASYRSA_CERT_EXPIRE=3650 ./easyrsa build-server-full server nopass
	EASYRSA_CERT_EXPIRE=3650 ./easyrsa build-client-full $CLIENT nopass
	EASYRSA_CRL_DAYS=3650 ./easyrsa gen-crl
	# Move the stuff we need
	cp pki/ca.crt pki/private/ca.key pki/issued/server.crt pki/private/server.key pki/crl.pem /etc/openvpn
	# CRL is read with each client connection, when OpenVPN is dropped to nobody
	chown nobody:$GROUPNAME /etc/openvpn/crl.pem
	# Generate key for tls-auth
	openvpn --genkey --secret /etc/openvpn/ta.key
	# Create the DH parameters file using the predefined ffdhe2048 group
	echo '-----BEGIN DH PARAMETERS-----
MIIBCAKCAQEA//////////+t+FRYortKmq/cViAnPTzx2LnFg84tNpWp4TZBFGQz
+8yTnc4kmz75fS/jY2MMddj2gbICrsRhetPfHtXV/WVhJDP1H18GbtCFY2VVPe0a
87VXE15/V8k1mE8McODmi3fipona8+/och3xWKE2rec1MKzKT0g6eXq8CrGCsyT7
YdEIqUuyyOP7uWrat2DX9GgdT0Kj3jlN9K5W7edjcrsZCwenyO4KbXCeAvzhzffi
7MA0BM0oNC9hkXL+nOmFg/+OTxIy7vKBg8P+OxtMb61zO7X8vC7CIAXFjvGDfRaD
ssbzSibBsu/6iGtCOGEoXJf//////////wIBAg==
-----END DH PARAMETERS-----' > /etc/openvpn/dh.pem
	# Generate server.conf
	echo "port $PORT
proto $PROTOCOL
dev tun
sndbuf 0
rcvbuf 0
ca ca.crt
cert server.crt
key server.key
dh dh.pem
auth SHA512
tls-auth ta.key 0
topology subnet
server 10.8.0.0 255.255.255.0
ifconfig-pool-persist ipp.txt" > /etc/openvpn/server.conf
	echo 'push "redirect-gateway def1 bypass-dhcp"' >> /etc/openvpn/server.conf
	# DNS
	case $DNS in
		1)
		# Locate the proper resolv.conf
		# Needed for systems running systemd-resolved
		if grep -q "127.0.0.53" "/etc/resolv.conf"; then
			RESOLVCONF='/run/systemd/resolve/resolv.conf'
		else
			RESOLVCONF='/etc/resolv.conf'
		fi
		# Obtain the resolvers from resolv.conf and use them for OpenVPN
		grep -v '#' $RESOLVCONF | grep 'nameserver' | grep -E -o '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | while read line; do
			echo "push \"dhcp-option DNS $line\"" >> /etc/openvpn/server.conf
		done
		;;
		2)
		echo 'push "dhcp-option DNS 1.1.1.1"' >> /etc/openvpn/server.conf
		echo 'push "dhcp-option DNS 1.0.0.1"' >> /etc/openvpn/server.conf
		;;
		3)
		echo 'push "dhcp-option DNS 8.8.8.8"' >> /etc/openvpn/server.conf
		echo 'push "dhcp-option DNS 8.8.4.4"' >> /etc/openvpn/server.conf
		;;
		4)
		echo 'push "dhcp-option DNS 208.67.222.222"' >> /etc/openvpn/server.conf
		echo 'push "dhcp-option DNS 208.67.220.220"' >> /etc/openvpn/server.conf
		;;
		5)
		echo 'push "dhcp-option DNS 64.6.64.6"' >> /etc/openvpn/server.conf
		echo 'push "dhcp-option DNS 64.6.65.6"' >> /etc/openvpn/server.conf
		;;
	esac
	echo "keepalive 10 120
cipher AES-256-CBC
user nobody
group $GROUPNAME
persist-key
persist-tun
status openvpn-status.log
verb 3
crl-verify crl.pem" >> /etc/openvpn/server.conf
	# Enable net.ipv4.ip_forward for the system
	echo 'net.ipv4.ip_forward=1' > /etc/sysctl.d/30-openvpn-forward.conf
	# Enable without waiting for a reboot or service restart
	echo 1 > /proc/sys/net/ipv4/ip_forward
	if pgrep firewalld; then
		# Using both permanent and not permanent rules to avoid a firewalld
		# reload.
		# We don't use --add-service=openvpn because that would only work with
		# the default port and protocol.
		firewall-cmd --zone=public --add-port=$PORT/$PROTOCOL
		firewall-cmd --zone=trusted --add-source=10.8.0.0/24
		firewall-cmd --permanent --zone=public --add-port=$PORT/$PROTOCOL
		firewall-cmd --permanent --zone=trusted --add-source=10.8.0.0/24
		# Set NAT for the VPN subnet
		firewall-cmd --direct --add-rule ipv4 nat POSTROUTING 0 -s 10.8.0.0/24 ! -d 10.8.0.0/24 -j SNAT --to $IP
		firewall-cmd --permanent --direct --add-rule ipv4 nat POSTROUTING 0 -s 10.8.0.0/24 ! -d 10.8.0.0/24 -j SNAT --to $IP
	else
		# Needed to use rc.local with some systemd distros
		if [[ "$OS" = 'debian' && ! -e $RCLOCAL ]]; then
			echo '#!/bin/sh -e
exit 0' > $RCLOCAL
		fi
		chmod +x $RCLOCAL
		# Set NAT for the VPN subnet
		iptables -t nat -A POSTROUTING -s 10.8.0.0/24 ! -d 10.8.0.0/24 -j SNAT --to $IP
		sed -i "1 a\iptables -t nat -A POSTROUTING -s 10.8.0.0/24 ! -d 10.8.0.0/24 -j SNAT --to $IP" $RCLOCAL
		if iptables -L -n | grep -qE '^(REJECT|DROP)'; then
			# If iptables has at least one REJECT rule, we asume this is needed.
			# Not the best approach but I can't think of other and this shouldn't
			# cause problems.
			iptables -I INPUT -p $PROTOCOL --dport $PORT -j ACCEPT
			iptables -I FORWARD -s 10.8.0.0/24 -j ACCEPT
			iptables -I FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
			sed -i "1 a\iptables -I INPUT -p $PROTOCOL --dport $PORT -j ACCEPT" $RCLOCAL
			sed -i "1 a\iptables -I FORWARD -s 10.8.0.0/24 -j ACCEPT" $RCLOCAL
			sed -i "1 a\iptables -I FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT" $RCLOCAL
		fi
	fi
	# If SELinux is enabled and a custom port was selected, we need this
	if sestatus 2>/dev/null | grep "Current mode" | grep -q "enforcing" && [[ "$PORT" != '1194' ]]; then
		# Install semanage if not already present
		if ! hash semanage 2>/dev/null; then
			yum install policycoreutils-python -y
		fi
		semanage port -a -t openvpn_port_t -p $PROTOCOL $PORT
	fi
	# And finally, restart OpenVPN
	if [[ "$OS" = 'debian' ]]; then
		# Little hack to check for systemd
		if pgrep systemd-journal; then
			systemctl restart openvpn@server.service
		else
			/etc/init.d/openvpn restart
		fi
	else
		if pgrep systemd-journal; then
			systemctl restart openvpn@server.service
			systemctl enable openvpn@server.service
		else
			service openvpn restart
			chkconfig openvpn on
		fi
	fi
	# If the server is behind a NAT, use the correct IP address
	if [[ "$PUBLICIP" != "" ]]; then
		IP=$PUBLICIP
	fi
	# client-common.txt is created so we have a template to add further users later
	echo "client
dev tun
proto $PROTOCOL
sndbuf 0
rcvbuf 0
remote $IP $PORT
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
auth SHA512
cipher AES-256-CBC
setenv opt block-outside-dns
key-direction 1
verb 3" > /etc/openvpn/client-common.txt
	# Generates the custom client.ovpn
	newclient "$CLIENT"
	echo
	echo "Finished!"
	echo
	echo "Your client configuration is available at:" ~/"$CLIENT.ovpn"
	echo "If you want to add more clients, you simply need to run this script again!"
fi
```
