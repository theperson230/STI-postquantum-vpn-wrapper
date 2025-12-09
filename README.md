# STI-postquantum-vpn-wrapper
VPN wrapper incorporating VPN solutions


#Installing dependencies
sudo apt update
sudo apt install -y build-essential git cmake python3 python3-venv python3-dev \
    libssl-dev libtool autoconf automake ninja-build pkg-config \
    libcurl4-openssl-dev liboqs-dev net-tools iptables curl
pip install --upgrade pip
pip install liboqs
pip install pycryptodome


#Set up
cd this directory
sudo modprobe tun
sudo chmod 666 /dev/net/tun
sudo sysctl -w net.ipv4.ip_forward=1
sudo sysctl -w net.ipv6.conf.all.forwarding=1
sudo iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
sudo iptables -A FORWARD -i tun1 -o eth0 -j ACCEPT
sudo iptables -A FORWARD -i eth0 -o tun1 -m state --state RELATED,ESTABLISHED -j ACCEPT

#Create environment
python3 -m venv ~/oqs-venv
source ~/oqs-venv/bin/activate

#Start scripts


sudo ~/oqs-venv/bin/python3 server.py
sudo ~/oqs-venv/bin/python3 client.py
# replace <tun_name> with what server printed, e.g. tun1
sudo ip addr add 10.8.0.1/24 dev tun1
sudo ip link set dev tun1 up
# replace <tun_name> printed by client, e.g. tun2
sudo ip addr add 10.8.0.2/24 dev tun2
sudo ip link set dev tun2 up

sudo ip route add 10.0.2.15 dev tun2
sudo ip route add 0.0.0.0/1 dev tun2
sudo ip route add 128.0.0.0/1 dev tun2
sudo ip route add 10.8.0.0/24 dev tun1

# replace eth0 with your server’s real Internet-facing interface
sudo iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE

# allow forwarding from VPN to Internet
sudo iptables -A FORWARD -i tun1 -o eth0 -j ACCEPT
sudo iptables -A FORWARD -i eth0 -o tun1 -m state --state ESTABLISHED,RELATED -j ACCEPT




