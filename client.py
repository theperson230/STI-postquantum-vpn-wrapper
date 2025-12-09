#!/usr/bin/env python3
# client.py - PQ wrapper client (framed, select-based, TUN <-> socket)

import os
import fcntl
import struct
import socket
import sys
import select
from common import create_kem, encapsulate_secret, derive_aes_key, encrypt

# TUN constants
TUNSETIFF = 0x400454ca
IFF_TUN = 0x0001
IFF_NO_PI = 0x1000

def create_tun(preferred_name=b"tun2"):
    dev = "/dev/net/tun"
    names_to_try = [preferred_name] + [f"tun{i}".encode() for i in range(0, 10)]
    fd = os.open(dev, os.O_RDWR)
    for nm in names_to_try:
        try:
            ifr = struct.pack("16sH", nm.ljust(16, b"\0"), IFF_TUN | IFF_NO_PI)
            fcntl.ioctl(fd, TUNSETIFF, ifr)
            return fd, nm.decode().rstrip("\0")
        except OSError:
            continue
    os.close(fd)
    raise RuntimeError("Could not allocate a TUN device (all names busy)")

def recv_all(sock, n):
    parts = []
    to_read = n
    while to_read > 0:
        chunk = sock.recv(to_read)
        if not chunk:
            raise ConnectionError("Unexpected socket close while receiving")
        parts.append(chunk)
        to_read -= len(chunk)
    return b"".join(parts)

def recv_framed(sock):
    header = recv_all(sock, 4)
    length = int.from_bytes(header, "big")
    return recv_all(sock, length)

def send_framed(sock, payload: bytes):
    sock.send(len(payload).to_bytes(4, "big") + payload)

def label_packet(vpn_data):
    if not vpn_data:
        return "Empty", ""
    ver = (vpn_data[0] >> 4) if len(vpn_data) >= 1 else None
    if ver == 4 and len(vpn_data) >= 10:
        proto = vpn_data[9]
        header_sample = " ".join(f"{b:02x}" for b in vpn_data[:20])
        if proto == 1:
            return "ICMP (Ping)", header_sample
        elif proto == 6:
            return "TCP (Browser?)", header_sample
        elif proto == 17:
            return "UDP (DNS/other)", header_sample
        else:
            return "Other", header_sample
    elif ver == 6 and len(vpn_data) >= 40:
        nh = vpn_data[6]
        header_sample = " ".join(f"{b:02x}" for b in vpn_data[:40])
        if nh == 58:
            return "ICMPv6 (Ping)", header_sample
        elif nh == 6:
            return "TCP (Browser?)", header_sample
        elif nh == 17:
            return "UDP (DNS/other)", header_sample
        else:
            return "Other", header_sample
    else:
        return "Other", " ".join(f"{b:02x}" for b in vpn_data[:16])

# ---------- Main ----------
def main():
    try:
        tun_fd, tun_name = create_tun(b"tun2")
    except Exception as e:
        print("TUN creation failed:", e)
        sys.exit(1)
    print(f"Client TUN device created successfully: {tun_name}")

    # server IP can be set by env or default
    server_ip = os.environ.get("SERVER_IP", "10.0.2.15")
    port_env = os.environ.get("SERVER_PORT", "51820")
    PORT = int(port_env)

    kem = create_kem("Kyber512")

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((server_ip, PORT))
        print(f"Connected to server: {server_ip}:{PORT}")

        # receive server public key (framed)
        server_pub = recv_framed(s)
        print("Received server public key (len={} bytes).".format(len(server_pub)))

        # encapsulate -> ciphertext, shared_secret
        ciphertext, shared_secret = encapsulate_secret(kem, server_pub)
        aes_key = derive_aes_key(shared_secret)
        print("Client derived AES key:", aes_key.hex())

        # send encapsulated ciphertext (framed)
        send_framed(s, ciphertext)
        print("Sent encapsulated ciphertext to server.")

        print("Starting PQ-VPN packet loop... (client)")

        try:
            while True:
                # select on TUN fd and socket - we want to both send (TUN->socket) and receive (socket->TUN)
                rlist, _, _ = select.select([tun_fd, s], [], [], 1.0)
                if tun_fd in rlist:
                    vpn_data = os.read(tun_fd, 65535)
                    if not vpn_data:
                        continue
                    label, hdr = label_packet(vpn_data)
                    print(f"Encrypted {len(vpn_data)} bytes [{label}], header: {hdr}")

                    nonce, ciphertext_msg = encrypt(vpn_data, aes_key)
                    payload = nonce + ciphertext_msg
                    send_framed(s, payload)

                if s in rlist:
                    # framed inbound (server -> client)
                    pkt = recv_framed(s)
                    if len(pkt) < 13:
                        print("Received too-short framed pkt, skipping")
                        continue
                    nonce = pkt[:12]
                    ciphertext = pkt[12:]
                    try:
                        vpn_data = decrypt(nonce, ciphertext, aes_key)
                    except Exception as e:
                        print("Decryption failed (incoming):", type(e).__name__, e)
                        continue
                    os.write(tun_fd, vpn_data)
                    label, hdr = label_packet(vpn_data)
                    print(f"Decrypted {len(vpn_data)} bytes [{label}], header: {hdr}")

        except (BrokenPipeError, ConnectionError) as e:
            print("Connection closed:", e)

if __name__ == "__main__":
    main()
