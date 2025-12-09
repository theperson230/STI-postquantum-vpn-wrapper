#!/usr/bin/env python3
import os
import fcntl
import struct
import socket
import sys
from common import create_kem, generate_keypair, decapsulate_secret, derive_aes_key, decrypt

# TUN constants
TUNSETIFF = 0x400454ca
IFF_TUN = 0x0001
IFF_NO_PI = 0x1000

# Helpers
def create_tun(preferred_name=b"tun1"):
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

def handle_label_and_print(vpn_data, prefix="Decrypted"):
    if len(vpn_data) < 1:
        label = "Empty"
        header_sample = ""
    else:
        ver = (vpn_data[0] >> 4) if len(vpn_data) >= 1 else None
        if ver == 4 and len(vpn_data) >= 20:
            proto = vpn_data[9]
            header_sample = " ".join(f"{b:02x}" for b in vpn_data[:20])
        elif ver == 6 and len(vpn_data) >= 40:
            proto = 58
            header_sample = " ".join(f"{b:02x}" for b in vpn_data[:40])
        else:
            proto = None
            header_sample = " ".join(f"{b:02x}" for b in vpn_data[:16])

        if proto == 1:
            label = "ICMP (Ping)"
        elif proto == 6:
            label = "TCP (Browser?)"
        elif proto == 17:
            label = "UDP (DNS/other)"
        else:
            label = "Other"

    print(f"{prefix} {len(vpn_data)} bytes [{label}], header: {header_sample}")

# ---------- Main ----------
def main():
    # create TUN
    try:
        tun_fd, tun_name = create_tun(b"tun1")
    except Exception as e:
        print("TUN creation failed:", e)
        sys.exit(1)
    print(f"Server TUN device created successfully: {tun_name}")

    # server networking
    HOST = "0.0.0.0"
    PORT = 51820

    # KEM setup
    kem = create_kem("Kyber512")
    public_key = generate_keypair(kem)
    print("Server generated KEM public key (len={} bytes)".format(len(public_key)))

    # raw socket for forwarding packets
    raw_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((HOST, PORT))
        s.listen(1)
        print(f"Server listening on {HOST}:{PORT}")
        conn, addr = s.accept()
        print("Connected by", addr)
        with conn:
            # send server public key
            conn.send(len(public_key).to_bytes(4, "big") + public_key)
            print("Sent server public key to client.")

            # receive ciphertext
            raw = recv_framed(conn)
            shared_secret = decapsulate_secret(kem, raw)
            aes_key = derive_aes_key(shared_secret)
            print("Shared AES key established:", aes_key.hex())

            print("Starting PQ-VPN receive loop... (server)")

            try:
                while True:
                    # receive VPN packet
                    pkt = recv_framed(conn)
                    if len(pkt) < 13:
                        continue
                    nonce = pkt[:12]
                    ciphertext = pkt[12:]
                    try:
                        vpn_data = decrypt(nonce, ciphertext, aes_key)
                    except Exception as e:
                        print("Decryption failed:", e)
                        continue

                    handle_label_and_print(vpn_data, prefix="Decrypted")

                    # write to TUN (for client-side routing)
                    os.write(tun_fd, vpn_data)

                    # Forward IPv4 packets to Internet
                    if vpn_data[0] >> 4 == 4:
                        dst_ip = ".".join(str(b) for b in vpn_data[16:20])
                        try:
                            raw_sock.sendto(vpn_data, (dst_ip, 0))
                        except Exception as e:
                            print("Raw send failed:", e)

            except (ConnectionError, BrokenPipeError) as e:
                print("Connection closed:", e)

if __name__ == "__main__":
    main()
