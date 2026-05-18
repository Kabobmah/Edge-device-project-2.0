import socket
import json
import os
import sys
import time
import subprocess
from datetime import datetime

# Cryptodome for linux , Crypto for windows
from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import pad, unpad
from Cryptodome.Random import get_random_bytes

class SecureKeyClient:
    def __init__(self, server_ip='192.168.56.1', server_port=8443):
        self.server_ip = server_ip
        self.server_port = server_port
        self.SHARED_SECRET = b"SuperSecretPreSharedKeyForAES256"
        
        self.device_name = "sdb"  
        self.device = f"/dev/{self.device_name}"
        self.mapper = "my_secret_disk"
        self.mount_point = "/mnt/secret"
        self.device_id = "Debian_Physical_Node"
        self.is_mounted = False

    def check_root(self):
        if os.geteuid() != 0:
            print("[-] Ошибка: Запускай строго через sudo!")
            sys.exit(1)

    def encrypt_data(self, plain_text: bytes) -> dict:
        iv = get_random_bytes(16)
        cipher = AES.new(self.SHARED_SECRET, AES.MODE_CBC, iv)
        encrypted_bytes = cipher.encrypt(pad(plain_text, AES.block_size))
        return {"iv": iv.hex(), "payload": encrypted_bytes.hex()}

    def decrypt_data(self, cipher_data: dict) -> bytes:
        iv = bytes.fromhex(cipher_data["iv"])
        payload = bytes.fromhex(cipher_data["payload"])
        cipher = AES.new(self.SHARED_SECRET, AES.MODE_CBC, iv)
        return unpad(cipher.decrypt(payload), AES.block_size)

    def mount_luks(self, luks_key):
        print("[*] Feeding key to LUKS kernel subsystem...")
        try:
            os.makedirs(self.mount_point, exist_ok=True)
            
         
            open_cmd = f"echo -n '{luks_key}' | cryptsetup open {self.device} {self.mapper} --key-file -"
            subprocess.run(open_cmd, shell=True, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            
            mount_cmd = f"mount -o x-gvfs-show /dev/mapper/{self.mapper} {self.mount_point}"
            subprocess.run(mount_cmd, shell=True, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            
            # Настройка прав
            subprocess.run(f"chmod 777 {self.mount_point}", shell=True)
            subprocess.run(f"chown -R edgedevice:edgedevice {self.mount_point}", shell=True)
            
            # Обновляем таблицы разделов для GUI
            subprocess.run("udevadm trigger", shell=True, stderr=subprocess.DEVNULL)
            
            print(f"[+] Success! Encrypted disk mounted at: {self.mount_point}")
            self.is_mounted = True
        except subprocess.CalledProcessError as e:
            print(f"[-] Mount execution failed: {e}")
            self.emergency_lock(exit_program=True)

    def emergency_lock(self, exit_program=True):
        
        print(f"\n[*] Start of kernel level blocking {self.device_name}...")
        
        subprocess.run("sync", shell=True)

        subprocess.run("pkill -9 -x thunar", shell=True, stderr=subprocess.DEVNULL)
        subprocess.run("pkill -9 -f gvfs", shell=True, stderr=subprocess.DEVNULL)
        time.sleep(0.3)

        try:
            mounts = subprocess.check_output(f"mount | grep {self.device_name}", shell=True).decode().split('\n')
            for mount in mounts:
                if mount.strip():
                    target = mount.split()[2]
                    print(f"[*] Dropping processes from: {target}")
                    subprocess.run(f"fuser -k -9 '{target}'", shell=True, stderr=subprocess.DEVNULL)
                    subprocess.run(f"umount -f -l '{target}'", shell=True, stderr=subprocess.DEVNULL)
        except subprocess.CalledProcessError:
            pass 

        try:
            dm_list = subprocess.check_output("dmsetup ls", shell=True).decode().split('\n')
            for dm in dm_list:
                if dm.strip():
                    dm_name = dm.split()[0]
                    
                    status = subprocess.check_output(f"dmsetup status {dm_name}", shell=True).decode()
                    if self.device_name in status or "luks" in dm_name or "secret" in dm_name:
                        print(f"[+] Kernel mapper: {dm_name}. Сносим устройство...")
                        
                        subprocess.run(f"fuser -k -9 /dev/mapper/{dm_name}", shell=True, stderr=subprocess.DEVNULL)
                        subprocess.run(f"umount -f -l /dev/mapper/{dm_name}", shell=True, stderr=subprocess.DEVNULL)
                        
                        subprocess.run(f"dmsetup remove -f {dm_name}", shell=True, stderr=subprocess.DEVNULL)
                        
                        subprocess.run(f"cryptsetup close {dm_name}", shell=True, stderr=subprocess.DEVNULL)
        except Exception as e:
            print(f"[-] Error: {e}")

        subprocess.run("udevadm trigger", shell=True, stderr=subprocess.DEVNULL)
        subprocess.run(f"blockdev --flushbufs {self.device}", shell=True, stderr=subprocess.DEVNULL)

        print("[+] DONE")
        self.is_mounted = False
        
        if exit_program:
            print("[+] Script closed.")
            sys.exit(0)

    def send_ping(self) -> bool:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(2)
            s.connect((self.server_ip, self.server_port))
            
            ping_packet = {"action": "ping"}
            s.send(json.dumps(ping_packet).encode('utf-8'))
            
            raw_res = s.recv(1024).decode('utf-8')
            if not raw_res:
                return False
                
            res = json.loads(raw_res)
            s.close()
            return res.get("status") == "PONG"
        except:
            return False

    def start_keep_alive_loop(self):
        print("[*] Keep-Alive active. Monitoring connection every 5 seconds...\n")
        while True:
            time.sleep(5)
            if self.is_mounted:
                current_time = datetime.now().strftime("%H:%M:%S")
                if self.send_ping():
                    print(f"[{current_time}] [PING OK] Server is alive. Disk is secure and available.")
                else:
                    print(f"\n[{current_time}] [-] Server heartbeat lost!")
                    self.emergency_lock(exit_program=True)

    def execute_handshake(self):
        try:
            print(f"[*] Connecting to server {self.server_ip}:{self.server_port}...")
            client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client_socket.settimeout(3)
            client_socket.connect((self.server_ip, self.server_port))
            
            client_nonce = get_random_bytes(16).hex()
            init_packet = {"action": "init_handshake", "device_id": self.device_id, "nonce": client_nonce}
            client_socket.send(json.dumps(init_packet).encode('utf-8'))
            
            raw_response = client_socket.recv(4096).decode('utf-8')
            server_packet = json.loads(raw_response)
            decrypted_server_data = json.loads(self.decrypt_data(server_packet).decode('utf-8'))
            
            if decrypted_server_data.get("client_nonce") != client_nonce:
                print("[-] Nonce mismatch validation failed!")
                client_socket.close()
                self.emergency_lock(exit_program=True)
                return
            
            server_nonce = decrypted_server_data.get("server_nonce")
            print("[+] Server identity validated.")
            
            confirmation_payload = {"server_nonce": server_nonce}
            encrypted_confirmation = self.encrypt_data(json.dumps(confirmation_payload).encode('utf-8'))
            client_socket.send(json.dumps(encrypted_confirmation).encode('utf-8'))
            
            raw_key_packet = client_socket.recv(4096).decode('utf-8')
            key_packet = json.loads(raw_key_packet)
            decrypted_key_data = json.loads(self.decrypt_data(key_packet).decode('utf-8'))
            
            if decrypted_key_data.get("status") == "AUTH_OK":
                print("[+] Auth OK! Key received securely.")
                luks_key = decrypted_key_data.get("luks_key")
                client_socket.close()
                
                self.emergency_lock(exit_program=False)
                self.mount_luks(luks_key)
            else:
                print("[-] Server denied access.")
                client_socket.close()
                self.emergency_lock(exit_program=True)
                
        except Exception as e:
            print(f"[-] Handshake failed: Server is offline ({e})")
            self.emergency_lock(exit_program=True)

if __name__ == "__main__":
    client = SecureKeyClient()
    client.check_root()
    
    client.emergency_lock(exit_program=False)
    
    client.execute_handshake()
    
    if client.is_mounted:
        client.start_keep_alive_loop()