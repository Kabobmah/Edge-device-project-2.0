import socket
import json
import logging
import threading  # multithreading
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s: %(message)s')

class SecureKeyServer:
    def __init__(self, host='0.0.0.0', port=8443):
        self.host = host
        self.port = port
        self.SHARED_SECRET = b"SuperSecretPreSharedKeyForAES256"  # 32 bytes
        self.DATABASE = {
            "Debian_Physical_Node": "edgedevice",
            "Debian_Node_01": "edgedevice"
        }

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

    def handle_client(self, client_socket):
        try:
            client_socket.settimeout(5) # for stalled connections
            raw_data = client_socket.recv(4096).decode('utf-8')
            if not raw_data:
                return
                
            packet = json.loads(raw_data)
            action = packet.get("action")
            # ping answering
            if action == "ping":
                response = {"status": "PONG"}
                client_socket.send(json.dumps(response).encode('utf-8'))
                return

            # handshake
            # -------------------------------------

            elif action == "init_handshake":
                device_id = packet.get("device_id")
                client_nonce = packet.get("nonce")
                logging.info(f"[*] Handshake initiated by device: {device_id}")

                if device_id not in self.DATABASE:
                    logging.warning(f"[-] Unauthorized device_id: {device_id}")
                    client_socket.close()
                    return

                # handshake logic
                server_nonce = get_random_bytes(16).hex()
                server_data = {"client_nonce": client_nonce, "server_nonce": server_nonce}
                encrypted_server_data = self.encrypt_data(json.dumps(server_data).encode('utf-8'))
                client_socket.send(json.dumps(encrypted_server_data).encode('utf-8'))

                raw_confirmation = client_socket.recv(4096).decode('utf-8')
                confirmation_packet = json.loads(raw_confirmation)
                decrypted_confirmation = json.loads(self.decrypt_data(confirmation_packet).decode('utf-8'))

                if decrypted_confirmation.get("server_nonce") != server_nonce:
                    logging.error("[-] Client validation failed (Nonce mismatch)!")
                    client_socket.close()
                    return

                logging.info(f"[+] Device {device_id} successfully authenticated!")
                
                luks_key = self.DATABASE[device_id]
                key_payload = {"status": "AUTH_OK", "luks_key": luks_key}
                encrypted_key_packet = self.encrypt_data(json.dumps(key_payload).encode('utf-8'))
                client_socket.send(json.dumps(encrypted_key_packet).encode('utf-8'))
                # -------------------------------------

        except Exception as e:
            logging.error(f"[-] Session error: {str(e)}")
        finally:
            client_socket.close()

    def start(self):
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind((self.host, self.port))
        server_socket.listen(10)
        logging.info(f"[+] Server online on {self.host}:{self.port}...")

        try:
            while True:
                client_sock, client_address = server_socket.accept()
                # hs or ping on different threads
                client_thread = threading.Thread(
                    target=self.handle_client, 
                    args=(client_sock,), 
                    daemon=True
                )
                client_thread.start()
        except KeyboardInterrupt:
            logging.info("[!] Server stopped by admin.")
        finally:
            server_socket.close()

if __name__ == "__main__":
    server = SecureKeyServer()
    server.start()  