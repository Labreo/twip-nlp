from http.server import BaseHTTPRequestHandler, HTTPServer
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
import os

UPLOAD_DIR = "c:\Users\erika\Downloads\data"
os.makedirs(UPLOAD_DIR, exist_ok=True)

if not os.path.exists("client.pub"):
    print("[*] Generating keypair...")

    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()

    # save private key (give this to VM)
    with open("client.key", "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption()
        ))

    # save public key (stay on server)
    with open("client.pub", "wb") as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        ))

    print("[!] Private key saved as client.key")
else:
    print("[*] Using existing public key")

with open("client.pub", "rb") as f:
    PUBLIC_KEY = Ed25519PublicKey.from_public_bytes(f.read())

class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        try:
            length = int(self.headers.get("Content-Length", 0))
            filename = self.headers.get("Filename")
            signature_hex = self.headers.get("Signature")

            if not filename or not signature_hex:
                raise ValueError("Missing headers")
            if filename == "__shutdown__" and data == b"SHUTDOWN":
                print("[*] Shutdown requested")
                self.send_response(200)
                self.end_headers()
                import threading
                threading.Thread(target=self.server.shutdown).start()
                return

            data = self.rfile.read(length)
            signature = bytes.fromhex(signature_hex)

            message = filename.encode() + b":" + data
            PUBLIC_KEY.verify(signature, message)

            safe_name = os.path.basename(filename)
            path = os.path.join(UPLOAD_DIR, safe_name)

            with open(path, "wb") as f:
                f.write(data)

            print(f"[OK] {safe_name}")
            self.send_response(200)

        except Exception as e:
            print("[DENIED]", e)
            self.send_response(403)

        self.end_headers()
print("[*] Listening on 0.0.0.0:8000")
HTTPServer(("0.0.0.0", 8000), Handler).serve_forever()
