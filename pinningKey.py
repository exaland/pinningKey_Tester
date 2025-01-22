import ssl
import socket
import base64
import hashlib
import sys
def verify_certificate_pinning(host, port, expected_pin):
    try:
        # Ouvre une connexion au serveur
        conn = socket.create_connection((host, port))
        context = ssl.create_default_context()
        sock = context.wrap_socket(conn, server_hostname=host)

        # Récupère le certificat du serveur
        der_cert = sock.getpeercert(binary_form=True)
        public_key = ssl.DER_cert_to_PEM_cert(der_cert).encode()

        # Calcule l'empreinte SHA-256
        sha256_hash = hashlib.sha256(public_key).digest()
        base64_pin = base64.b64encode(sha256_hash).decode()

        # Compare l'empreinte avec la clé pinning attendue
        if f"sha256/{base64_pin}" == expected_pin:
            print("✔️ Pinning réussi ! La clé correspond.")
        else:
            print(f"❌ Pinning échoué ! Empreinte attendue : {expected_pin}, obtenue : sha256/{base64_pin}")
    except Exception as e:
        print(f"Erreur : {e}")

# Test de connexion avec une clé pinning
host = input("Tapez votre domaine (ex: api.example.com) : ")  
expected_pin = input("Tapez votre clé pinning (ex: sha256/HzGPjh7MzWriq1ivfLZC6LbvjmbVcIWzgDGdE9IQzzE=) : ")
port = 443
verify_certificate_pinning(host, port, expected_pin)
