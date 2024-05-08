from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

private_key = ec.generate_private_key(ec.SECP256R1())
public_key = private_key.public_key()
message = b"Ayan Sayyad"
signature = private_key.sign(message, ec.ECDSA(hashes.SHA256()))
try:
    public_key.verify(signature, message, ec.ECDSA(hashes.SHA256()))
    print("Signature is valid!")
except Exception:
    print("Signature is invalid.")
serialized_public_key = public_key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
deserialized_public_key = ec.load_pem_public_key(serialized_public_key)

print("Serialized Public Key:")
print(serialized_public_key.decode("utf-8"))
