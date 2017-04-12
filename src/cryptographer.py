from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import ciphers, hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.kdf import pbkdf2


class Cryptographer:
    def __init__(self):
        self.backend = default_backend()

    def create_rsa_pair(self):
        private_key = rsa.generate_private_key(public_exponent=65537,
                                               key_size=2048,
                                               backend=self.backend)
        public_key = private_key.public_key()
        return public_key, private_key

    def load_private_key(self, private_key_der):
        private_key = serialization.load_der_private_key(private_key_der.read(),
                                                         password=None,
                                                         backend=self.backend)
        return private_key

    def load_public_key(self, public_key_der):
        public_key = serialization.load_der_public_key(public_key_der.read(),
                                                        backend=self.backend)
        return public_key

    def compute_hash_from_client_password(self, username, password):
        hasher = hashes.Hash(hashes.SHA512, self.backend)
        hasher.update(username)
        salt = hasher.finalize()
        kdf = pbkdf2.PBKDF2HMAC(hashes.SHA512(),
                                length=64,
                                salt=salt,
                                iterations=200000,
                                backend=self.backend)
        password_hash = kdf.derive(password)
        return password_hash

    def sign_message(self, private_key, message):
        signature = private_key.sign(
                        message,
                        padding.PSS(
                        mgf=padding.MGF1(hashes.SHA512()),
                        salt_length=padding.PSS.MAX_LENGTH), hashes.SHA512())
        return signature
