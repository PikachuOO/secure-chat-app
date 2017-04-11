from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import ciphers, hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa


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