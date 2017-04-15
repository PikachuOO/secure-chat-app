from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import ciphers, hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.kdf import pbkdf2
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import UnsupportedAlgorithm
import constants as CN


class Cryptographer:
    def __init__(self):
        self.backend = default_backend()

    def create_rsa_pair(self):
        try:
            private_key = rsa.generate_private_key(public_exponent=CN.RSA_PUBLIC_EXPONENT,
                                               key_size=CN.RSA_KEY_SIZE,
                                               backend=self.backend)
            public_key = private_key.public_key()
            return public_key, private_key
        except UnsupportedAlgorithm:
            print CN.exception_messages.get('UnsupportedAlgorithm')


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
        hasher = hashes.Hash(hashes.SHA512(), self.backend)
        hasher.update(username)
        salt = hasher.finalize()
        kdf = pbkdf2.PBKDF2HMAC(hashes.SHA512(),
                                length=CN.HASH_LENGTH,
                                salt=salt,
                                iterations=CN.HASH_ITERATIONS,
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

    def rsa_encryption(self,public_key,message):
        ciphertext = public_key.encrypt(message,padding.OAEP(mgf = padding.MGF1(algorithm=hashes.SHA512()),
                                                             algorithm = hashes.SHA512(),label = None))
        return ciphertext

    def rsa_decryption(self,private_key,ciphertext):
        plaintext = private_key.decrypt(ciphertext,padding.OAEP(mgf = padding.MGF1(algorithm=hashes.SHA512()),
                                                                algorithm = hashes.SHA512(),label = None))
        return plaintext

    def get_dh_pair(self):
        private_key = ec.generate_private_key(ec.SECP384R1(), default_backend())
        public_key = private_key.public_key()
        return private_key, public_key

    # get symmetric key from DH

    def get_symmetric_key(self,peer_public_key, private_key):
        return private_key.exchange(ec.ECDH(), peer_public_key)

    def public_key_to_bytes(self, public_key):
        return bytes(public_key.public_bytes(encoding=serialization.Encoding.DER,
                                             format=serialization.PublicFormat.SubjectPublicKeyInfo))

    def bytes_to_public_key(self, bytes):
        try:
            return serialization.load_der_public_key(bytes, backend=self.backend)
        except ValueError:
            print "Invlaisliasi"
