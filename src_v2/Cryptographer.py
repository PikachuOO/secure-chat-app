from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import ciphers, hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.kdf import pbkdf2
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives.ciphers import algorithms
from cryptography.hazmat.primitives.ciphers import modes
import constants as CN


class Cryptographer:
    def __init__(self):
        self.backend = default_backend()

    def create_rsa_pair(self):
        # try:
        private_key = rsa.generate_private_key(public_exponent=CN.RSA_PUBLIC_EXPONENT,
                                           key_size=CN.RSA_KEY_SIZE,
                                           backend=self.backend)
        public_key = private_key.public_key()
        return public_key, private_key
        # except UnsupportedAlgorithm:
        #     print CN.exception_messages.get('UnsupportedAlgorithm')


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

    def compute_hash(self, message):
        hasher = hashes.Hash(hashes.SHA512(), self.backend)
        salt = hasher.finalize()
        kdf = pbkdf2.PBKDF2HMAC(hashes.SHA512(),
                                length=CN.HASH_LENGTH,
                                salt=salt,
                                iterations=CN.HASH_ITERATIONS,
                                backend=self.backend)
        message_hash = kdf.derive(message)
        return message_hash

    def sign_message(self, private_key, message):
        signer = private_key.signer(
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ), hashes.SHA256())

        signer.update(message)
        signature = signer.finalize()
        return signature

    def verify_message(self, public_key, message, signature):
        try:
            verifier = public_key.verifier(
                signature,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH),
                hashes.SHA256())
            verifier.update(message)
            verifier.verify()
        except:
            print "dsfdfgdg"

    def rsa_encryption(self,public_key,message):
        ciphertext = public_key.encrypt(message,padding.OAEP(mgf = padding.MGF1(algorithm=hashes.SHA256()),
                                                             algorithm = hashes.SHA256(),label = None))
        return ciphertext

    def rsa_decryption(self,private_key,ciphertext):
        plaintext = private_key.decrypt(ciphertext,padding.OAEP(mgf = padding.MGF1(algorithm=hashes.SHA256()),
                                                                algorithm = hashes.SHA256(),label = None))
        return plaintext

    def get_dh_pair(self):
        private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
        public_key = private_key.public_key()
        return private_key, public_key

    # get symmetric key from DH

    def get_symmetric_key(self, peer_public_key, private_key):
        return private_key.exchange(ec.ECDH(), peer_public_key)

    def public_key_to_bytes(self, public_key):
        return bytes(public_key.public_bytes(encoding=serialization.Encoding.DER,
                                             format=serialization.PublicFormat.SubjectPublicKeyInfo))

    def bytes_to_public_key(self, bytes):
        try:
            return serialization.load_der_public_key(bytes, backend=self.backend)
        except ValueError:
            print "Invlaisliasi"

    def symmetric_encryption(self, sym_key, iv, payload, ad):
        encryptor = ciphers.Cipher(algorithms.AES(sym_key), mode=modes.GCM(iv),
                                   backend=default_backend()).encryptor()
        encryptor.authenticate_additional_data(ad)
        ciphertext = encryptor.update(payload) + encryptor.finalize()
        return encryptor.tag, ciphertext
