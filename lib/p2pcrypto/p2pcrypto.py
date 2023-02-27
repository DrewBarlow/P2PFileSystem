from ctypes import sizeof
from coincurve import verify_signature
from coincurve.keys import PrivateKey
from Crypto.Cipher import AES, _mode_gcm
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes 
from Crypto.Util.Padding import pad, unpad
from ecies import decrypt, encrypt
from ecies.utils import generate_key
from typing import Optional, Tuple

class P2PCrypto:
    # Exceptions for missing a key
    class MissingOwnPrivkey(Exception): pass
    class MissingOwnPubkey(Exception): pass
    class MissingPeerPubkey(Exception): pass
    class MissingSymmetricKey(Exception): pass

    # Already having a key present
    class SymmetricKeyExists(Exception): pass 

    # Failing to verify security attributes
    class DataIsNotIntegrous(Exception): pass

    AES_BLOCK_SIZE: int = 16
    NONCE_SIZE: int = 16
    NUM_AES_KEY_BITS: int = 256
    CONCAT_DELIMITER: bytes = b"||:>}!@$*@$|!*$!}>:{||"

    def __init__(self, pubkey_path: str, privkey_path: str, /, save_generated_key: bool=True) -> None:
        self._save_generated_key: bool = save_generated_key
        self._pubkey_path: str = pubkey_path
        self._privkey_path: str = privkey_path 
        self._pubkey: bytes = None
        self._peer_pubkey: bytes = None
        self.__keypair: PrivateKey = None
        self.__privkey: bytes = None
        self.__symkey: bytes = None
        self.__symkey_cipher: _mode_gcm.GcmMode = None
        self.__fetch_ecc_keypair()
    
    def sign_then_encrypt(self, plaintext: bytes) -> bytes:
        """
        Encrypts the supplied data with the symmetric key, then signs it and encrypts it
        under the peer's private key.

        Parameters:
            plaintext (bytes): The data to encrypt, encoded as bytes. 

        Returns:
            The encrypted data as bytes.

        Raises:
            MissingOwnPrivkey if no ECC private key is loaded.
            MissingSymmetricKey if no symmetric key is present.
        """
        if self.__privkey is None:
            raise self.MissingOwnPrivkey("Failed to sign message: no private key is loaded.")
        elif self._peer_pubkey is None:
            raise self.MissingPeerPubkey("Failed to encrypt message: no public key is set for the peer.")
        elif self.__symkey_cipher is None:
            raise self.MissingSymmetricKey("Failed to encrypt message and hash: no symmetric key is present (use set_symkey()).")

        # encrypt the data under the private key, then concatenate it with a hash of it 
        encrypted_data = self.__symkey_cipher.encrypt(pad(plaintext, self.AES_BLOCK_SIZE))
        self.__reset_symkey_cipher()
        signature: bytes = self.__keypair.sign(encrypted_data, hasher=self.__hasher)

        concat: bytes = encrypted_data + self.CONCAT_DELIMITER + signature + self.__symkey_cipher.nonce
        return encrypt(self._peer_pubkey, concat)

    # TODO: GEN NEW NONCE IF THE MESSAGES BECOME OUT OF SYNC
    def decrypt_and_verify(self, ciphertext: bytes) -> bytes:
        """
        Decrypts ciphertext with the symmetric key, then verifies the signed message and hash.

        Parameters:
            ciphertext (bytes): The signed data and its hash encrypted under the symmetric key.

        Returns:
            The data decrypted under the peer's private key.
            If it is gibberish, non-repudation is not present.

        Raises:
            MissingPeerPubkey if no public key is registered for the peer.
            MissingSymmetricKey if no symmetric key is set.
            DataIsNotIntegrous if the hash doesn't match.
        """
        if self._peer_pubkey is None:
            raise self.MissingPeerPubkey("Failed to verify signature: no peer public key is present.")
        elif self.__symkey_cipher is None:
            raise self.MissingSymmetricKey("Failed to decrypt message and verify signature: no symmetric key is present.")

        decrypted_signed_data: bytes = decrypt(self.__privkey, ciphertext)
        encrypted_data, signature_and_nonce = decrypted_signed_data.split(self.CONCAT_DELIMITER)
        nonce: bytes = signature_and_nonce[-self.NONCE_SIZE:]
        signature: bytes = signature_and_nonce[:-self.NONCE_SIZE]

        if not verify_signature(signature, encrypted_data, self._peer_pubkey, hasher=self.__hasher):
            raise self.DataIsNotIntegrous("Failed to verify the signature.")

        self.__reset_symkey_cipher(nonce)
        try:
            plaintext: bytes = unpad(self.__symkey_cipher.decrypt(encrypted_data), self.AES_BLOCK_SIZE)
        except ValueError as err:
            raise self.DataIsNotIntegrous(err)
        finally:
            self.__reset_symkey_cipher(nonce)

        return plaintext 

    def encrypt_with_peer_pubkey(self, plaintext: bytes) -> bytes:
        """
        Simply encrypts the supplied data under the recipient's public key.

        Parameters:
            plaintext (bytes): The data to encrypt, encoded as bytes. 

        Returns:
            The encrypted data as bytes.

        Raises:
            MissingPeerPubkey if no public key for peer is set.
        """
        if self._peer_pubkey is None:
            raise self.MissingPeerPubkey("Failed to encrypt message under peer's public key: no public key is present (use set_peer_pubkey()).")

        return encrypt(self._peer_pubkey, plaintext)

    def decrypt_with_privkey(self, ciphertext: bytes) -> bytes:
        """
        Decrypts a message sent under this peer's public key.

        Parameters:
            data (bytes): The ciphertext encrypted under this peer's public key.

        Returns:
            The resulting decrypted text.

        Raises:
            MissingOwnPrivkey if no ECC private key is present.
        """
        if self.__privkey is None:
            raise self.MissingOwnPrivkey("Failed to decrypt message: no private key is loaded.")

        return decrypt(self.__privkey, ciphertext)

    def set_peer_pubkey(self, peer_pubkey: bytes) -> None:
        """
        Upon reception of the peer's public key, stores it.

        Parameters:
            peer_pubkey (bytes): The peer's pubkey encoded in raw byte form.

        Returns:
            None
        """
        self._peer_pubkey = peer_pubkey
        return

    def get_peer_pubkey(self) -> bytes:
        """
        Simple getter for the peer's public key.

        Parameters:
            None.

        Returns:
            The peer's public key, in bytes and DER format.
        """
        if self._peer_pubkey is None:
            raise self.MissingPeerPubkey("Failed to fetch peer's public key. It hasn't been registered.")

        return self._peer_pubkey

    def set_symkey(self, symkey: bytes, nonce: bytes) -> None:
        """
        Upon reception of a generated private key, create its cipher object and store it.

        Parameters:
            symkey (bytes): The raw symkey sent by the peer, encoded as bytes.
            nonce (bytes): A nonce to establish a new AES cipher, encoded as bytes.

        Returns:
            None.

        Raises:
            SymmetricKeyExists if a key is already present.
        """
        if self.__symkey_cipher:
            raise self.SymmetricKeyExists("Can't set a new symmetric key for this session, one is already set.")

        self.__symkey = symkey
        self.__symkey_cipher = AES.new(symkey, AES.MODE_GCM, nonce=nonce)

        return 

    def gen_symkey(self) -> Tuple[bytes, bytes]: 
        """
        Generates a new symmetric key and sets this instance's symkey and symkey_cipher attrs.
        
        Parameters:
            None.

        Returns:
            The new symmetric key in bytes along with the nonce as a tuple.

        Raises:
            SymmetricKeyExists if a key is already present.
        """
        if (self.__symkey or self.__symkey_cipher):
            raise self.SymmetricKeyExists("Can't generate a new symmetric key for this session, one is already present.")

        self.__symkey = get_random_bytes(self.NUM_AES_KEY_BITS // 8)
        nonce: bytes = get_random_bytes(self.NONCE_SIZE)
        self.set_symkey(self.__symkey, nonce)

        return self.__symkey, nonce
        
    def get_own_pubkey(self) -> bytes:
        """
        Simple getter for this peer's public key.

        Parameters:
            None.

        Returns:
            This peer's public key, in bytes.
        """
        if self._pubkey is None:
            raise self.MissingOwnPubkey("Failed to retrieve own public key. One is not present.")

        return self._pubkey

    def __reset_symkey_cipher(self, nonce: Optional[bytes]=None) -> None:
        """
        Recreates a used AES cipher object with a new nonce.

        Parameters:
            nonce (Optional[bytes]): A provided nonce to initialize to, if desired.

        Returns:
            None.
        """
        nonce = nonce if nonce is not None else self.__symkey_cipher.nonce
        self.__symkey_cipher = AES.new(self.__symkey, AES.MODE_GCM, nonce=nonce)
        return

    def __fetch_ecc_keypair(self) -> None:
        """
        Loads an ECC keypair from the file system if it exists.
        Otherwise, it generates a new one.

        Parameters:
            None.

        Returns:
            None.
        """
        self.__load_ecc_key_from_path(self._pubkey_path)
        self.__load_ecc_key_from_path(self._privkey_path)

        if not (self._pubkey or self.__privkey):
            self.__generate_and_save_key_to_path()

        return

    def __generate_and_save_key_to_path(self) -> None:
        """
        Generates a new ECC public/private keypair.

        Parameters:
            None.

        Returns:
            None.
        """
        self.__keypair = generate_key()
        self.__privkey = self.__keypair.secret
        self._pubkey = self.__keypair.public_key.format(True)

        if self._save_generated_key:
            with open(self._pubkey_path, "wb") as file:
                file.write(self._pubkey)

            with open(self._privkey_path, "wb") as file:
                file.write(self.__privkey)

        return

    @staticmethod
    def __load_ecc_key_from_path(path: str) -> Optional[bytes]:
        """
        Loads an ECC key (public or private) from the supplied path.

        Parameters:
            path (str): The path to the key (.key) file.

        Returns:
            ECC.EccKey if the file is opened and the key is successfully parsed.
            None if the file is not found or the key can't be parsed.
        """
        try:
            with open(path, "rb") as file:
                return file.read()
        except FileNotFoundError as err:
            pass
            # print(f"Couldn't find {path}, generating new keys instead.")
        except (ValueError, IndexError, TypeError) as err:
            print(f"Failed to parse key from {path}, generating new keys instead.")
        except Exception as err:
            print("Something went horribly wrong when loading key...")
            print(err)

        return

    @staticmethod
    def __hasher(data: bytes) -> bytes:
        sha: SHA256.SHA256Hash = SHA256.new(data=data)
        return sha.digest()

