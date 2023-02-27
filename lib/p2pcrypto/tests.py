import unittest
from Crypto.Cipher import AES, _mode_gcm
from Crypto.Hash import SHA512
from Crypto.Util.Padding import pad, unpad
from p2pcrypto import P2PCrypto
from ecies import decrypt, encrypt
from glob import glob
from os import system  # yeah yeah shut up

# includes loading ECC keys, generating AES key, and instantiated cipher objects
class TestAttributeMethods(unittest.TestCase):
    INVALID_FILENAME: str = "THIS_FILE_DOES_NOT_EXIST"
    VALID_PUBKEY_FILENAME: str = "__TESTING_PUBKEY__.key"
    VALID_PRIVKEY_FILENAME: str = "__TESTING_PUBKEY__.key"

    def cleanup(self) -> None:
        for fname in [self.INVALID_FILENAME, self.VALID_PUBKEY_FILENAME, self.VALID_PRIVKEY_FILENAME]:
            if fname in glob('*'):
                system(f"rm {fname}")

        return

    def setUp(self) -> None:
        self.cleanup()
        return

    def tearDown(self) -> None:
        self.cleanup()
        return

    def test_ecc_keys_are_not_present_on_machine(self) -> None:
        """
        Testing the constructor in the case that ECC key files are not present on the machine at all.
        Expects all asymmetric key member variables to have values (freshly generated).
        """
        crypto: P2PCrypto = P2PCrypto(self.INVALID_FILENAME, self.INVALID_FILENAME, save_generated_key=False)
        self.assertIsNotNone(crypto._pubkey)
        self.assertIsNotNone(crypto._privkey)

        return

    def test_valid_ecc_keys_are_present_on_machine(self) -> None:
        """
        Testing the constructor in the case that ECC key files are present and are valid.
        Expects all asymmetric key member variables to have values (loaded).
        """
        P2PCrypto(self.VALID_PUBKEY_FILENAME, self.VALID_PRIVKEY_FILENAME)
        crypto: P2PCrypto = P2PCrypto(self.VALID_PUBKEY_FILENAME, self.VALID_PRIVKEY_FILENAME)
        self.assertIsNotNone(crypto._pubkey)
        self.assertIsNotNone(crypto._privkey)

        return

    def test_invalid_ecc_keys_are_present_on_machine(self) -> None:
        """
        Testing the constructor in the case that ECC key files are present but are invalid.
        Expects all asymmetric key member variables to have values (freshly generated).
        """
        P2PCrypto(self.VALID_PUBKEY_FILENAME, self.VALID_PRIVKEY_FILENAME)
        system(f"rm {self.VALID_PRIVKEY_FILENAME}")
        crypto: P2PCrypto = P2PCrypto(self.VALID_PUBKEY_FILENAME, self.VALID_PRIVKEY_FILENAME)
        self.assertIsNotNone(crypto._pubkey)
        self.assertIsNotNone(crypto._privkey)

        return

    def test_aes_key_is_generated_first_time(self) -> None:
        """
        Testing the generation of a fresh symmetric key.
        Expects no errors, and the symmetric key member variable should be populated.
        """
        crypto: P2PCrypto = P2PCrypto(self.INVALID_FILENAME, self.INVALID_FILENAME, save_generated_key=False)
        crypto.gen_symkey()
        self.assertIsNotNone(crypto._symkey_cipher)

        return

    def test_aes_key_is_set_when_one_is_present(self) -> None:
        """
        Testing the symmetric key generation function call when one is already present.
        Expects a SymmetricKeyExists exception to be thrown, and the old symmetric cipher should not be different.
        """
        crypto: P2PCrypto = P2PCrypto(self.INVALID_FILENAME, self.INVALID_FILENAME, save_generated_key=False)
        symkey, nonce = crypto.gen_symkey()

        with self.assertRaises(P2PCrypto.SymmetricKeyExists) as _:
            crypto.set_symkey(symkey, nonce)

        return

    def test_sent_aes_key_cipher_matches_local_cipher(self) -> None:
        """
        Testing that the generated symmetric key and iv cipher matches the one created by the receiver.
        Expects them to have the same attributes.
        """
        crypto: P2PCrypto = P2PCrypto(self.INVALID_FILENAME, self.INVALID_FILENAME, save_generated_key=False)
        symkey, nonce = crypto.gen_symkey()
        receiver: P2PCrypto = P2PCrypto(self.INVALID_FILENAME, self.INVALID_FILENAME, save_generated_key=False)
        receiver.set_symkey(symkey, nonce)

        return

# includes encryption under peer's public key, and signing then encrypting with symmetric
class TestEncryption(unittest.TestCase):
    MSG: bytes = b"HELLO!"
    PLACEHOLDER: bytes = b"123"
    INVALID_FILENAME: str = "THIS_FILE_DOES_NOT_EXIST"

    def test_encryption_with_peer_public_key(self) -> None:
        """
        Testing the encryption and decryption functionality of the ECC library.
        Expects a private key to decrypt the original message without issue.
        """
        send: P2PCrypto = P2PCrypto(self.INVALID_FILENAME, self.INVALID_FILENAME, save_generated_key=False)
        recv: P2PCrypto = P2PCrypto(self.INVALID_FILENAME, self.INVALID_FILENAME, save_generated_key=False)

        send.set_peer_pubkey(recv.get_own_pubkey())
        ciphertext: bytes = send.encrypt_with_peer_pubkey(self.MSG)
        plaintext: bytes = recv.decrypt_with_privkey(ciphertext)

        self.assertEqual(plaintext, self.MSG)
        return

    def test_encryption_without_peer_public_key(self) -> None:
        """
        Testing the encryption of a message without a public key set.
        Expects MissingPeerPubkey to be thrown and nothing else modified.
        """
        send: P2PCrypto = P2PCrypto(self.INVALID_FILENAME, self.INVALID_FILENAME, save_generated_key=False)
        ciphertext: bytes = self.PLACEHOLDER

        with self.assertRaises(P2PCrypto.MissingPeerPubkey) as _:
            ciphertext = send.encrypt_with_peer_pubkey(self.MSG)

        self.assertEqual(ciphertext, self.PLACEHOLDER)
        return

    def test_encryption_and_signing_without_private_key(self) -> None:
        """
        Testing the encryption of a message without a private key set.
        Expects MissingOwnPrivkey to be thrown and nothing else modified.
        """
        send: P2PCrypto = P2PCrypto(self.INVALID_FILENAME, self.INVALID_FILENAME, save_generated_key=False)
        send._privkey = None
        recv: P2PCrypto = P2PCrypto(self.INVALID_FILENAME, self.INVALID_FILENAME, save_generated_key=False)
        send.set_peer_pubkey(recv.get_own_pubkey())
        ciphertext: bytes = self.PLACEHOLDER

        send.gen_symkey()
        with self.assertRaises(P2PCrypto.MissingOwnPrivkey) as _:
            ciphertext = send.sign_then_encrypt(self.MSG)

        self.assertEqual(ciphertext, self.PLACEHOLDER)
        return

    def test_encryption_and_signing_without_symmetric_key(self) -> None:
        """
        Testing the encryption of a message without a symmetric key set.
        Expects MissingSymmetricKey to be thrown and nothing else modified.
        """
        send: P2PCrypto = P2PCrypto(self.INVALID_FILENAME, self.INVALID_FILENAME, save_generated_key=False)
        recv: P2PCrypto = P2PCrypto(self.INVALID_FILENAME, self.INVALID_FILENAME, save_generated_key=False)
        send.set_peer_pubkey(recv.get_own_pubkey())
        ciphertext: bytes = self.PLACEHOLDER

        with self.assertRaises(P2PCrypto.MissingSymmetricKey) as _:
            ciphertext = send.sign_then_encrypt(self.MSG)

        self.assertEqual(ciphertext, self.PLACEHOLDER)
        return

    def test_encryption_and_signing_with_all_keys(self) -> None:
        """
        Testing the usage of the sign and encrypt functionality.
        Expects nothing to happen.
        """
        send: P2PCrypto = P2PCrypto(self.INVALID_FILENAME, self.INVALID_FILENAME, save_generated_key=False)
        recv: P2PCrypto = P2PCrypto(self.INVALID_FILENAME, self.INVALID_FILENAME, save_generated_key=False)

        symkey, nonce = send.gen_symkey()
        recv.set_peer_pubkey(send.get_own_pubkey())
        send.set_peer_pubkey(recv.get_own_pubkey())
        ciphertext: bytes = send.sign_then_encrypt(self.MSG)

        self.assertIsNotNone(ciphertext)
        return

# includes decryption of signed and encrypted message, and decryption with a private key
class TestDecryption(unittest.TestCase):
    MSG: bytes = b"THIS IS A MESSAGE"
    INVALID_FILENAME: str = "THIS_FILE_DOES_NOT_EXIST"

    def test_decryption_of_bundle_with_integrity(self) -> None:
        """
        Testing for if a message is sent from one party to the other,
        and it is verified to be integrous.
        Expects nothing.
        """
        sender: P2PCrypto = P2PCrypto(self.INVALID_FILENAME, self.INVALID_FILENAME, save_generated_key=False)
        receiver: P2PCrypto = P2PCrypto(self.INVALID_FILENAME, self.INVALID_FILENAME, save_generated_key=False)

        sender.set_peer_pubkey(receiver.get_own_pubkey())
        receiver.set_peer_pubkey(sender.get_own_pubkey())
        symkey, nonce = sender.gen_symkey()
        receiver.set_symkey(symkey, nonce)

        ciphertext: bytes = sender.sign_then_encrypt(self.MSG)
        plaintext: bytes = b""

        try:
            plaintext = receiver.decrypt_and_verify(plaintext)
        except P2PCrypto.DataIsNotIntegrous as err:
            self.fail("Failed to decrypt.")

        self.assertEqual(self.MSG, plaintext)

        return

    def test_decryption_of_bundle_without_integrity(self) -> None:
        """
        Testing for if the message has been tampered with in transit.
        Expects a DataIsNotIntegrous exception.
        """
        sender: P2PCrypto = P2PCrypto(self.INVALID_FILENAME, self.INVALID_FILENAME, save_generated_key=False)
        receiver: P2PCrypto = P2PCrypto(self.INVALID_FILENAME, self.INVALID_FILENAME, save_generated_key=False)

        sender.set_peer_pubkey(receiver.get_own_pubkey())
        receiver.set_peer_pubkey(sender.get_own_pubkey())
        symkey, nonce = sender.gen_symkey()
        receiver.set_symkey(symkey, nonce)

        ciphertext: bytes = sender.sign_then_encrypt(self.MSG)

        # tampering with the data
        decrypted_halfway: bytes = receiver.decrypt_with_privkey(ciphertext)
        decrypted_halfway += b"jhgerfj"
        ciphertext = sender.encrypt_with_peer_pubkey(decrypted_halfway)
        plaintext: bytes = b""

        with self.assertRaises(P2PCrypto.DataIsNotIntegrous) as _:
            receiver.decrypt_and_verify(ciphertext)

        return

if __name__ == "__main__":
    unittest.main()
