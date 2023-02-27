### Cryptography API
#### Dependencies
  * PyCryptodome (3.17)
  * eciespy

#### What is Used?
  * Elliptic-Curve Integrated Encryption Scheme (secp256k1)
  * AES-256-GCM
      * Block Size: 16 bytes
  * SHA256

#### Important Functions
  * `P2PCrypto.sign_then_encrypt(plaintext: bytes) -> bytes`:  
      * Encrypts the plaintext under the AES symmetric key.  
      * Hashes the encrypted plaintext under SHA512.  
      * Concatenates the ciphertext and hash together to provide a signature.  
      * Returns the concatenated ciphertext under the symmetric key again.  
  * `P2PCrypto.decrypt_and_verify(ciphertext: bytes) -> bytes`: 
      * Decrypts the ciphertext and separates it into a digitial signature and data.  
      * Hashes the data and verifies that the provided hash matches it.
      * Decrypts the data and returns it.
  * `P2PCrypto.set_peer_pubkey(peer_pubkey_raw: bytes) -> bool`:
      * Initializes the peer's public ECC key for this session.
      * Returns true if successful. false otherwise.
  * `P2PCrypto.get_peer_pubkey() -> bytes`:
      * Returns the peer's public key as bytes.
  * `P2PCrypto.get_own_pubkey() -> bytes`:
      * Returns own public key as bytes.
  * `P2PCrypto.set_symkey(symkey: bytes, nonce: bytes) -> bool`:
      * Initializes the AES symmetric key for this session.
      * Can only be called once per object. This should NOT be used if `gen_symkey()` is used for this object.
      * Returns True if successful. False otherwise.
  * `P2PCrypto.gen_symkey() -> Tuple[bytes, bytes]`:
      * Generated a new AES symmetric key and nonce, initializes them for this object, and returns them.
      * Can only be called once per object. This should NOT be used if `set_symkey()` is used for this object.
  * `P2PCrypto.encrypt_with_peer_pubkey(plaintext: bytes) -> bytes`:
      * Encrypts the plaintext under the peer's public key.
  * `P2PCrypto.decrypt_with_privkey(ciphertext: bytes) -> bytes`:
      * Decrypts ciphertext encrypted under this peer's public key.

#### Sample Usage
```py
from p2pcrypto import P2PCrypto 

def interaction(peer1: P2PCrypto, peer2: P2PCrypto, msg: bytes) -> None:
    # encrypt a message and send it to the other peer
    ciphertext: bytes = peer1.sign_then_encrypt(msg)

    try:
        # decrypt and verify the received ciphertext
        print(peer2.decrypt_and_verify(ciphertext))
    except P2PCrypto.DataIsNotIntegrous:
        print("The integrity of the data cannot be verified.")
    
    return

def main() -> None:
    # instantiate P2PCrypto for each peer to load/generate asymmetric keys
    peer1: P2PCrypto = P2PCrypto("peer1_pubkey.key", "peer1_privkey.key")
    peer2: P2PCrypto = P2PCrypto("peer2_pubkey.key", "peer2_privkey.key")

    # assume public keys are initially sent over an insecure channel
    peer2.set_peer_pubkey(peer1.get_own_pubkey())
    peer1.set_peer_pubkey(peer2.get_own_pubkey())

    # generate a symmetric key and nonce, then send them (encrypted) to the peer
    symkey, nonce = peer1.gen_symkey()
    encrypted_symkey: bytes = peer1.encrypt_with_peer_pubkey(symkey + nonce)
    
    # decrypt the symmetric key and set it for this session
    decrypted_symkey_and_nonce = peer2.decrypt_with_privkey(encrypted_symkey)
    decrypted_symkey: bytes = decrypted_symkey_and_nonce[:-16]
    nonce: bytes = decrypted_symkey_and_nonce[-16:]
    peer2.set_symkey(decrypted_symkey, nonce)

    interaction(peer1, peer2, b"Hello!")
    interaction(peer2, peer1, b"Goodbye!")

    return

if __name__ == "__main__":
    main()
```
