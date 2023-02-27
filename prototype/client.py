import asyncio as asy
from constants import ACK, HOST_IP_ADDR, HOST_PORT, READ_SIZE
from p2pcrypto import P2PCrypto

async def main() -> None:
    reader, writer = await asy.open_connection(HOST_IP_ADDR, HOST_PORT)
    crypto: P2PCrypto = P2PCrypto("dne.key", "dne.key", save_generated_key=False)

    # send own pubkey
    writer.write(crypto.get_own_pubkey())
    await writer.drain()

    # get peer pubkey
    peer_pubkey: bytes = await reader.read(READ_SIZE)
    crypto.set_peer_pubkey(peer_pubkey)

    # generate symmetric key
    symkey, nonce = crypto.gen_symkey()
    writer.write(crypto.encrypt_with_peer_pubkey(symkey + nonce))
    await writer.drain()
    #print(crypto._symkey)

    # receive acknowledgement
    ciphertext: bytes = await reader.read(READ_SIZE)
    plaintext: bytes = crypto.decrypt_and_verify(ciphertext)
    assert(plaintext == ACK)

    writer.close()
    await writer.wait_closed()
    return

if __name__ == "__main__":
    asy.run(main())
