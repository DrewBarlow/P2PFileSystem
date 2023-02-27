import asyncio as asy
from constants import ACK, HOST_IP_ADDR, HOST_PORT, READ_SIZE
from p2pcrypto import P2PCrypto 
from typing import Any

async def main() -> None:
    async def cb(reader: asy.StreamReader, writer: asy.StreamWriter) -> None:
        print(f"Client connected from {reader._transport.get_extra_info('socket').getpeername()}.")
        crypto: P2PCrypto = P2PCrypto("dne.key", "dne.key", save_generated_key=False)

        # get peer pubkey
        peer_pubkey: bytes = await reader.read(READ_SIZE)
        crypto.set_peer_pubkey(peer_pubkey)

        # send own pubkey
        writer.write(crypto.get_own_pubkey())
        await writer.drain()

        # establish session key
        ciphertext: bytes = await reader.read(READ_SIZE)
        symkey_and_nonce: bytes = crypto.decrypt_with_privkey(ciphertext)
        crypto.set_symkey(symkey_and_nonce[:-16], symkey_and_nonce[-16:])

        # send ack
        writer.write(crypto.sign_then_encrypt(ACK))
        await writer.drain()
        
        writer.close()
        await writer.wait_closed()
        return

    server: asy.base_events.Server = await asy.start_server(cb, host=HOST_IP_ADDR, port=HOST_PORT)
    async with server:
        print("Server is running!")
        try:
            await server.serve_forever()
        finally:
            print("Closing sockets.")
            await server.wait_closed()

    return

if __name__ == "__main__":
    asy.run(main())
