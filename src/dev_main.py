import asyncio as asy
from argparse import ArgumentParser, Namespace
from p2pfileserver import P2PFileServer
from socket import gethostbyname, gethostname

async def main() -> None:
    parser: ArgumentParser = ArgumentParser()
    local_ip_addr: str = gethostbyname(gethostname())
    parser.add_argument("-lA", "--local-address", type=str, default=local_ip_addr, help="The address to host on.")
    parser.add_argument("-rA", "--remote-address", type=str, default="127.0.0.1", help="The address to connect to.")
    parser.add_argument("-lP", "--local-port", type=int, default=0, help="The port to host on.")
    parser.add_argument("-rP", "--remote-port", type=int, default=0, help="The port to connect to.")
    parser.add_argument("-pK", "--public-key-path", type=str, default="pub.key", help="The path to the public key.")
    parser.add_argument("-sK", "--secret-key-path", type=str, default="priv.key", help="The path to the private key.")
    args: Namespace = parser.parse_args()

    peer: P2PFileServer = P2PFileServer(args.public_key_path, args.secret_key_path, server_ip=args.local_address, server_port=args.local_port)

    # start client before server
    if args.remote_port:
        is_connected: bool = await peer.connect_to(args.remote_address, remote_port=args.remote_port)
        if not is_connected:
            print("Failed to connect to that remote address.")
        # await peer.send("Hello!")
        # await peer.broadcast("Hello!")

    # blocking call
    peer.start_server()
    return

if __name__ == "__main__":
    asy.run(main())
