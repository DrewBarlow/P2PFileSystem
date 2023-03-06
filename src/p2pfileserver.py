import asyncio as asy
from collections.abc import Coroutine
from concurrent.futures._base import Future
from functools import wraps
from p2pcrypto import P2PCrypto
from sys import stdout
from threading import Thread
from typing import Any, Dict, List, Optional, Tuple, Union
from util.constants import ACK, IO_SIZE_BYTES, LOOPBACK, P2P_SERVER_PORT
from util.functional import gen_ref_key, keyify_from_tuple, wait_for, wait_for_wrapper

class P2PFileServer:
    # connection or session already exists
    class ConnectionAlreadyEstablished(Exception): pass
    class AttemptedDuplicateConnection(Exception): pass
    
    # generic failed to connect error
    class FailedToOpenStreams(Exception): pass

    # cryptography failure
    class FailedToEstablishCrypto(Exception): pass

    __SERVER_KEY: str = "__SERVER__"
    __CLIENT_KEY: str = "__CLIENT__"
    __READ_KEY: str = "__STREAM_READER__"
    __WRITE_KEY: str = "__STREAM_WRITER__"
    __CRYPTO_KEY: str = "__CRYPTOGRAPHY__"

    def __init__(self, pubkey_path: str, privkey_path: str, /, *, server_ip: str=LOOPBACK, server_port: int=P2P_SERVER_PORT) -> None:
        self._pubkey_path: str = pubkey_path
        self._privkey_path: str = privkey_path
        self.__local_ip: str = server_ip
        self.__local_port: int = server_port
        self.__network: Dict[str, Dict[str, Union[asy.StreamReader, asy.StreamWriter, P2PCrypto]]] = {}

        return

    # starts a server on this machine
    def start_server(self) -> None:
        def start_background_loop(new_loop: asy.AbstractEventLoop) -> None:
            asy.set_event_loop(new_loop)
            new_loop.run_forever()

        loop = asy.new_event_loop()
        thread: Thread = Thread(target=start_background_loop, args=(loop,), daemon=True)
        thread.start()

        task: Future = asy.run_coroutine_threadsafe(self.__start_server(), loop)

        inp = input(">> ")
        while inp != "stop":
            if inp == "info":
                print(self.__network)

            inp = input(">> ")

        loop.stop()
        return

    async def __start_server(self) -> None:
        server: asy.base_events.Server = await asy.start_server(self.__callback, self.__local_ip, self.__local_port)

        try:
            print("Server is up!")
            await server.serve_forever()
        finally:
            await server.wait_closed()
            print("Server is closed.")

        return

    # joins the network attached to the supplied remote ip
    @wait_for_wrapper()
    async def connect_to(self, remote_ip: str, /, *, remote_port: int=P2P_SERVER_PORT) -> bool:
        try:
            # attempt to connect to the peer's server
            reader, writer = await wait_for(asy.open_connection(remote_ip, remote_port))
            if reader is None or writer is None:
                raise self.FailedToOpenStreams("Failed to open IO streams to remote host.")

            crypto: P2PCrypto = await self.__establish_client_session(reader, writer)
            peer_port: int = await self.__get_peer_port_client(crypto, reader, writer)

            # session_ref_key: laddr_key?raddr_key
            session_ref_key, _ = self.__get_socket_keys(reader, peer_port, is_server=False)
            if not self.__add_network_entry(session_ref_key, self.__CLIENT_KEY, reader, writer, crypto):
                return False

        except ConnectionRefusedError as e:
            return False

        return True

    async def __callback(self, reader: asy.StreamReader, writer: asy.StreamWriter) -> None:
        crypto: P2PCrypto = await self.__establish_server_session(reader, writer)
        peer_host_port: int = await self.__get_peer_port_server(crypto, reader, writer)

        # session_ref_key: raddr_key?laddr_key
        session_ref_key, peer_ip = self.__get_socket_keys(reader, peer_host_port)
        addr: str = f"{peer_ip}:{peer_host_port}"
        if not self.__add_network_entry(session_ref_key, self.__SERVER_KEY, reader, writer, crypto):
            await self.multicast(addr, exclude=(session_ref_key))
            return

        print(f"Client connected from {peer_ip}:{peer_host_port}")
        await asy.sleep(0.01)
        await self.connect_to(peer_ip, remote_port=peer_host_port)

        def cb(task: asy.Task) -> None:
            try:
                ip, port = task.result().decode().split(':')
                loop: asy.AbstractEventLoop = asy.get_event_loop()
                asy.run_coroutine_threadsafe(self.connect_to(ip, remote_port=int(port)), loop)
            except: pass
            return

        future = asy.ensure_future(reader.read(IO_SIZE_BYTES))
        future.add_done_callback(cb)

        return

    def __get_socket_keys(self, stream: Union[asy.StreamReader, asy.StreamWriter], peer_port: int, /, *, is_server: bool=False) -> Tuple[str, str]:
        peer_ip: str = stream._transport.get_extra_info("socket").getpeername()[0]
        raddr_key: str = keyify_from_tuple((peer_ip, peer_port))
        laddr_key: str = keyify_from_tuple((self.__local_ip, self.__local_port))
        session_ref_key: str = ""

        if not is_server:
            session_ref_key = gen_ref_key(laddr_key, raddr_key)
        else:
            session_ref_key = gen_ref_key(raddr_key, laddr_key)
        
        return session_ref_key, peer_ip

    def __add_network_entry(self, ref_key: str, srv_cli_key: str, reader: asy.StreamReader, writer: asy.StreamWriter, crypto: P2PCrypto) -> bool:
        if self.__network.get(ref_key) is not None:
            if self.__network[ref_key].get(srv_cli_key) is not None:
                return False
        else:
            self.__network[ref_key] = {}

        self.__network[ref_key][srv_cli_key] = {
            self.__READ_KEY: reader,
            self.__WRITE_KEY: writer,
            self.__CRYPTO_KEY: crypto
        }
        return True

    @wait_for_wrapper()
    async def __get_peer_port_server(self, crypto: P2PCrypto, reader: asy.StreamReader, writer: asy.StreamWriter) -> int:
        ciphertext: bytes = await wait_for(reader.read(IO_SIZE_BYTES))
        peer_port: int = int(crypto.decrypt_and_verify(ciphertext).decode())

        port_bytes: bytes = str(self.__local_port).encode()
        writer.write(crypto.sign_then_encrypt(port_bytes))
        await wait_for(writer.drain())

        return peer_port

    @wait_for_wrapper()
    async def __get_peer_port_client(self, crypto: P2PCrypto, reader: asy.StreamReader, writer: asy.StreamWriter) -> int:
        port_bytes: bytes = str(self.__local_port).encode()
        writer.write(crypto.sign_then_encrypt(port_bytes))
        await wait_for(writer.drain())

        ciphertext: bytes = await wait_for(reader.read(IO_SIZE_BYTES))
        peer_port: int = int(crypto.decrypt_and_verify(ciphertext).decode())

        return peer_port

    @wait_for_wrapper()
    async def __establish_client_session(self, reader: asy.StreamReader, writer: asy.StreamWriter) -> P2PCrypto:
        crypto: P2PCrypto = P2PCrypto(self._pubkey_path, self._privkey_path, save_generated_key=False)

        # send pubkey
        writer.write(crypto.get_own_pubkey())
        await wait_for(writer.drain())

        # get peer pubkey
        peer_pubkey: bytes = await wait_for(reader.read(IO_SIZE_BYTES))
        crypto.set_peer_pubkey(peer_pubkey)

        # generate symkey and nonce
        symkey, nonce = crypto.gen_symkey()
        writer.write(crypto.encrypt_with_peer_pubkey(symkey + nonce))
        await wait_for(writer.drain())

        # receive and verify ACK
        ciphertext: bytes = await wait_for(reader.read(IO_SIZE_BYTES))
        plaintext: bytes = crypto.decrypt_and_verify(ciphertext)
        
        if plaintext != ACK:
            raise self.FailedToEstablishCrypto("Could not establish a secure session with that host.")

        return crypto

    @wait_for_wrapper()
    async def __establish_server_session(self, reader: asy.StreamReader, writer: asy.StreamWriter) -> P2PCrypto:
        crypto: P2PCrypto = P2PCrypto(self._pubkey_path, self._privkey_path, save_generated_key=False)
        
        # get peer pubkey
        peer_pubkey: bytes = await wait_for(reader.read(IO_SIZE_BYTES))
        crypto.set_peer_pubkey(peer_pubkey)

        # send pubkey
        writer.write(crypto.get_own_pubkey())
        await wait_for(writer.drain())

        # receive symmetric key
        ciphertext: bytes = await wait_for(reader.read(IO_SIZE_BYTES))
        symkey_and_nonce: bytes = crypto.decrypt_with_privkey(ciphertext)
        crypto.set_symkey(symkey_and_nonce[:-16], symkey_and_nonce[-16:])

        # send signed ACK
        writer.write(crypto.sign_then_encrypt(ACK))
        await wait_for(writer.drain())

        return crypto

    # does not work yet
    @wait_for_wrapper()
    async def multicast(self, msg: str, /, *, exclude: Optional[Tuple[str]]=None) -> None:
        for key, session_info in self.__network.items():
            if key == exclude: continue
            session_info[self.__CLIENT_KEY][self.__WRITE_KEY].write(msg.encode())
            await session_info[self.__CLIENT_KEY][self.__WRITE_KEY].drain()

        return


