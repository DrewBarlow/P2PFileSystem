from argparse import ArgumentParser, Namespace
from multiprocessing import Process
from os import system
from typing import Callable, Iterable, List

SERVER_FILE: str = "./server.py"
CLIENT_FILE: str = "./client.py"

def main() -> None:
    parser: ArgumentParser = ArgumentParser()
    parser.add_argument("-n", "--num-clients", type=int, default=3, help="Number of clients to spin up.")
    args: Namespace = parser.parse_args()

    fmt_args: Callable[[str], Iterable[str]] = lambda fname: (f"python3 {fname}",)
    server: Process = Process(target=system, args=fmt_args(SERVER_FILE))
    clients: List[Process] = [Process(target=system, args=fmt_args(CLIENT_FILE)) for _ in range(args.num_clients)]
    
    server.start()
    for client in clients:
        client.start()

    for client in clients:
        client.join()

    server.terminate()
    return

if __name__ == "__main__":
    main()
