import asyncio as asy
from constants import HOST_IP_ADDR, HOST_PORT 
from typing import Any

async def main() -> None:
    async def cb(reader: asy.StreamReader, writer: asy.StreamWriter) -> None:
        print("Client connected!")

        data: bytes = await reader.read(1028)
        print(f"Got: {data.decode()!r}")

        writer.close()
        await writer.wait_closed()

        return

    server: Any = await asy.start_server(cb, host=HOST_IP_ADDR, port=HOST_PORT)
    async with server:
        print("Server is running!")
        await server.serve_forever()

    return

if __name__ == "__main__":
    asy.run(main())
