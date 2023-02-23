import asyncio as asy
from constants import HOST_IP_ADDR, HOST_PORT

async def main() -> None:
    reader, writer = await asy.open_connection(HOST_IP_ADDR, HOST_PORT)
    
    msg: str = "some test message"
    print(f"Sending: {msg!r}")
    writer.write(msg.encode())
    await writer.drain()

    writer.close()
    await writer.wait_closed()

    return

if __name__ == "__main__":
    asy.run(main())
