import asyncio as asy
from collections.abc import Coroutine
from .constants import TIMEOUT_SECONDS
from functools import wraps
from typing import Any, Tuple

def gen_ref_key(laddr: str, raddr: str) -> str:
    return f"{laddr}?{raddr}"

def keyify_from_tuple(addr: Tuple[str, int]) -> str:
    return f"{addr[0]}_{addr[1]}"

async def wait_for(coro: Coroutine[Any, Any, Any]) -> Any:
    return await asy.wait_for(coro, timeout=TIMEOUT_SECONDS)

def wait_for_wrapper() -> Any:
    def wrapper(coro: Any) -> Any:
        @wraps(coro)
        async def wrapped(*args: Any, **kwargs: Any) -> Any:
            return await wait_for(coro(*args, **kwargs))
        return wrapped
    return wrapper

