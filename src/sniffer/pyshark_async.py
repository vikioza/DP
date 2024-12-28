import asyncio
import threading
import aiologic
import pyshark

# local import
from config import Interfaces


async def async_func(queue: aiologic.SimpleQueue) -> None:
    while True:
        print("running")
        packet = await queue.async_get()
        print(packet)


def capture_packets_threaded(queue: aiologic.SimpleQueue, loop: asyncio.BaseEventLoop):
    print("capture called")
    interface = Interfaces.ETHERNET
    print("init live capture")
    capture = pyshark.LiveCapture(interface=interface, use_ek=True, eventloop=loop)
    print("starting live capture")
    queue.put(next(capture.sniff_continuously()))


def run_loop(loop):
    asyncio.set_event_loop(loop)
    loop.run_forever()


if __name__ == "__main__":
    try:
        print("queue")
        queue = aiologic.SimpleQueue()
        print("event_loop")
        event_loop = asyncio.new_event_loop()
        print("thread start")
        threading.Thread(target=lambda: run_loop(event_loop)).start()
        print("loop call")
        event_loop.call_soon_threadsafe(
            lambda: capture_packets_threaded(queue, event_loop)
        )
        # threading.Thread(target=sniffer.capture_packets_threaded).start()
        print("asyncio run")
        asyncio.run(async_func(queue))
    except KeyboardInterrupt:
        print("Interrupted by User")
    # finally:
    #     event_loop.call_soon_threadsafe(event_loop.stop)
