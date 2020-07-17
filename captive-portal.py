#!/usr/bin/env python3

from aiohttp import web
from asyncio import subprocess
import argparse
import os
import sys

STATE = {}


async def start_ap(request):
    p = await subprocess.create_subprocess_shell("ifconfig %s down" % STATE["interface"])
    await p.wait()
    print(p.returncode)
    return web.Response(text="")


async def handle(request):
    name = request.match_info.get("name", "Anonymous")
    text = "Hello, " + name
    return web.Response(text=text)


app = web.Application()
app.add_routes([web.get("/start-ap", start_ap)])

parser = argparse.ArgumentParser(description="A captive portal service for the thingy")
parser.add_argument(
    "--unix",
    type=str,
    help="open the server on a UNIX socket",
)
parser.add_argument(
    "--host",
    type=str,
    help="open the server on a TCP/IP host",
)
parser.add_argument(
    "--port",
    type=int,
    help="open the server on a TCP/IP port",
)
parser.add_argument(
    "interface",
    type=str,
    help="WiFi interface",
)

if __name__ == "__main__":
    args = parser.parse_args()

    if args.unix is None and (args.host is None or args.port is None):
        print("You must at least provide the UNIX socket or the TCP/IP host " "and port.")
        sys.exit(1)

    STATE["interface"] = args.interface

    web.run_app(
        app,
        host=args.host,
        port=args.port,
        path=args.unix,
    )
else:
    STATE["interface"] = os.environ["INTERFACE"]
