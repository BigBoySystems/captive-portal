#!/usr/bin/env python3

from aiohttp import web
import argparse
import sys

async def handle(request):
    name = request.match_info.get('name', "Anonymous")
    text = "Hello, " + name
    return web.Response(text=text)

app = web.Application()
app.add_routes([web.get('/', handle),
                web.get('/{name}', handle)])

parser = argparse.ArgumentParser(
    description='A captive portal service for the thingy'
)
parser.add_argument('--unix', type=str,
                    help='open the server on a UNIX socket')
parser.add_argument('--host', type=str,
                    help='open the server on a TCP/IP host')
parser.add_argument('--port', type=int,
                    help='open the server on a TCP/IP port')

if __name__ == '__main__':
    args = parser.parse_args()

    if args.unix is None and (args.host is None or args.port is None):
        print(
            "You must at least provide the UNIX socket or the TCP/IP host "
            "and port."
        )
        sys.exit(1)

    web.run_app(
        app,
        host=args.host,
        port=args.port,
        path=args.unix,
    )
