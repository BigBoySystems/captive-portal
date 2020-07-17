#!/usr/bin/env python3

from aiohttp import web
from asyncio import sleep, subprocess
import argparse
import os
import sys


async def start_ap(request):
    await run_check("ifconfig {if} down")
    await run_daemon("hostapd", "hostapd /etc/hostapd/hostapd.conf")
    await run_check("ifconfig {if} up 192.168.1.1")
    await run_daemon(
        "dnsmasq", "dnsmasq -i {if} -d -R -F 192.168.1.2,192.168.1.32 -A /#/192.168.1.1"
    )
    return web.Response(text="")


# daemon management


async def run_daemon(name, cmd, **format_args):
    await stop_daemon(name)
    proc = app["daemons"][name] = await run_proc(cmd, **format_args)
    await sleep(1)
    if proc.returncode is not None:
        raise Exception("daemon execution failed (exit status: %s): %s" % (proc.returncode, cmd))
    return proc


async def stop_daemon(name):
    if name not in app["daemons"]:
        return
    proc = app["daemons"].pop(name)
    print("Terminating process %s..." % name)
    proc.terminate()
    await sleep(2)
    if proc.returncode is None:
        print("Killing process %s..." % name)
        proc.kill()
    print("Waiting process %s..." % name)
    await proc.wait()


async def kill_daemons(app):
    for name in list(app["daemons"].keys()):
        await stop_daemon(name)


# process management


async def run_proc(cmd, **format_args):
    format_args.update({
        "if": app["interface"],
    })
    cmd = cmd.format_map(format_args)
    return await subprocess.create_subprocess_shell(cmd)


async def run_check(cmd, **format_args):
    proc = await run_proc(cmd, **format_args)
    rc = await proc.wait()
    if rc != 0:
        raise Exception("command execution failed (exit status != 0): %s" % cmd)


###################################################################################################

app = web.Application()
app.on_cleanup.append(kill_daemons)
app["daemons"] = {}
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
    # production mode
    args = parser.parse_args()

    if args.unix is None and (args.host is None or args.port is None):
        print("You must at least provide the UNIX socket or the TCP/IP host " "and port.")
        sys.exit(1)

    app["interface"] = args.interface

    web.run_app(
        app,
        host=args.host,
        port=args.port,
        path=args.unix,
    )
else:
    # development mode
    app["interface"] = os.environ["INTERFACE"]
