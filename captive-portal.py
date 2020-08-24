#!/usr/bin/env python3

from aiohttp import web
from asyncio import sleep, subprocess, gather, Lock, shield
from collections import OrderedDict
import argparse
import ast
import json
import logging
import os
import re
import sys

if sys.version_info.major == 3 and sys.version_info.minor < 7:
    from asyncio import ensure_future as create_task
else:
    from asyncio import create_task

IWLIST_NETWORKS = re.compile(r"^\s+Cell", re.M)
IWLIST_KEYS = re.compile(r"^\s*(\S[^:\n]*):(.+)", re.M)
# NOTE: ip -br -j addr # -j is not supported on Debian Stretch! :(
IP_ADDR = re.compile(r"^(\w+)\s+\S+\s+(\S.*) ", re.M)


async def start_ap():
    async with app["lock"]:
        logger.info("Starting access point...")
        await kill_daemons()
        await run_check("ip", "link", "set", "{if}", "down")
        await run_check("ip", "link", "set", "{if}", "up")
        await clear_ip()
        await run_check("ip", "addr", "add", "192.168.1.1", "dev", "{if}")
        await run_daemon("hostapd", "/etc/hostapd/hostapd.conf")
        await run_daemon(
            "dnsmasq",
            "-i",
            "{if}",
            "-d",
            "-R",
            "-F",
            "192.168.1.1,192.168.1.32,255.255.255.0",
            "-A",
            "/#/192.168.1.1",
        )
        await run_daemon("nginx", "-g", "daemon off; error_log stderr;")
        logger.info("Access point started successfully.")
        app["portal"].set(True)


async def list_networks():
    try:
        async with app["lock"]:
            logger.info("Getting networks...")
            if app["portal"]:
                await kill_daemons()
            await run_check("ip", "link", "set", "{if}", "up")
            output = await run_capture_check("iwlist", "{if}", "scan")
            networks = [
                {x[0]: x[1]
                for x in IWLIST_KEYS.findall(output)} for output in IWLIST_NETWORKS.split(output)
                if "ESSID" in output
            ]
            networks = [
                (
                ast.literal_eval(section["ESSID"]),
                section["Encryption key"] == "on",
                ) for section in networks
            ]
            logger.info("Networks received successfully.")
    finally:
        if app["portal"]:
            create_task(start_ap())
    return networks


async def get_ip_addresses():
    output = await run_capture_check("ip", "-br", "addr")
    interfaces = {ifname: addr_info.split(" ") for (ifname, addr_info) in IP_ADDR.findall(output)}
    return interfaces.get(app["interface"], [])


async def clear_ip():
    addr_info = await get_ip_addresses()
    for ip in addr_info:
        await run_check("ip", "addr", "del", ip, "dev", "{if}")


async def check_ip_status():
    addr_info = await get_ip_addresses()
    return len(addr_info) > 0


async def connect(essid, password):
    try:
        async with app["lock"]:
            await kill_daemons()
            await run_check("ip", "link", "set", "{if}", "down")
            await clear_ip()
            await run_check("ip", "link", "set", "{if}", "up")
            if password is not None:
                output = await run_capture_check(
                    "wpa_passphrase",
                    essid,
                    password,
                )
                with open("/run/%s.conf" % app["interface"], "wt") as fh:
                    fh.write(output)
                await run_daemon(
                    "wpa_supplicant",
                    "-i",
                    "{if}",
                    "-D",
                    "nl80211,wext",
                    "-c",
                    "/run/{if}.conf",
                )
            else:
                await run_check("iwconfig", "{if}", "essid", essid)
                await run_check("iwconfig", "{if}", "ap", "any")
            await run_daemon("dhclient", "{if}", "-d")
            logger.info("Checking if connection is ready...")
            for _ in range(4):
                if await check_ip_status():
                    logger.info("Connection succeeded.")
                    break
                await sleep(2)
            else:
                logger.info(
                    "The connection to the WiFi did not succeed in the allowed amount of time"
                )
                raise Exception("Could not connect to network.")
            app["portal"].set(False)
    except Exception:
        await start_ap()
        raise


# daemon management


async def run_daemon(*cmd, **format_args):
    name = cmd[0]
    await stop_daemon(name)
    proc = app["daemons"][name] = await run_proc(cmd, format_args, {})
    await sleep(1)
    if proc.returncode is not None:
        raise Exception("daemon execution failed (exit status: %s): %s" % (proc.returncode, cmd))
    return proc


async def stop_daemon(name):
    if name not in app["daemons"]:
        return
    proc = app["daemons"].pop(name)
    if proc.returncode is not None:
        return
    logger.info("Terminating process %s..." % name)
    proc.terminate()
    await sleep(2)
    if proc.returncode is None:
        logger.info("Killing process %s..." % name)
        proc.kill()
    logger.info("Waiting process %s..." % name)
    await proc.wait()


async def kill_daemons():
    daemons = list(reversed(app["daemons"].keys()))
    if daemons:
        logger.debug("Killing daemons...")
    else:
        logger.debug("No daemon to kill.")
        return
    await gather(
        *[stop_daemon(name) for name in daemons],
        return_exceptions=True,
    )
    if daemons:
        logger.debug("Killing daemons completed.")


# process management


async def run_proc(cmd, format_args, subprocess_args):
    format_args.update({
        "if": app["interface"],
    })
    cmd = [x.format_map(format_args) for x in cmd]
    logger.debug("Running command: %s", cmd)
    return await subprocess.create_subprocess_exec(*cmd, **subprocess_args)


async def run_check(*cmd, **format_args):
    proc = await run_proc(cmd, format_args, {})
    rc = await proc.wait()
    if rc != 0:
        raise Exception("command execution failed (exit status != 0): %s" % (cmd, ))


async def run_capture_check(*cmd, **format_args):
    proc = await run_proc(cmd, format_args, {"stdout": subprocess.PIPE})
    rc = await proc.wait()
    if rc != 0:
        raise Exception("command execution failed (exit status != 0): %s" % (cmd, ))
    stdout = await proc.stdout.read()
    return stdout.decode("utf8")


###################################################################################################


async def route_start_ap(_request):
    if not app["portal"]:
        await shield(start_ap())
    return web.Response(text="OK")


async def route_connect(request):
    try:
        await shield(connect(request.query["essid"], request.query.get("password")))
        return web.Response(text="OK")
    except KeyError as exc:
        return web.Response(text="Missing query key essid or password!", status=400)


async def route_list_networks(_request):
    networks = await shield(list_networks())
    data = [
        {
        "essid": essid,
        "password": password,
        } for (essid, password) in dict(networks).items()
    ]
    return web.json_response(data)


async def route_ap(_request):
    return web.json_response(app["portal"].get())


async def start_ap_on_startup(app):
    create_task(start_ap())


async def kill_daemons_on_cleanup(app):
    async with app["lock"]:
        await kill_daemons()


async def shutdown_interface(app):
    logger.debug("Shutting down interface...")
    await run_check("ifconfig", "{if}", "down")


class Container:
    """
    Help against the deprecation warning when storing a value in `app` and re-assigning during
    execution
    """
    def __init__(self, value):
        self.value = value

    def __bool__(self):
        return bool(self.value)

    def set(self, value):
        self.value = value

    def get(self):
        return self.value


logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("captive-portal")
app = web.Application()
app.on_startup.append(start_ap_on_startup)
app.on_cleanup.append(kill_daemons_on_cleanup)
app.on_cleanup.append(shutdown_interface)
app["daemons"] = OrderedDict()
app["lock"] = Lock()
app["portal"] = Container(False)
app.add_routes([web.get("/start-ap", route_start_ap)])
app.add_routes([web.get("/list-networks", route_list_networks)])
app.add_routes([web.get("/connect", route_connect)])
app.add_routes([web.get("/portal", route_ap)])

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
    "--debug",
    action="store_true",
    help="show debug logs",
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

    if args.debug:
        logger.setLevel(logging.DEBUG)

    app["interface"] = args.interface

    web.run_app(
        app,
        host=args.host,
        port=args.port,
        path=args.unix,
    )
else:
    if "INTERFACE" not in os.environ:
        print("Missing `INTERFACE` in environment variables.", file=sys.stderr)
        print("Example: INTERFACE=wlan0 pipenv run dev", file=sys.stderr)
        sys.exit(1)

    logger.setLevel(logging.DEBUG)

    # development mode
    app["interface"] = os.environ["INTERFACE"]
