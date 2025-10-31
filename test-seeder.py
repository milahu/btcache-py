#!/usr/bin/env python3

import os
import time
import logging
import argparse
import ipaddress
import socket

import libtorrent as lt

# seconds between alert checks / actions
POLL_INTERVAL = 1.0


# global state
logger = None


def get_logger():
    # Create a custom logger
    logger = logging.getLogger("btcache-seeder")
    logger.setLevel(logging.DEBUG)
    # Create console handler
    ch = logging.StreamHandler()
    ch.setLevel(logging.DEBUG)
    # Create formatter
    formatter = logging.Formatter(
        fmt="%(asctime)s.%(msecs)03d %(module)s %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )
    # Attach formatter to handler
    ch.setFormatter(formatter)
    # Attach handler to logger
    logger.addHandler(ch)
    return logger


def parse_args():
    parser = argparse.ArgumentParser(description="Hidden BitTorrent Seeder")
    # TODO if args.torrent is unset, generate a random test torrent
    parser.add_argument(
        "--torrent", # args.torrent
        required=True,
        help="Path to the .torrent file",
    )
    parser.add_argument(
        "--listen", # args.listen
        required=True,
        help="Listen address:port. example: 127.0.0.1:6881",
    )
    parser.add_argument(
        "--save", # args.save
        default="test-seeder-downloads",
        help="Folder where the torrent data is stored",
    )
    parser.add_argument(
        "--allowed-peers", # args.allowed_peers
        metavar="ADDR",
        nargs="+",
        help="List of allowed peers by IP address",
    )
    return parser.parse_args()


def main():
    global logger
    logger = get_logger()
    logger.info("starting")

    args = parse_args()

    settings = lt.default_settings()
    settings['listen_interfaces'] = args.listen
    # FIXME expose these as a CLI options
    settings['enable_upnp'] = False
    settings['enable_natpmp'] = False
    settings['enable_lsd'] = False
    settings['enable_dht'] = False
    settings['active_tracker_limit'] = 0 # disable trackers?
    # settings['allow_multiple_connections_per_ip'] = True # only needed in btcache

    # Create session
    ses = lt.session(settings)

    if args.allowed_peers:
        ses.set_ip_filter(get_ip_filter_of_allowed_peers(args.allowed_peers))

    # Load torrent info
    ti = lt.torrent_info(args.torrent)

    # Add torrent with auto_managed=False, paused=False
    atp = lt.add_torrent_params()
    atp.ti = ti
    atp.save_path = args.save
    # disable PEX to keep our hidden peers hidden
    atp.flags = atp.flags | lt.torrent_flags.disable_pex
    atp.flags &= ~lt.torrent_flags.auto_managed
    atp.flags &= ~lt.torrent_flags.paused  # start immediately
    atp.trackers = []  # no trackers

    th = ses.add_torrent(atp)

    logger.info(f"Listening on {args.listen}")

    try:
        while True:
            status = th.status()
            peers = th.get_peer_info()
            logger.info(f"Seeding torrent: btih={th.info_hash()} state={status.state} peers={peers} uploaded={status.total_upload}")
            for p in peers:
                ip = getattr(p, "ip", None)
                pieces_bitfield = getattr(p, "pieces", [])
                missing_pieces = [i for i, has in enumerate(pieces_bitfield) if not has]
                logger.info(f"  peer {ip} missing pieces: {missing_pieces}")
            time.sleep(POLL_INTERVAL)
    except KeyboardInterrupt:
        logger.info("Seeder shutting down.")


def get_ip_filter_of_allowed_peers(allowed_peers):

    # Create a new ip_filter
    ip_filter = lt.ip_filter()

    # 1. Block everything
    ip_filter.add_rule("0.0.0.0", "255.255.255.255", 1)
    ip_filter.add_rule("::", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", 1)

    # 2. Allow specific IPs
    for ip in allowed_peers:
        addr = ipaddress.ip_address(ip)
        ip_filter.add_rule(ip, ip, 0)

    return ip_filter


if __name__ == "__main__":
    main()
