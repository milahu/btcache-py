#!/usr/bin/env python3

import sys
import time
import socket
import logging
import argparse
import itertools

import libtorrent as lt

# seconds between alert checks / actions
POLL_INTERVAL = 1.0


# global state
logger = None


def get_logger():
    # Create a custom logger
    logger = logging.getLogger("btcache-test-leecher")
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
    parser = argparse.ArgumentParser(
        description="Test BitTorrent client for a single peer",
    )
    parser.add_argument(
        "--listen",
        required=True,
        help="Listen address:port. example: 127.0.0.1:6882",
    )
    parser.add_argument(
        "--peer",
        required=True,
        help="Peer address:port to connect to",
    )
    parser.add_argument(
        "--btih",
        required=True,
        help="Torrent infohash (hex)",
    )
    parser.add_argument(
        "--enable-seeding", # args.enable_seeding
        action="store_true",
        help="Enable seeding. By default this is a leech-only client",
    )
    return parser.parse_args()


def compress_ranges(indices):
    """Compress sorted indices like [0,1,2,5,6] -> '[0-2, 5-6]'"""
    if not indices:
        return []
    ranges = []
    for k, g in itertools.groupby(enumerate(indices), lambda x: x[1] - x[0]):
        group = list(g)
        start = group[0][1]
        end = group[-1][1]
        if start == end:
            ranges.append(f"{start}")
        else:
            ranges.append(f"{start}-{end}")
    return "[" + ", ".join(ranges) + "]"


def main():
    global logger
    logger = get_logger()
    logger.info("starting")

    args = parse_args()

    # listen_ip, listen_port = args.listen.split(":")
    # listen_port = int(listen_port)
    peer_ip, peer_port = args.peer.split(":")
    peer_port = int(peer_port)
    btih_hex = args.btih.lower()

    settings = lt.default_settings()
    settings['listen_interfaces'] = args.listen
    # FIXME expose these as a CLI options
    settings['enable_upnp'] = False
    settings['enable_natpmp'] = False
    settings['enable_lsd'] = False
    settings['enable_dht'] = False
    settings['active_tracker_limit'] = 0 # disable trackers?
    # settings['allow_multiple_connections_per_ip'] = True # only needed in btcache
    if not args.enable_seeding:
        # disable seeding per session
        settings['upload_rate_limit'] = 0
        settings['enable_incoming_utp'] = False
        settings['enable_incoming_tcp'] = False

    ses = lt.session(settings)

    # construct torrent handle from infohash
    info_hash_bytes = bytes.fromhex(btih_hex)
    atp = lt.add_torrent_params()
    atp.info_hash = lt.sha1_hash(info_hash_bytes)
    atp.save_path = "./btcache-test-leecher-downloads"
    atp.flags &= ~lt.torrent_flags.auto_managed
    atp.flags &= ~lt.torrent_flags.paused  # start immediately
    atp.trackers = []  # no trackers
    if not args.enable_seeding:
        # disable seeding per torrent
        atp.upload_mode = True
    th = ses.add_torrent(atp)

    # manually add the peer
    th.connect_peer((peer_ip, peer_port))

    logger.info(f"Listening on {args.listen}, trying to connect to peer {peer_ip}:{peer_port}")
    logger.info(f"Infohash: {btih_hex}")

    while True:
        # logger.info connected peers
        try:
            peers = th.get_peer_info()
            status = th.status()
            downloading = [i for i, v in enumerate(status.pieces) if not v and th.piece_priority(i) > 0]
            compressed = compress_ranges(downloading)

            # Compute progress
            total = status.total_wanted
            done = status.total_wanted_done
            percent = (done / total * 100) if total > 0 else 0.0

            logger.info(
                f"state={status.state} progress={done}/{total} bytes ({percent:.2f}%) "
                f"fetching_pieces={compressed}"
            )

            for p in peers:
                ip, port = getattr(p, "ip", None)
                interested = getattr(p, "remote_interested", False)
                choked = getattr(p, "remote_choked", False)
                logger.info(f"  peer={ip}:{port} interested={interested} choked={choked}")

        except Exception as e:
            logger.info(f"Error querying peers: {e}")

        time.sleep(POLL_INTERVAL)


if __name__ == "__main__":
    main()
