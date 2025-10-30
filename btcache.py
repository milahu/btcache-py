#!/usr/bin/env python3

"""
btcache.py
A caching BitTorrent client running as a proxy between hidden seeders and public leechers
"""

import os
import re
import sys
import time
import socket
import logging
import argparse
import threading
import urllib.parse
from typing import List, Tuple

import requests
import libtorrent as lt

# ---------------------------------------------------------------------
# Logger
# ---------------------------------------------------------------------
def get_logger() -> logging.Logger:
    logger = logging.getLogger("btcache")
    logger.setLevel(logging.DEBUG)
    ch = logging.StreamHandler()
    ch.setLevel(logging.DEBUG)
    formatter = logging.Formatter(
        fmt="%(asctime)s.%(msecs)03d %(module)s %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )
    ch.setFormatter(formatter)
    logger.addHandler(ch)
    return logger

# ---------------------------------------------------------------------
# Fetch and cache torrents
# ---------------------------------------------------------------------
torrent_link_re = re.compile(r'<a\s+href="([^"]+\.torrent)"', re.IGNORECASE)

def fetch_and_cache_torrents_for_host(logger, hostname: str, cache_dir: str) -> List[Tuple[str, str, str]]:
    host_dir = os.path.join(cache_dir, hostname)
    os.makedirs(host_dir, exist_ok=True)
    # TODO configure custom url per hostname
    url = f"https://{hostname}/torrents/"
    if hostname in ["localhost", "127.0.0.1"]:
        url = f"http://{hostname}/torrents/"
    try:
        r = requests.get(url, timeout=10)
        r.raise_for_status()
    except Exception as e:
        logger.info(f"{hostname}: directory fetch failed: {e}")
        return []

    found = []
    for m in torrent_link_re.finditer(r.text):
        href = m.group(1)
        decoded = urllib.parse.unquote(href)
        filename = os.path.basename(decoded)
        path = os.path.join(host_dir, filename)
        found.append((filename, path, urllib.parse.urljoin(url, href)))
        if not os.path.exists(path):
            try:
                r2 = requests.get(urllib.parse.urljoin(url, href), timeout=15)
                r2.raise_for_status()
                with open(path, "wb") as f:
                    f.write(r2.content)
                logger.info(f"{hostname}: cached {filename}")
            except Exception as e:
                logger.info(f"{hostname}: failed to fetch {href}: {e}")
    return found

# ---------------------------------------------------------------------
# Torrent helper functions
# ---------------------------------------------------------------------
def add_torrent_with_zero_priorities(logger, ses, torrent_path, args):
    ti = lt.torrent_info(torrent_path)

    # Determine CAS path if provided
    if args.cas_path:
        infohashes = ti.info_hashes()
        # Determine storage type
        if infohashes.has_v1(): # v1 or hybrid torrent
            infohash_type = "btih"
            infohash = str(infohashes.v1)
        elif infohashes.has_v2(): # v2-only torrent
            infohash_type = "btmh"
            infohash = str(infohashes.v2)
        else:
            raise ValueError("Torrent has neither v1 nor v2 infohash")

        save_path = os.path.join(args.cas_path, infohash_type, infohash)
        os.makedirs(save_path, exist_ok=True)
    else:
        save_path = args.save_dir
        os.makedirs(save_path, exist_ok=True)

    logger.info(f"adding {torrent_path} -> {save_path}")

    atp = lt.add_torrent_params()
    atp.ti = ti
    atp.save_path = save_path
    # minimize disk usage
    # TODO limit cache size
    # evict unpopular pieces from the cache
    # by punching holes in content files
    # fallocate(fd, FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE, offset, length)
    atp.storage_mode = lt.storage_mode_t.storage_mode_sparse
    # disable PEX to keep our hidden peers hidden
    atp.flags |= lt.torrent_flags.disable_pex
    # dont manage
    atp.flags &= ~lt.torrent_flags.auto_managed
    # start now
    atp.flags &= ~lt.torrent_flags.paused
    # disable trackers
    atp.trackers = []
    th = ses.add_torrent(atp)

    n_pieces = ti.num_pieces()
    th.prioritize_pieces([0] * n_pieces)
    return th

def resolve_hostname(hostname):
    try:
        return socket.gethostbyname(hostname)
    except Exception:
        return None

def ensure_hidden_peers_connected(logger, th, hidden_peers):
    for hostname, port in hidden_peers:
        ip = resolve_hostname(hostname)
        if not ip:
            continue
        try:
            th.connect_peer((ip, port), 0)
            logger.info(f"Adding hidden peer {hostname}:{port} = {ip}:{port}")
        except Exception as e:
            logger.info(f"Failed to connect to hidden peer {hostname}:{port} = {ip}:{port} - {e}")

# ---------------------------------------------------------------------
# Monitor loop
# ---------------------------------------------------------------------
def monitor_loop(logger, ses, torrent_handles, args):
    # parse hidden peers from args
    hidden_peers = []
    for hp in args.hidden_peers:
        host, port = hp.split(":")
        hidden_peers.append((host, int(port)))
    poll_interval = args.poll_interval
    max_incremental_fetch = args.max_incremental_fetch

    while True:
        alerts = ses.pop_alerts()
        for a in alerts:
            if isinstance(a, lt.peer_info_alert):
                th = next(iter(torrent_handles.values()))[0] if torrent_handles else None
                if not th:
                    continue

                peers = th.get_peer_info()
                for p in peers:
                    ip, port = getattr(p, "ip", None)
                    pieces_bitfield = getattr(p, "pieces", [])
                    is_seed = all(pieces_bitfield)
                    is_leecher = not is_seed
                    missing_pieces = [i for i, has in enumerate(pieces_bitfield) if not has]

                    logger.info(f"peer {ip}:{port} seed={is_seed} leecher={is_leecher} missing_pieces={missing_pieces}")

                    # Incremental fetch: only enable a few missing pieces at a time
                    current_priorities = [th.piece_priority(i) for i in range(th.torrent_file().num_pieces())]
                    to_fetch = []
                    for i in missing_pieces:
                        if not th.have_piece(i) and current_priorities[i] == 0:
                            current_priorities[i] = 1
                            to_fetch.append(i)
                        if len(to_fetch) >= max_incremental_fetch:
                            break

                    if to_fetch:
                        logger.info(f"Fetching pieces from hidden peers: {to_fetch}")
                        th.prioritize_pieces(current_priorities)
                        ensure_hidden_peers_connected(logger, th, hidden_peers)

        # Update torrent stats
        for host, th_list in torrent_handles.items():
            for th in th_list:
                try:
                    th.post_peer_info()
                except Exception:
                    pass
                try:
                    status = th.status()
                    n_pieces = th.torrent_file().num_pieces()
                    enabled_pieces = "".join(
                        ["1" if th.piece_priority(i) > 0 else "0" for i in range(n_pieces)]
                    )
                    downloaded_pieces = "".join("Y" if th.have_piece(i) else "N" for i in range(n_pieces))
                    total_downloaded = status.total_done
                    logger.info(f"Torrent: btih={th.info_hash()} priorities={enabled_pieces} haves={downloaded_pieces} done={total_downloaded} state={status.state}")
                    if str(status.state) == "downloading":
                        ensure_hidden_peers_connected(logger, th, hidden_peers)
                except Exception as e:
                    logger.info(f"Error fetching status for torrent: {e}")

        time.sleep(poll_interval)

# ---------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(
        description="BTCache: a caching BitTorrent proxy",
    )
    parser.add_argument(
        "--hidden-peers",
        nargs="+",
        required=True,
        help="List of hidden peers host:port",
    )
    parser.add_argument(
        "--listen",
        default="0.0.0.0:6881",
        help="listen interface IP:port",
    )
    parser.add_argument(
        "--cache-dir",
        default="cache/torrents",
        help="torrent cache directory",
    )
    parser.add_argument(
        "--cas-path",
        default=None,
        help="root path for content-addressed storage (overrides save-dir)",
    )
    parser.add_argument(
        "--save-dir",
        default="btcache-downloads",
        help="download path for torrents",
    )
    parser.add_argument(
        "--poll-interval",
        type=float,
        default=1.0,
        help="seconds between alert checks",
    )
    parser.add_argument(
        "--max-incremental-fetch",
        type=int,
        default=3,
        help="max pieces to fetch at once",
    )
    args = parser.parse_args()

    logger = get_logger()
    logger.info("starting btcache")

    os.makedirs(args.cache_dir, exist_ok=True)
    os.makedirs(args.save_dir, exist_ok=True)

    # configure libtorrent session
    settings = lt.default_settings()
    settings['listen_interfaces'] = args.listen
    # FIXME expose these as a CLI options
    settings['enable_upnp'] = False
    settings['enable_natpmp'] = False
    settings['enable_lsd'] = False
    settings['enable_dht'] = False
    settings['active_tracker_limit'] = 0
    # FIXME expose this as a CLI option, default False
    # True is needed for tests where both seeder and leecher run on localhost
    settings['allow_multiple_connections_per_ip'] = True
    logger.info(f"listening on {settings['listen_interfaces']}")
    ses = lt.session(settings)

    # fetch torrents from hidden peers
    torrent_handles = {}
    for hp in args.hidden_peers:
        host, _ = hp.split(":")
        found = fetch_and_cache_torrents_for_host(logger, host, args.cache_dir)
        handles = []
        for filename, path, url in found:
            try:
                th = add_torrent_with_zero_priorities(logger, ses, path, args)
                handles.append(th)
            except Exception as e:
                logger.info(f"add torrent failed: {e}")
        if handles:
            torrent_handles[host] = handles

    # start monitor thread
    t = threading.Thread(target=monitor_loop, args=(logger, ses, torrent_handles, args), daemon=True)
    t.start()

    # keep main alive
    try:
        while True:
            time.sleep(60)
    except KeyboardInterrupt:
        logger.info("shutting down")

if __name__ == "__main__":
    main()
