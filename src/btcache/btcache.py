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
from typing import List, Tuple, Optional
from dataclasses import dataclass, field, asdict
import itertools

import requests
import libtorrent as lt
import yaml


# ---------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------
@dataclass
class BTCacheConfig:
    """Configuration for BTCache."""

    hidden_peers: List[str] = field(default_factory=list)
    listen: str = "0.0.0.0:6881"
    cache_dir: str = "btcache-torrents"
    cas_path: Optional[str] = None
    save_dir: str = "btcache-downloads"
    poll_interval: float = 1.0
    max_incremental_fetch: int = 3

    # nested dict of libtorrent session settings
    torrent_settings: dict = field(default_factory=lambda: {
        "enable_dht": False,
        "enable_upnp": False,
        "enable_natpmp": False,
        "enable_lsd": False,
        "allow_multiple_connections_per_ip": True,
        "active_tracker_limit": 0,
    })

    @staticmethod
    def from_yaml(path: str) -> "BTCacheConfig":
        with open(path, "r") as f:
            data = yaml.safe_load(f) or {}
        return BTCacheConfig(**data)


# ---------------------------------------------------------------------
# BTCache main class
# ---------------------------------------------------------------------
class BTCache:
    torrent_link_re = re.compile(r'<a\s+href="([^"]+\.torrent)"', re.IGNORECASE)

    def __init__(self, config: BTCacheConfig):
        self.config = config
        self.logger = self._get_logger()
        self.session = self._create_session()

        self.hidden_peers: List[Tuple[str, int]] = [
            (h.split(":")[0], int(h.split(":")[1])) for h in config.hidden_peers
        ]
        self.torrent_handles: dict[str, list[lt.torrent_handle]] = {}

    # ------------------------------------------------------------------
    # Logging setup
    # ------------------------------------------------------------------
    def _get_logger(self) -> logging.Logger:
        logger = logging.getLogger("btcache")
        if not logger.handlers:
            logger.setLevel(logging.DEBUG)
            ch = logging.StreamHandler(sys.stdout)
            ch.setLevel(logging.DEBUG)
            fmt = logging.Formatter(
                fmt="%(asctime)s.%(msecs)03d %(module)s %(message)s",
                datefmt="%Y-%m-%d %H:%M:%S",
            )
            ch.setFormatter(fmt)
            logger.addHandler(ch)
        return logger

    # ------------------------------------------------------------------
    # Libtorrent session setup
    # ------------------------------------------------------------------
    def _create_session(self) -> lt.session:
        cfg = self.config
        settings = lt.default_settings()
        settings.update(cfg.torrent_settings)
        settings["listen_interfaces"] = cfg.listen
        self.logger.info(f"Listening on {settings['listen_interfaces']}")
        return lt.session(settings)

    # ------------------------------------------------------------------
    # Torrent fetch and cache
    # ------------------------------------------------------------------
    def fetch_and_cache_torrents_for_host(self, hostname: str) -> List[Tuple[str, str, str]]:
        cfg = self.config
        host_dir = os.path.join(cfg.cache_dir, hostname)
        os.makedirs(host_dir, exist_ok=True)

        url = f"https://{hostname}/torrents/"
        if hostname in ["localhost", "127.0.0.1"]:
            url = f"http://{hostname}/torrents/"

        try:
            r = requests.get(url, timeout=10)
            r.raise_for_status()
        except Exception as e:
            self.logger.info(f"{hostname}: directory fetch failed: {e}")
            return []

        found = []
        for m in self.torrent_link_re.finditer(r.text):
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
                    self.logger.info(f"{hostname}: cached {filename}")
                except Exception as e:
                    self.logger.info(f"{hostname}: failed to fetch {href}: {e}")
        return found

    # ------------------------------------------------------------------
    # Torrent handling
    # ------------------------------------------------------------------
    def add_torrent(self, torrent_path: str) -> lt.torrent_handle:
        cfg = self.config
        ti = lt.torrent_info(torrent_path)

        if cfg.cas_path:
            infohashes = ti.info_hashes()
            if infohashes.has_v1():
                infohash_type = "btih"
                infohash = str(infohashes.v1)
            elif infohashes.has_v2():
                infohash_type = "btmh"
                infohash = str(infohashes.v2)
            else:
                raise ValueError("Torrent has neither v1 nor v2 infohash")
            save_path = os.path.join(cfg.cas_path, infohash_type, infohash)
        else:
            save_path = cfg.save_dir

        os.makedirs(save_path, exist_ok=True)
        self.logger.info(f"Adding {torrent_path} -> {save_path}")

        atp = lt.add_torrent_params()
        atp.ti = ti
        atp.save_path = save_path
        atp.storage_mode = lt.storage_mode_t.storage_mode_sparse
        atp.flags |= lt.torrent_flags.disable_pex
        atp.flags &= ~lt.torrent_flags.auto_managed
        atp.flags &= ~lt.torrent_flags.paused
        atp.trackers = []

        th = self.session.add_torrent(atp)
        th.prioritize_pieces([0] * ti.num_pieces())
        return th

    # ------------------------------------------------------------------
    # Peer management
    # ------------------------------------------------------------------
    def resolve_hostname(self, hostname: str):
        try:
            return socket.gethostbyname(hostname)
        except Exception:
            return None

    def ensure_hidden_peers_connected(self, th: lt.torrent_handle):
        for hostname, port in self.hidden_peers:
            ip = self.resolve_hostname(hostname)
            if not ip:
                continue
            try:
                th.connect_peer((ip, port), 0)
                self.logger.info(f"Adding hidden peer {hostname}:{port} = {ip}:{port}")
            except Exception as e:
                self.logger.info(f"Failed to connect to hidden peer {hostname}:{port} = {ip}:{port} - {e}")

    # ------------------------------------------------------------------
    # Monitoring loop
    # ------------------------------------------------------------------
    def monitor_loop(self):
        cfg = self.config
        while True:
            alerts = self.session.pop_alerts()
            self.monitor_alerts(alerts)

            for host, th_list in self.torrent_handles.items():
                for th in th_list:
                    self.monitor_torrent(th, host)

            time.sleep(cfg.poll_interval)

    def monitor_alerts(self, alerts):
        for a in alerts:
            if isinstance(a, lt.peer_info_alert):
                self.monitor_peer_info_alert(a)

    def monitor_peer_info_alert(self, a):
        if not self.torrent_handles:
            return

        for host, th_list in self.torrent_handles.items():
            for th in th_list:
                peers = th.get_peer_info()
                for p in peers:
                    self.monitor_peer(p, th, host)

    def monitor_peer(self, p, th, host):
        ip, port = getattr(p, "ip", None)
        pieces_bitfield = getattr(p, "pieces", [])
        is_seed = all(pieces_bitfield)
        missing_pieces = [i for i, has in enumerate(pieces_bitfield) if not has]
        missing_piece_ranges = compress_ranges(missing_pieces)
        if is_seed:
            self.logger.info(f"seeder peer {ip}:{port} seed={is_seed} missing={missing_piece_ranges}")
            return

        self.logger.info(f"leecher peer {ip}:{port} seed={is_seed} missing={missing_piece_ranges}")
        current_priorities = [th.piece_priority(i) for i in range(th.torrent_file().num_pieces())]
        to_fetch = []
        for i in missing_pieces:
            if not th.have_piece(i) and current_priorities[i] == 0:
                current_priorities[i] = 1
                to_fetch.append(i)
            if len(to_fetch) >= self.config.max_incremental_fetch:
                break
        if to_fetch:
            self.logger.info(f"Fetching pieces from hidden peers: {compress_ranges(to_fetch)}")
            th.prioritize_pieces(current_priorities)
            self.ensure_hidden_peers_connected(th)

    def monitor_torrent(self, th, host):
        try:
            th.post_peer_info()
        except Exception:
            pass

        try:
            status = th.status()
            tf = th.torrent_file()
            n_pieces = tf.num_pieces()
            btih = tf.info_hashes().v1

            # Collect enabled and downloaded piece indices
            enabled_indices = [i for i in range(n_pieces) if th.piece_priority(i) > 0]
            have_indices = [i for i in range(n_pieces) if th.have_piece(i)]

            # Compress ranges for readability
            enabled_ranges = compress_ranges(enabled_indices)
            have_ranges = compress_ranges(have_indices)

            # Compute byte-level progress
            total = status.total_wanted
            done = status.total_wanted_done
            percent = (done / total * 100) if total > 0 else 0.0

            self.logger.info(
                f"host={host}: btih={btih} state={status.state} "
                f"progress={done}/{total} bytes ({percent:.2f}%) "
                f"enabled={enabled_ranges} have={have_ranges}"
            )

            if str(status.state) == "downloading":
                self.ensure_hidden_peers_connected(th)

        except Exception as e:
            self.logger.info(f"Error fetching status for torrent: {e}")

    # ------------------------------------------------------------------
    # Main control
    # ------------------------------------------------------------------
    def run(self):
        cfg = self.config
        os.makedirs(cfg.cache_dir, exist_ok=True)
        os.makedirs(cfg.save_dir, exist_ok=True)

        for host, _ in self.hidden_peers:
            found = self.fetch_and_cache_torrents_for_host(host)
            handles = []
            for _, path, _ in found:
                try:
                    th = self.add_torrent(path)
                    handles.append(th)
                except Exception as e:
                    self.logger.info(f"{host}: add torrent failed: {e}")
            if handles:
                self.torrent_handles[host] = handles

        threading.Thread(target=self.monitor_loop, daemon=True).start()

        try:
            while True:
                time.sleep(60)
        except KeyboardInterrupt:
            self.logger.info("Shutting down")


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


# ----------------------------------------------------------------------
# CLI entrypoint
# ----------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(
        description="BTCache: a caching BitTorrent proxy",
    )
    parser.add_argument(
        "--config",
        metavar="PATH",
        help="read btcache.config.yaml from this path",
    )
    parser.add_argument(
        "--write-config",
        metavar="PATH",
        help="write default btcache.config.yaml to this path",
    )
    args = parser.parse_args()

    if args.write_config:
        default_config = BTCacheConfig()
        with open(args.write_config, "w") as f:
            yaml.safe_dump(asdict(default_config), f, sort_keys=False)
        print(f"writing {args.write_config}")
        sys.exit(0)

    if not args.config:
        print("error: no config")
        print()
        parser.print_help()
        sys.exit(1)

    config = BTCacheConfig.from_yaml(args.config)
    btcache = BTCache(config)
    btcache.run()


if __name__ == "__main__":
    main()
