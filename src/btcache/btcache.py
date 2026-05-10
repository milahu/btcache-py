#!/usr/bin/env python3

"""
btcache.py
A caching BitTorrent client running as a proxy between hidden seeders and public leechers
"""

import os
import re
import io
import sys
import time
import socket
import logging
import argparse
import ipaddress
import threading
import urllib.parse
from typing import List, Tuple, Optional
from dataclasses import dataclass, field, asdict
import itertools

import requests
import libtorrent as lt
from ruamel.yaml import YAML
from ruamel.yaml.comments import CommentedMap

yaml = YAML()
yaml.indent(mapping=2, sequence=4, offset=2)

debug_alerts = 0

ignore_alert_types = (
    lt.tracker_error_alert,
    lt.add_torrent_alert,
    lt.torrent_resumed_alert,
    lt.torrent_checked_alert,
    lt.tracker_announce_alert,
    lt.cache_flushed_alert,
    lt.alerts_dropped_alert,
    lt.torrent_finished_alert,
    # lt.state_changed_alert, # state changed to: finished
    lt.torrent_added_alert,
)

# filter alerts of type torrent_log_alert
ignore_alert_strings = [
    ": creating torrent:",
    ": init torrent:",
    ": init, async_check_files",
    ": set_state()",
    ": start_announcing()",
    ": *** UPDATE LIST [ torrent_want_tick", # TODO what
    ": *** announce:",
    ": *** tracker:",
    ": *** update_tracker_timer:",
    ": *** update tracker timer:",
    ": *** tracker error:",
    ": fastresume data accepted",
    # ": state changed to: finished",
    ": ==> TRACKER REQUEST",
    ": ==> TRACKER_REQUEST",
    ": *** QUEUE_TRACKER_REQUEST",
    ": *** increment tracker fail count",
    "dropped alerts:", # lt.alerts_dropped_alert
    "tracker_announce_alert:", # lt.tracker_announce_alert
    "parsed listen interfaces count:",
    "add_torrent_alert: added torrent:", # lt.add_torrent_alert
    "torrent_added_alert:", # lt.torrent_added_alert
    "torrent_resumed_alert:", # lt.torrent_resumed_alert
    "torrent_finished_alert:",
    "torrent_checked_alert:",
    "cache_flushed_alert:",
    "tracker_error_alert:",
    "stats_alert:",
]


# ---------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------


@dataclass
class BTCachePeer:
    hostname: str = ""
    torrent_dir_urls: List[str] = field(default_factory=list)
    cas_urls: List[str] = field(default_factory=list)
    torrent_peers: List[str] = field(default_factory=list)


@dataclass
class BTCacheConfig:
    """Configuration for BTCache."""
    hidden_peers: List[BTCachePeer] = field(default_factory=list)
    allowed_ips: List[str] = field(default_factory=list)
    # FIXME move to torrent_settings "listen_interfaces"
    listen: str = "0.0.0.0:6881"
    cache_dir: str = "btcache-torrents"
    cache_size: str = "100MiB"
    cas_path: Optional[str] = None
    save_dir: str = "btcache-downloads"
    poll_interval: float = 1.0
    max_incremental_fetch: int = 3
    # TODO
    keep_first_n_pieces_in_cache: int = 0

    # nested dict of libtorrent session settings
    # https://www.libtorrent.org/reference-Settings.html
    torrent_settings: dict = field(default_factory=lambda: {
        # "enable_dht": False,
        # "enable_upnp": False,
        # "enable_natpmp": False,
        # "enable_lsd": False,
        "allow_multiple_connections_per_ip": True,
    })

    @staticmethod
    def from_yaml(path: str) -> "BTCacheConfig":
        with open(path, "r") as f:
            data = yaml.load(f) or {}
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

        if config.allowed_ips:
            self.logger.info(f"setting ip filter: allowing peers {config.allowed_ips}")
            self.session.set_ip_filter(get_ip_filter_of_allowed_peers(config.allowed_ips))
        else:
            self.logger.info("not setting ip filter")

        # parse torrent_peers into tuples of (host, port)
        for peer in self.config.hidden_peers:
            # FIXME use SimpleNamespace: peer.bittorrent_peer
            for torrent_peer_idx, torrent_peer in enumerate(peer["torrent_peers"]):
                host, port = torrent_peer.split(":")
                port = int(port)
                peer["torrent_peers"][torrent_peer_idx] = (host, port)

        self.torrent_handles: dict[str, list[lt.torrent_handle]] = {}
        self.uploaded_pieces_by_torrent_handle: dict[lt.torrent_handle, list[bool]] = {}

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
        # Enable alerts
        settings["alert_mask"] = (
            0
            # lt.alert.category_t.status_notification # incoming_connection_alert
            | lt.alert.category_t.error_notification
            # peer_connect_alert
            # peer_disconnected_alert
            # | lt.alert.category_t.connect_notification
            # peer_snubbed_alert
            # peer_blocked_alert
            | lt.alert.category_t.peer_notification
            # | lt.alert.category_t.peer_log_notification # peer_log_alert
            | lt.alert.category_t.storage_notification
            # | lt.alert.category_t.tracker_notification
            # | lt.alert.category_t.piece_progress_notification # piece_finished_alert
            | lt.alert.category_t.upload_notification # block_uploaded_alert
            | lt.alert.category_t.performance_warning
            # | lt.alert.category_t.all_categories # debug
        )
        if debug_alerts:
            # NOTE alerts are dropped when too many
            settings["alert_mask"] |= lt.alert.category_t.all_categories
        # settings["send_redundant_have"] = True # send HAVE even if peer already knows
        # settings["lazy_bitfields"] = False # send full bitfield immediately on connect
        return lt.session(settings)

    # ------------------------------------------------------------------
    # Torrent fetch and cache
    # ------------------------------------------------------------------
    def fetch_and_cache_torrents_for_host(self, peer, url_idx) -> List[Tuple[str, str, str]]:
        cfg = self.config
        url = peer["torrent_dir_urls"][url_idx]
        u = urllib.parse.urlparse(url)
        hostname = peer.get("hostname", u.netloc)
        host_dir = os.path.join(cfg.cache_dir, hostname, u.path[1:])
        os.makedirs(host_dir, exist_ok=True)

        try:
            r = requests.get(url, timeout=10)
            r.raise_for_status()
        except Exception as e:
            self.logger.info(f"{hostname}: directory fetch failed: {e}")
            return []

        found = []
        for m in self.torrent_link_re.finditer(r.text):
            href = m.group(1)
            file_url = urllib.parse.urljoin(url, href)
            decoded = urllib.parse.unquote(href)
            filename = os.path.basename(decoded)
            file_path = os.path.join(host_dir, filename)
            found.append((filename, file_path, file_url))
            if not os.path.exists(file_path):
                try:
                    r2 = requests.get(file_url, timeout=15)
                    r2.raise_for_status()
                    with open(file_path, "wb") as f:
                        f.write(r2.content)
                    self.logger.info(f"{hostname}: cached {file_path}")
                except Exception as e:
                    self.logger.info(f"{hostname}: failed to fetch {file_url}: {e}")
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
        # TODO add session parameter pex_ip_filter
        # https://github.com/arvidn/libtorrent/issues/8059
        atp.flags |= lt.torrent_flags.disable_pex
        atp.flags &= ~lt.torrent_flags.auto_managed
        # atp.flags &= ~lt.torrent_flags.paused
        # atp.flags |= lt.torrent_flags.paused  # start paused
        # atp.flags &= ~lt.torrent_flags.has_metadata

        th = self.session.add_torrent(atp)

        # TODO use bitfield
        self.uploaded_pieces_by_torrent_handle[th] = [False] * ti.num_pieces()

        th.resume()

        status = th.status()
        self.logger.info(f"Torrent status after session.add_torrent: state={status.state} progress={status.progress} bytes={status.total_wanted}")

        th.prioritize_pieces([0] * ti.num_pieces())

        status = th.status()
        self.logger.info(f"Torrent status after th.prioritize_pieces: state={status.state} progress={status.progress} bytes={status.total_wanted}")

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
        all_torrent_peers = []
        for peer in self.config.hidden_peers:
            all_torrent_peers += peer["torrent_peers"]
        for hostname, port in all_torrent_peers:
            ip = self.resolve_hostname(hostname)
            if not ip:
                continue
            try:
                th.connect_peer((ip, port), 0)
                # self.logger.info(f"Adding hidden peer {hostname}:{port} = {ip}:{port}")
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
                # self.logger.debug("peer_info_alert")
                self.monitor_peer_info_alert(a)
            elif isinstance(a, lt.block_uploaded_alert):
                ip, port = a.ip
                if self.uploaded_pieces_by_torrent_handle[a.handle][a.piece_index]:
                    continue
                # self.logger.debug(f"block_uploaded_alert: torrent={a.handle.torrent_file().info_hashes().v1} piece={a.piece_index} block={a.block_index} peer={ip}:{port}")
                # assume a piece was uploaded when one of its pieces was uploaded
                # we cannot be more strict here
                # because we cannot get the actual "have" bitfield from leech-only peers
                # TODO keep track of time?
                self.uploaded_pieces_by_torrent_handle[a.handle][a.piece_index] = True
                # trigger next incremental fetch
                self.fetch_pieces(a.handle, a.ip)
            elif isinstance(a, lt.peer_connect_alert):
                # too early. no handshake. no bitfield exchange
                ip, port = getattr(a, "ip", None)
                self.logger.debug(f"peer_connect_alert: peer={ip}:{port} torrent={a.handle.torrent_file().info_hashes().v1}")
            # elif isinstance(a, lt.incoming_connection_alert):
            #     # too early. no handshake. no a.handle
            #     ip, port = getattr(a, "ip", None)
            #     self.logger.debug(f"incoming_connection_alert: peer={ip}:{port}")
            elif isinstance(a, lt.peer_disconnected_alert):
                ip, port = getattr(a, "ip", None)
                self.logger.debug(f"peer_disconnected_alert: peer={ip}:{port} torrent={a.handle.torrent_file().info_hashes().v1}")
            elif isinstance(a, lt.peer_snubbed_alert):
                self.logger.debug(f"peer_snubbed_alert: peer={a.ip}")
            elif isinstance(a, lt.peer_blocked_alert):
                self.logger.debug(f"peer_blocked_alert: peer={a.ip}")
                if 0:
                    # get alert category
                    a_category = a.category()
                    for key in dir(lt.alert.category_t):
                        val = getattr(lt.alert.category_t, key)
                        if val == a_category:
                            self.logger.debug(f"peer_blocked_alert: category=lt.alert.category_t.{key}")
            # elif isinstance(a, lt.piece_availability_alert):
            #     # Swarm-wide piece availability
            #     self.logger.debug(f"piece_availability_alert: piece={a.piece_index} num_peers={a.num_peers}")
            # elif isinstance(a, lt.peer_log_alert):
            #     self.logger.debug(f"peer_log_alert: msg={a.msg()!r} peers={peers}")
            # elif isinstance(a, lt.block_finished_alert):
            #     # a block finished downloading
            #     self.logger.debug(f"block_finished_alert: torrent={a.handle.torrent_file().info_hashes().v1} piece={a.piece_index} peers={a.handle.get_peer_info()}")
            # elif isinstance(a, lt.piece_finished_alert):
            #     # a piece finished downloading and passed the hash check
            #     self.logger.debug(f"piece_finished_alert: torrent={a.handle.torrent_file().info_hashes().v1} piece={a.piece_index} peers={a.handle.get_peer_info()}") # dir(a)={dir(a)}
            elif debug_alerts:
                # Log all alerts for debugging
                s = f"{type(a).__name__}: {a}"
                ignore_alert = False
                for _s in ignore_alert_strings:
                    if _s in s:
                        ignore_alert = True
                        break
                if ignore_alert: continue
                self.logger.debug(f"ALERT {type(a).__name__}: {a}")

    def monitor_peer_info_alert(self, a):
        # called from peer_info_alert
        th = a.handle
        peers = th.get_peer_info()
        # self.logger.debug(f"monitor_peer_info_alert: peers={peers}")
        for p in peers:
            ip, port = getattr(p, "ip", None)
            self.logger.debug(f"monitor_peer_info_alert: peer={ip}:{port} choked={getattr(p,'remote_choked',None)} interested={getattr(p,'remote_interested',None)} pieces={compress_bool_ranges(p.pieces)}")
            # FIXME move this to "Connected peer" -> initial fetch of pieces
            # TODO? call fetch_pieces
            # this is the only event where we get the "haves" bitfield from peers
            # and this is fired only once after the bitfield exchange
            self.fetch_pieces(th, p.ip, p.pieces)

    def fetch_pieces(self, torrent_handle, peer_ip, peer_pieces=None):
        # FIXME this can be called from
        #   monitor_peer_info_alert
        #   block_uploaded_alert
        # but when called from monitor_peer_info_alert
        # then new pieces are added too fast
        # so this should be limited by uploaded_pieces
        th = torrent_handle
        ip, port = peer_ip
        if peer_pieces:
            # the peer just connected
            # called from monitor_peer_info_alert
            # this is called only once per peer
            # fetch the first N missing pieces
            self.logger.info(f"fetch_pieces: called from monitor_peer_info_alert")
            is_seed = all(peer_pieces)
            # NOTE leech-only clients will never "have" any pieces
            # so we cannot reliably predict which pieces they will request next
            missing_pieces = [i for i, has in enumerate(peer_pieces) if not has]
            missing_piece_ranges = compress_ranges(missing_pieces)
            if is_seed:
                self.logger.info(f"fetch_pieces: seeder peer {ip}:{port} seed={is_seed} missing={missing_piece_ranges}")
                return
            self.logger.info(f"fetch_pieces: leecher peer {ip}:{port} seed={is_seed} missing={missing_piece_ranges}")
        else:
            # the peer just downloaded a block
            # called from block_uploaded_alert
            # fetch the next N missing pieces
            # FIXME this only works when the leecher needs all pieces in order
            # we would have to lie ("we have all pieces")
            # to know which pieces the leecher actually needs
            # we could do "limited lying"
            # by slowly expanding our "have" bitfield
            # until the leecher starts requesting pieces
            # then we fetch the pieces from hidden seeders
            # and deliver the pieces to the leecher
            # and continue to expand our "have" bitfield
            # anyway, this would require patching libtorrent
            # https://github.com/bittorrent/bittorrent.org/pull/176
            # draft BEP: Want Bitfields of Leech-Only Clients
            self.logger.info(f"fetch_pieces: called from block_uploaded_alert")
            uploaded_pieces = self.uploaded_pieces_by_torrent_handle[th]
            missing_pieces = []
            for piece in range(th.torrent_file().num_pieces()):
                done = uploaded_pieces[piece]
                if not done:
                    missing_pieces.append(piece)
        current_priorities = [th.piece_priority(i) for i in range(th.torrent_file().num_pieces())]
        self.logger.info(f"fetch_pieces: missing_pieces={compress_ranges(missing_pieces)} current_priorities={compress_bool_ranges(current_priorities)}")
        to_fetch = []
        for i in missing_pieces:
            if current_priorities[i] == 0:
                current_priorities[i] = 1
                to_fetch.append(i)
            if len(to_fetch) >= self.config.max_incremental_fetch:
                break
        if to_fetch:
            self.logger.info(f"fetch_pieces: Fetching pieces from hidden peers: {compress_ranges(to_fetch)}")
            th.prioritize_pieces(current_priorities)
            self.ensure_hidden_peers_connected(th)

    def monitor_torrent(self, th, host):
        try:
            # self.logger.info(f"monitor_torrent: th.post_peer_info")
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
                f"monitor_torrent: "
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

        for peer in self.config.hidden_peers:
            host = peer["hostname"]
            found = []
            for url_idx in range(len(peer["torrent_dir_urls"])):
                found += self.fetch_and_cache_torrents_for_host(peer, url_idx)
            handles = []
            for _, path, _ in found:
                try:
                    th = self.add_torrent(path)
                    handles.append(th)
                except Exception as e:
                    raise
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


def compress_bool_ranges(pieces):
    """Compress list of bools like [True,True,False] -> '[0-1]'"""
    a = enumerate(pieces)
    b = map(lambda iv: iv[0] if iv[1] else -1, a)
    c = filter(lambda x: x >= 0, b)
    return compress_ranges(c)


def yaml_scalar(value) -> str:
    """Render a Python value as a one-line YAML literal."""
    buf = io.StringIO()
    y = YAML(typ='safe')
    y.default_flow_style = False
    # dump as a key in a dummy mapping
    # so ruamel doesn't add document markers (trailing '...')
    y.dump({'v': value}, buf)
    text = buf.getvalue().strip()
    # extract the value portion after 'v: '
    return text.split(': ', 1)[1].strip()


def get_ip_filter_of_allowed_peers(allowed_ips):

    # Create a new ip_filter
    ip_filter = lt.ip_filter()

    # 1. Block everything
    ip_filter.add_rule("0.0.0.0", "255.255.255.255", 1)
    ip_filter.add_rule("::", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", 1)

    # 2. Allow specific IPs
    for ip in allowed_ips:
        addr = ipaddress.ip_address(ip)
        ip_filter.add_rule(ip, ip, 0)

    return ip_filter


# https://stackoverflow.com/questions/9555118/parsing-string-with-kb-mb-gb-etc-into-numeric-value
import re
parse_size = lambda s:(
    lambda m,e,i:float(m)*(1000+24*bool(i))**'1kmgtpezyrq'.find(e or "1")
)(*re.match(r'([0-9.]+)([kmgtpezyrq])?(i)?b?$',s.lower()).groups())


# https://stackoverflow.com/questions/12523586/python-format-size-application-converting-b-to-kb-mb-gb-tb
# binary-prefixed decimal units: B, KiB, MiB, GiB, ...
format_size = lambda n:(
    (lambda L:(f'{n/1024**L:.2f}{(" KMGTPEZYRQ"[L]+"i")*(L>0)}'
    ).rstrip('0').rstrip('.')if L else str(n))(
    (len(bin(int(n)))-1)//10
    )
)+"B"


# ----------------------------------------------------------------------
# CLI entrypoint
# ----------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(
        description="BTCache: a caching BitTorrent proxy",
    )
    parser.add_argument(
        "--config", # args.config
        metavar="PATH",
        help="read btcache.config.yaml from this path",
    )
    parser.add_argument(
        "--write-config", # args.write_config
        metavar="PATH",
        help="write default btcache.config.yaml to this path",
    )
    args = parser.parse_args()

    if args.write_config:
        default_config = BTCacheConfig()
        lt_defaults = lt.default_settings()
        data = asdict(default_config)
        # comment default values
        ts_map = CommentedMap()
        # non-default settings first
        for k, v in data["torrent_settings"].items():
            ts_map[k] = v
            if k in lt_defaults:
                default_yaml = yaml_scalar(lt_defaults[k])
                ts_map.yaml_add_eol_comment(f"default: {default_yaml}", key=k)
        data["torrent_settings"] = ts_map
        with open(args.write_config, "w") as f:
            yaml.dump(data, f)
            # default settings second
            for k, v in lt_defaults.items():
                v_yaml = yaml_scalar(v)
                if k not in ts_map:
                    f.write(f"  # {k}: {v_yaml} # default: {v_yaml}\n")
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
