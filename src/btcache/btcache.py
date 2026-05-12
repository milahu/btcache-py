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
import heapq

import requests
import libtorrent as lt
from ruamel.yaml import YAML
from ruamel.yaml.comments import CommentedMap

# # debug: print all alert types
# for key in dir(lt):
#     if key.endswith("_alert"):
#         print(f"lt.{key}")
# raise 5

yaml = YAML()
yaml.indent(mapping=2, sequence=4, offset=2)

debug_alerts = 0
# debug_alerts = 1

debug_peer_log_alerts = 0
# debug_peer_log_alerts = 1

debug_all_alerts = 0
# debug_all_alerts = 1

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
        "active_tracker_limit": 0,
        "download_rate_limit": 1024**3, # 1 GiB/s
        "upload_rate_limit": 1024**3, # 1 GiB/s
        "allow_multiple_connections_per_ip": True,
        # fix: By default peers on the local network are not rate limited.
        "ignore_limits_on_local_network": False,
        # fix: performance_alert: performance warning: download limit too low (upload rate will suffer)
        "rate_limit_ip_overhead": False,
    })

    @staticmethod
    def from_yaml(path: str) -> "BTCacheConfig":
        with open(path, "r") as f:
            data = yaml.load(f) or {}
        return BTCacheConfig(**data)


@dataclass
class CacheEntry:
    cached: bool = False
    last_access: float = 0


# self.cache_lru
class MinHeap:

    def __init__(self):
        self._heap = []

    def push(self, item):
        heapq.heappush(self._heap, item)

    def pop(self):
        if not self._heap:
            return None
        return heapq.heappop(self._heap)

    def peek(self):
        if not self._heap:
            return None
        return self._heap[0]

    def clear(self):
        self._heap.clear()

    def __len__(self):
        return len(self._heap)

    def __bool__(self):
        return bool(self._heap)


# ---------------------------------------------------------------------
# BTCache main class
# ---------------------------------------------------------------------
class BTCache:
    torrent_link_re = re.compile(r'<a\s+href="([^"]+\.torrent)"', re.IGNORECASE)

    def __init__(self, config: BTCacheConfig):
        self.config = config
        self.logger = self._get_logger()
        self.session = self._create_session()

        self.cache_size = int(parse_size(self.config.cache_size))

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

        # TODO rename to self.torrent_handles_by_host
        self.torrent_handles: dict[str, list[lt.torrent_handle]] = {}
        self.uploaded_pieces_by_torrent_handle: dict[lt.torrent_handle, list[bool]] = {}
        self.peer_have_pieces: dict[lt.torrent_handle, dict[str, list[bool]]] = {}
        self.active_prefetch: dict[lt.torrent_handle, set[int]] = {}

        self.cache_state: dict[lt.torrent_handle, list[CacheEntry]] = {}
        self.cache_lru = MinHeap()
        self.cache_size_current = 0

        self.piece_last_access: dict[lt.torrent_handle, list[float]] = {}
        self.active_torrents: set[lt.torrent_handle] = set()
        self.cache_full: bool = False
        self.last_upload_time: dict[lt.torrent_handle, float] = {}
        self.last_activity: dict[lt.torrent_handle, float] = {}
        self.todo_set_piece_priority_1: dict[lt.torrent_handle, dict[int, float]] = {}
        self.todo_deactivate_torrent: dict[lt.torrent_handle, float] = {}

        # self.piece_refcount[th]     # number of peers needing piece
        # self.torrent_activity[th]   # popularity score

        self.monitor_torrent_last_msg = None
        self.monitor_peer_info_alert_last_msg = {}
        self.fetch_pieces_last_msg = None

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
            | lt.alert.category_t.status_notification
            | lt.alert.category_t.error_notification
            # peer_connect_alert
            # peer_disconnected_alert
            | lt.alert.category_t.connect_notification
            # peer_snubbed_alert
            # peer_blocked_alert
            | lt.alert.category_t.peer_notification
            | lt.alert.category_t.peer_log_notification
            | lt.alert.category_t.storage_notification
            # | lt.alert.category_t.tracker_notification
            | lt.alert.category_t.piece_progress_notification
            | lt.alert.category_t.progress_notification
            | lt.alert.category_t.upload_notification # block_uploaded_alert
            | lt.alert.category_t.performance_warning
            | lt.alert.category_t.all_categories # debug
        )
        if debug_alerts:
            # NOTE alerts are dropped when too many
            settings["alert_mask"] |= lt.alert.category_t.all_categories
        # settings["send_redundant_have"] = True # send HAVE even if peer already knows
        # settings["lazy_bitfields"] = False # send full bitfield immediately on connect

        # no, share_mode breaks downloading. why?!
        # https://www.libtorrent.org/reference-Settings.html#share_mode_target
        # for lt.torrent_flags.share_mode
        # default: 3
        # settings["share_mode_target"] = (2**63-1) # INT64_MAX = 9223372036854775807

        if 0:
            # debug: default config
            alert_mask = settings["alert_mask"]
            settings = lt.default_settings()
            settings["alert_mask"] = alert_mask

        ses = lt.session(settings)

        # in case ignore_limits_on_local_network is removed one day...
        r'''
        ignore_limits_on_local_network = settings.get("ignore_limits_on_local_network", True)
        if "ignore_limits_on_local_network" in settings:
            del settings["ignore_limits_on_local_network"]

        if ignore_limits_on_local_network == False:

            # https://github.com/arvidn/libtorrent/issues/8356
            # document rate-limiting of local peers

            # also apply upload_rate_limit and download_rate_limit
            # to peers on the local network
            # based on libtorrent/bindings/python/test.py

            # settings = ses.get_settings()

            # define limits for the default global class
            pci = ses.get_peer_class(lt.session.global_peer_class_id)
            pci["upload_limit"] = settings["upload_rate_limit"]
            pci["download_limit"] = settings["download_rate_limit"]
            ses.set_peer_class(lt.session.global_peer_class_id, pci)

            # force all peers into class 0
            pcf = lt.peer_class_type_filter()
            # all TCP peers
            pcf.add(lt.peer_class_type_filter.tcp_socket, lt.session.global_peer_class_id)
            # all UDP peers
            pcf.add(lt.peer_class_type_filter.utp_socket, lt.session.global_peer_class_id)
            ses.set_peer_class_type_filter(pcf)
        '''

        return ses

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

        # the whole point of btcache is
        # to run a bittorrent client with limited disk space
        # so of course we use storage_mode_sparse
        atp.storage_mode = lt.storage_mode_t.storage_mode_sparse

        # disable peer exchange
        # to not leak the hidden_peers
        # TODO add session parameter pex_ip_filter
        # https://github.com/arvidn/libtorrent/issues/8059
        atp.flags |= lt.torrent_flags.disable_pex

        atp.flags &= ~lt.torrent_flags.auto_managed # TODO what

        # no, upload_mode breaks downloading. why?!
        # atp.flags |= lt.torrent_flags.upload_mode # TODO what

        # atp.flags |= lt.torrent_flags.paused  # start paused
        # atp.flags &= ~lt.torrent_flags.paused  # start immediately

        atp.flags |= lt.torrent_flags.sequential_download

        # atp.flags &= ~lt.torrent_flags.has_metadata

        # no, share_mode breaks downloading. why?!
        # https://libtorrent.org/reference-Core.html#torrent_flags_t::share_mode
        # share_mode determines if the torrent should be added in share mode or not.
        # Share mode indicates that we are not interested in downloading the torrent,
        # but merely want to improve our share ratio (i.e. increase it).
        #
        # we enable share_mode
        # to prevent libtorrent from sending upload_only messages
        # to prevent leechers from disconnecting with
        # UPLOAD_ONLY [ the peer is upload-only and we're not interested in it ]
        # atp.flags |= lt.torrent_flags.share_mode

        if 0:
            # debug: default config
            atp = lt.add_torrent_params()
            atp.ti = ti
            atp.save_path = save_path

        th = self.session.add_torrent(atp)

        # no, this has no effect here
        # we have to wait until the torrent is actually seeding in state_changed_alert
        # self.enable_super_seeding(th)

        # TODO use bitfield / bitarray
        self.uploaded_pieces_by_torrent_handle[th] = [False] * ti.num_pieces()

        self.peer_have_pieces[th] = dict()

        self.active_prefetch[th] = set()

        # TODO? instead of time=0, use the current time if we have pieces
        self.piece_last_access[th] = [0] * ti.num_pieces()

        # no, this would use the same CacheEntry instance for all pieces
        # self.cache_state[th] = [CacheEntry()] * ti.num_pieces()
        self.cache_state[th] = [
            CacheEntry()
            for _ in range(ti.num_pieces())
        ]

        self.todo_set_piece_priority_1[th] = {}

        th.resume()

        status = th.status()
        self.logger.info(f"Torrent status after session.add_torrent: state={status.state} progress={status.progress:.2%} bytes={status.total_wanted}")

        return th

    def evict_piece(self, th, piece):
        ti = th.torrent_file()
        btih = str(ti.info_hashes().v1)

        # disable future downloading
        # low priority but NOT zero
        # th.piece_priority(piece, 1)
        # prevent immediate redownload
        th.piece_priority(piece, 0)
        # later: th.piece_priority(piece, 1)
        later = time.time() + 10 # 10 seconds in the future
        self.todo_set_piece_priority_1[th][piece] = later

        # remove piece from disk cache
        # th.flush_cache()

        download_root = th.status().save_path

        fs = ti.files()
        piece_size = ti.piece_size(piece)

        # self.logger.info(f"Evicting piece {piece}: {piece_size} bytes")

        remaining = piece_size
        piece_offset = 0

        while remaining > 0:

            file_slice_list = ti.map_block(piece, piece_offset, remaining)

            for file_slice_idx, file_slice in enumerate(file_slice_list):

                rel_path = fs.file_path(file_slice.file_index)
                full_path = os.path.join(download_root, rel_path)

                self.logger.info(
                    f"evict_piece: {piece}:"
                    f" file={rel_path!r}"
                    f" offset={file_slice.offset}"
                    f" size={file_slice.size}"
                )

                debug_file_size = True

                if debug_file_size:
                    st_before = os.stat(full_path)

                # punch hole into file to free up disk space
                # TODO optimize this for consecutive pieces
                # FIXME verify reduced file size
                fd = os.open(full_path, os.O_RDWR)
                flags = FALLOC_FL_KEEP_SIZE | FALLOC_FL_PUNCH_HOLE
                try:
                    fallocate(fd, flags, file_slice.offset, file_slice.size)
                    if debug_file_size:
                        os.fsync(fd)
                finally:
                    os.close(fd)

                if debug_file_size:
                    # NOTE libtorrent can modify the file
                    # between st_before and fallocate and st_after
                    # so we cannot rely on the stat data
                    st_after = os.stat(full_path)
                    self.logger.info(
                        f"Evicting piece {piece}:"
                        f" blocks before={st_before.st_blocks}"
                        f" after={st_after.st_blocks}"
                    )

                remaining -= file_slice.size
                piece_offset += file_slice.size

        # TODO remove?
        # force libtorrent to read this piece
        # so libtorrent can see that this piece is missing
        # NOTE this does not force libtorrent to actually read the piece from disk
        # instead, libtorrent can read the piece from the RAM cache
        # th.read_piece(piece)

    def piece_exists_on_disk(self, th, piece):
        ti = th.torrent_file()
        fs = ti.files()
        save_path = th.status().save_path
        piece_size = ti.piece_size(piece)
        offset = 0
        remaining = piece_size
        while remaining > 0:
            for fslice in ti.map_block(piece, offset, remaining):
                rel = fs.file_path(fslice.file_index)
                path = os.path.join(save_path, rel)
                try:
                    st = os.stat(path)
                    # hole-punched files may still exist but be sparse
                    if st.st_size == 0:
                        return False
                except FileNotFoundError:
                    return False
                remaining -= fslice.size
                offset += fslice.size
        return True

    def touch_piece(self, th, piece):
        entry = self.cache_state[th][piece]
        if not entry.cached:
            return
        now = time.time()
        entry.last_access = now
        heap_item = (now, th, piece)
        self.cache_lru.push(heap_item)

    def mark_piece_cached(self, th, piece):
        entry = self.cache_state[th][piece]
        if 0:
            # debug
            if entry.cached:
                self.logger.info(
                    f"mark_piece_cached: piece={piece}"
                    f" already cached"
                )
                return
        s2 = self.cache_size_current + th.torrent_file().piece_length()
        self.logger.info(
            f"mark_piece_cached: piece={piece}"
            f" cache usage: {self.cache_size_current} -> {s2}"
        )
        entry.cached = True
        entry.last_access = time.time()
        heap_item = (entry.last_access, th, piece)
        self.cache_lru.push(heap_item)
        # fixed-size accounting
        # assume: all pieces have equal size
        self.cache_size_current += th.torrent_file().piece_length()

    def mark_piece_evicted(self, th, piece):
        entry = self.cache_state[th][piece]
        if 0:
            # debug
            if not entry.cached:
                self.logger.info(
                    f"mark_piece_evicted: piece={piece}"
                    f" not cached"
                )
                return
        self.logger.info(f"mark_piece_evicted: piece={piece}")
        s2 = self.cache_size_current - th.torrent_file().piece_length()
        self.logger.info(
            f"mark_piece_evicted: piece={piece}"
            f" cache usage: {self.cache_size_current} -> {s2}"
        )
        entry.cached = False
        self.cache_size_current -= th.torrent_file().piece_length()

    # ------------------------------------------------------------------
    # Peer management
    # ------------------------------------------------------------------
    def resolve_hostname(self, hostname: str):
        try:
            return socket.gethostbyname(hostname)
        except Exception:
            return None

    def ensure_hidden_peers_connected(self, th: lt.torrent_handle):
        # TODO call this less often
        # once per second may be too much
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

        last_cleanup = 0
        last_set_piece_priority_1 = 0

        while True:
            alerts = self.session.pop_alerts()
            self.monitor_alerts(alerts)

            for host, th_list in self.torrent_handles.items():
                for th in th_list:
                    self.monitor_torrent(th, host)

            now = time.time()
            if now - last_cleanup > 30:
                self.cleanup_inactive_torrents()
                last_cleanup = now

            now = time.time()
            if now - last_set_piece_priority_1 > 10:
                self.set_piece_priority_1()
                last_set_piece_priority_1 = now

            time.sleep(cfg.poll_interval)

    def monitor_alerts(self, alerts):
        now = time.time()
        for a in alerts:
            if isinstance(a, lt.peer_info_alert): # status_notification
                # self.logger.debug("peer_info_alert")
                self.monitor_peer_info_alert(a)
            elif isinstance(a, lt.state_changed_alert): # status_notification
                self.logger.debug(f"state_changed_alert: a.state: {a.prev_state} -> {a.state}")
                # if a.state.seeding:
                #     self.enable_super_seeding(a.handle)

            elif isinstance(a, lt.listen_succeeded_alert): # status_notification
                continue

            elif isinstance(a, lt.block_uploaded_alert): # progress_notification upload_notification
                ip, port = a.ip
                th = a.handle
                piece = a.piece_index
                # self.uploaded_piece_time[a.handle][a.piece_index] = now
                self.touch_piece(th, piece)
                self.last_upload_time[th] = now
                # TODO? wait until the full piece has been uploaded
                self.active_prefetch[a.handle].discard(a.piece_index)
                if self.uploaded_pieces_by_torrent_handle[a.handle][a.piece_index]:
                    # this piece has already started uploading
                    continue

                # # TODO? wait until the full piece has been uploaded
                # peer_id = f"{ip}:{port}"
                # self.peer_have_pieces[a.handle][peer_id][a.piece_index] = True

                # self.logger.debug(f"block_uploaded_alert: torrent={a.handle.torrent_file().info_hashes().v1} piece={a.piece_index} block={a.block_index} peer={ip}:{port}")
                # assume a piece was uploaded when one of its pieces was uploaded
                # we cannot be more strict here
                # because we cannot get the actual "have" bitfield from leech-only peers
                # TODO keep track of time?
                self.uploaded_pieces_by_torrent_handle[a.handle][a.piece_index] = True
                # trigger next incremental fetch
                self.fetch_pieces(a.handle, a.ip)
            elif isinstance(a, lt.peer_connect_alert): # connect_notification
                # too early. no handshake. no bitfield exchange
                ip, port = getattr(a, "ip", None)
                th = a.handle
                btih = str(th.torrent_file().info_hashes().v1)
                self.logger.debug(f"peer_connect_alert: peer={ip}:{port} btih={btih[:7]}")
                # a.pid = peer ID = 0 for anonymous peers
                # self.logger.debug(f"ALERT {type(a).__name__}: category={category_names(a.category())} dir={dir(a)}")
                # no have pieces bitfield here
            # elif isinstance(a, lt.incoming_connection_alert):
            #     # too early. no handshake. no a.handle
            #     ip, port = getattr(a, "ip", None)
            #     self.logger.debug(f"incoming_connection_alert: peer={ip}:{port}")
            elif isinstance(a, lt.peer_disconnected_alert): # connect_notification
                ip, port = getattr(a, "ip", None)
                th = a.handle
                btih = str(th.torrent_file().info_hashes().v1)
                self.logger.debug(f"peer_disconnected_alert: peer={ip}:{port} btih={btih[:7]}")
            elif isinstance(a, lt.peer_snubbed_alert): # peer_notification
                self.logger.debug(f"peer_snubbed_alert: peer={a.ip}")
                # FIXME peer_snubbed_alert: peer=('127.0.0.1', 6880)
                # what?
            elif isinstance(a, lt.peer_blocked_alert): # ip_block_notification
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
            elif isinstance(a, lt.peer_log_alert): # peer_log_notification
                # self.logger.debug(f"peer_log_alert: {a.message()}")
                msg = a.message()
                # remove infohash and peer
                if 0:
                    # show peer log alerts only from this peer
                    leecher_peer = "127.0.0.1:6882"
                    if not f"peer [ {leecher_peer} client:" in msg:
                        continue

                # msg = msg.replace("==> ", "out ==> ").replace(">>> ", "out >>> ")
                # msg = msg.replace("<== ", "inn <== ").replace("<<< ", "inn <<< ")
                # msg = msg.replace("*** ", "nfo *** ")

                # msg = re.sub(r"^.*? peer \[ [0-9.:]+ client: .*? \]( \[[0-9.:]+\])? ", "", msg)
                msg = re.sub(r"^.*? peer \[ ([0-9.:]+) client: .*? \]( \[([0-9.:]+)\])? ", r"peer=\1 ", msg)
                if debug_peer_log_alerts:
                    self.logger.info(f"peer_log_alert: {msg}")
                elif re.search(r"HAVE|INTEREST|CHOKE|EXTENDED_HANDSHAKE", msg):
                    self.logger.info(f"peer_log_alert: {msg}")

                # if "==> EXTENDED_HANDSHAKE" in msg: # send
                # if "<== EXTENDED_HANDSHAKE" in msg: # receive

            elif isinstance(a, lt.block_finished_alert):
                # a block finished downloading
                continue
                th = a.handle
                btih = str(th.torrent_file().info_hashes().v1)
                self.logger.debug(f"block_finished_alert: btih={btih[:7]} piece={a.piece_index} peers={a.handle.get_peer_info()}")
            elif isinstance(a, lt.piece_finished_alert): # piece_progress_notification progress_notification
                # a piece finished downloading and passed the hash check
                th = a.handle
                btih = str(th.torrent_file().info_hashes().v1)
                self.logger.debug(
                    f"piece_finished_alert:"
                    f" btih={btih[:7]}"
                    f" piece={a.piece_index}"
                    # f" peers={a.handle.get_peer_info()}" # libtorrent.peer_info object
                )

                th = a.handle
                piece = a.piece_index

                self.active_prefetch[th].discard(piece)

                self.mark_piece_cached(th, piece)

                self.evict_until_safe()

                # keep piece "interesting"
                # NOTE dont set priority to zero
                # because that would remove the piece from our "have pieces" bitfield
                # and leechers would think we are not interesting and disconnect
                th.piece_priority(piece, 1)

                # no! download != upload
                # TODO? remove in favor of peer_have_pieces
                # self.uploaded_pieces_by_torrent_handle[th][a.piece_index] = True

                # 'handle', 'message', 'piece_index', 'torrent_name', 'what'
                # self.logger.debug(f"piece_finished_alert: a={dir(a)}")
                # self.logger.debug(f"piece_finished_alert: message={a.message()}")

                # no! download != upload
                # TODO? remove in favor of uploaded_pieces_by_torrent_handle
                # peer_id = f""
                # self.peer_have_pieces[th][peer_id][piece] = True

                # no! download != upload
                # self.active_prefetch[th].discard(a.piece_index)

                # TODO remove? fetch_pieces should only be called on upload activity (block_uploaded_alert)
                # self.fetch_pieces(a.handle, a.ip) # AttributeError: 'piece_finished_alert' object has no attribute 'ip'
                # self.fetch_pieces(a.handle)

                # no! download != upload
                # piece = a.piece_index
                # ti = th.torrent_file()
                # size = ti.piece_size(piece)
                # # self.cached_pieces[th] = size
                # self.piece_last_access[th] = time.time()



            # debug: not fetching from seeder

            # redundant with block_finished_alert
            # elif isinstance(a, lt.block_downloading_alert):
            #     if a.block_index == 0:
            #         th = a.handle
            #         btih = str(th.torrent_file().info_hashes().v1)
            #         self.logger.debug(f"block_downloading_alert: btih={btih[:7]} piece={a.piece_index} block={a.block_index} peer={ip}:{port}")

            # redundant with piece_finished_alert
            # elif isinstance(a, lt.block_finished_alert):
            #     # TODO what is the last block index?
            #     # piece_size / block_size
            #     if a.block_index == 0:
            #         th = a.handle
            #         btih = str(th.torrent_file().info_hashes().v1)
            #         self.logger.debug(f"block_finished_alert: btih={btih[:7]} piece={a.piece_index} block={a.block_index} peer={ip}:{port}")

            # block_progress_notification peer_notification progress_notification
            elif isinstance(a, lt.block_timeout_alert):
                ip, port = getattr(a, "ip", None)
                th = a.handle
                btih = str(th.torrent_file().info_hashes().v1)
                self.logger.debug(f"block_timeout_alert: btih={btih[:7]} piece={a.piece_index} block={a.block_index} peer={ip}:{port}")

            elif isinstance(a, lt.peer_error_alert):
                self.logger.debug(f"ALERT {type(a).__name__}: category={category_names(a.category())} dir={dir(a)}")
                self.logger.debug(f"peer_error_alert: {a.message()}")

            elif isinstance(a, lt.peer_unsnubbed_alert): # peer_notification
                self.logger.debug(f"peer_unsnubbed_alert: {a.message()}")

            elif isinstance(a, lt.performance_alert): # performance_warning
                self.logger.debug(f"performance_alert: {a.message()}")

            elif isinstance(a, lt.torrent_log_alert): # torrent_log_notification
                self.logger.debug(f"torrent_log_alert: {a.msg()}")

            elif isinstance(a, lt.log_alert): # session_log_notification
                self.logger.debug(f"log_alert: {a.message()}")

            elif debug_all_alerts:
                # Log all alerts for debugging
                s = f"{type(a).__name__}: {a}"
                ignore_alert = False
                for _s in ignore_alert_strings:
                    if _s in s:
                        ignore_alert = True
                        break
                if ignore_alert: continue
                # self.logger.debug(f"ALERT {type(a).__name__}: {a}")
                self.logger.debug(f"ALERT {type(a).__name__}: category={category_names(a.category())} dir={dir(a)}")

            r'''
            # block_progress_notification progress_notification
            elif isinstance(a, lt.block_downloading_alert):
                self.logger.debug(f"block_downloading_alert: {a.message()}")

            elif isinstance(a, lt.picker_log_alert): # picker_log_notification
                self.logger.debug(f"picker_log_alert: {a.message()}")

            elif isinstance(a, lt.alert): # incoming_request_notification
                continue
                if re.search(r": \[\d+\] \d+ \d+ \d+ \d+ \d+ \d+ \d+ \d+ \d+ \d+$"):
                    # TODO what is this?
                    # maybe 713702 is download speed...
                    # torrent name: [1000] 713702 564 0 14 19840 0 0 19840 0 0
                    # torrent name: [1000] 0 0 0 0 0 0 0 0 0 0
                    continue
                self.logger.debug(f"alert: {a.message()}")
            '''

    def monitor_peer_info_alert(self, a):
        # called from peer_info_alert
        th = a.handle
        peers = th.get_peer_info()
        # update self.peer_have_pieces before calling self.fetch_pieces
        for p in peers:
            ip, port = getattr(p, "ip", None)
            self.peer_have_pieces[th][f"{ip}:{port}"] = list(p.pieces)
        for p in peers:
            ip, port = getattr(p, "ip", None)
            peer_id = f"{ip}:{port}"
            flags = p.flags
            msg = (
                f"monitor_peer_info_alert:"
                f" peer={peer_id}"
                f" pieces={compress_bool_ranges(p.pieces)}"
                f" interesting={bool(flags & lt.peer_info.interesting)}"
                f" choked={bool(flags & lt.peer_info.choked)}"
                f" remote_interested={bool(flags & lt.peer_info.remote_interested)}"
                f" remote_choked={bool(flags & lt.peer_info.remote_choked)}"
            )
            if msg != self.monitor_peer_info_alert_last_msg.get(peer_id):
                self.logger.debug(msg)
                self.monitor_peer_info_alert_last_msg[peer_id] = msg

            # TODO remove? fetch_pieces should only be called on upload activity (block_uploaded_alert)
            # FIXME move this to "Connected peer" -> initial fetch of pieces
            # TODO? call fetch_pieces
            # this is the only event where we get the "haves" bitfield from peers
            # and this is fired only once after the bitfield exchange
            self.fetch_pieces(th, p.ip, p.pieces, peer=p)

    def enable_super_seeding(self, th):
        # enable super seeding mode
        # so we never send upload_only=1 to leechers
        # which would cause leechers to disconnect for 60 seconds
        # so we would need
        # max_incremental_fetch_size: 300MiB # 5MiB/s * 60s

        # https://libtorrent.org/reference-Core.html#torrent_flags_t::super_seeding
        # sets the torrent into super seeding/initial seeding mode.
        # If the torrent is not a seed, this flag has no effect.
        #
        # so we have to wait until the torrent is actually seeding
        # and then we have to call th.set_flags(flags)

        # https://github.com/arvidn/libtorrent/issues/4570
        # Today we have super seeding and
        # this mechanism gives out 1 piece at a time
        # until it spreads in the cluster and then the client moves on
        #
        # problem: that "one piece" is random
        # and can be a piece we dont even have! -> bug in libtorrent
        # https://github.com/arvidn/libtorrent/issues/8355
        # super seeding mode is advertising random pieces it does not have
        flags = th.flags()
        super_seeding = flags & lt.torrent_flags.super_seeding
        if super_seeding != 0:
            return
        # th.set_super_seeding(True) # deprecated
        btih = str(th.torrent_file().info_hashes().v1)
        self.logger.debug(f"enable_super_seeding: enabling super_seeding for {btih}")
        flags |= lt.torrent_flags.super_seeding
        th.set_flags(flags)

    def fetch_pieces(self, th, peer_ip=None, peer_pieces=None, peer=None):
        ti = th.torrent_file()
        num_pieces = ti.num_pieces()
        if peer_pieces is None:
            self.logger.debug("fetch_pieces: no peer_pieces")
            return
        # Determine which pieces peer still needs
        missing = []
        active = self.active_prefetch[th]
        for piece in range(num_pieces):
            # peer already has it
            if peer_pieces[piece]:
                continue
            # already cached locally
            if self.cache_state[th][piece].cached:
                continue
            # already fetching
            if piece in active:
                continue
            missing.append(piece)
        if not missing:
            # self.logger.debug("fetch_pieces: no pieces are missing")
            return
        # Torrent is useful NOW
        self.activate_torrent(th)
        # remember recent activity
        self.last_activity[th] = time.time()
        # Sequential fetch window
        MAX_ACTIVE = 32
        current = len(active)
        if current >= MAX_ACTIVE:
            msg = f"fetch_pieces: active_prefetch is full: {compress_ranges(active)}"
            if msg != self.fetch_pieces_last_msg:
                self.logger.debug(msg)
                self.fetch_pieces_last_msg = msg
            return
        wanted = missing[:MAX_ACTIVE - current]
        self.logger.info(
            "fetch_pieces: scheduling pieces "
            f"{compress_ranges(wanted)}"
        )
        # Enable pieces
        for piece in wanted:
            active.add(piece)
            # HIGH priority
            th.piece_priority(piece, 7)
            try:
                th.set_piece_deadline(piece, 0)
            except Exception:
                pass
        # unlimited bandwidth while active
        th.set_download_limit(0)

    def compute_needed_pieces(self, th, peer_pieces):
        ti = th.torrent_file()
        needed = []
        for piece in range(ti.num_pieces()):
            # peer already has it
            if peer_pieces[piece]:
                continue
            # TODO? dont trust libtorrent: th.have_piece(piece)
            # we already have it cached
            if th.have_piece(piece):
                continue
            # # piece disabled
            # if th.piece_priority(piece) == 0:
            #     continue
            needed.append(piece)
        # return needed[:self.config.max_incremental_fetch]
        return needed

    # FIXME dont oscillate
    # Deactivating torrent
    # Activating torrent
    # Deactivating torrent
    # Activating torrent
    #
    # fix: schedule deactivation
    # and in activate_torrent, remove the scheduled deactivation

    def activate_torrent(self, th):
        # cancel pending deactivation
        self.todo_deactivate_torrent.pop(th, None)
        if th in self.active_torrents:
            return
        self.active_torrents.add(th)
        self.logger.info(f"Activating torrent {th.info_hash()}")
        th.set_download_limit(0)

    def activate_torrent_zzz(self, th):
        # called from fetch_pieces
        if th in self.active_torrents:
            return
        self.active_torrents.add(th)
        self.logger.info(f"Activating torrent {th.info_hash()}")
        th.set_download_limit(0)

    def schedule_deactivate_torrent(self, th):
        # called from cleanup_inactive_torrents
        if th not in self.active_torrents:
            return
        if th in self.todo_deactivate_torrent:
            return
        timeout = 30
        self.todo_deactivate_torrent[th] = time.time() + timeout
        self.logger.info(
            f"Scheduling deactivation of torrent "
            f"{th.info_hash()} in {timeout}s"
        )

    def deactivate_torrent(self, th):
        self.todo_deactivate_torrent.pop(th, None)
        if th not in self.active_torrents:
            return
        self.active_torrents.remove(th)
        self.logger.info(f"Deactivating torrent {th.info_hash()}")
        if self.cache_full:
            th.set_download_limit(1)

    def process_pending_deactivations(self):
        now = time.time()
        for th, deadline in list(self.todo_deactivate_torrent.items()):
            if now < deadline:
                continue
            peers = th.get_peer_info()
            still_interested = False
            for p in peers:
                if p.flags & lt.peer_info.remote_interested:
                    still_interested = True
                    break
            if still_interested:
                # peer still downloading -> postpone
                self.todo_deactivate_torrent[th] = now + 30
                continue
            self.deactivate_torrent(th)

    def deactivate_torrent_zzz(self, th):
        # called from cleanup_inactive_torrents
        if th not in self.active_torrents:
            return
        self.active_torrents.remove(th)
        self.logger.info(f"Deactivating torrent {th.info_hash()}")
        if self.cache_full:
            th.set_download_limit(1)

    def cleanup_inactive_torrents(self):
        # called periodically from monitor_loop
        # we mutate self.active_torrents
        # so we have to get a copy with list()
        now = time.time()
        for th in list(self.active_torrents):
            last = self.last_upload_time.get(th, 0)
            if now - last < 30:
                continue
            peers = th.get_peer_info()
            interested = False
            for p in peers:
                if p.flags & lt.peer_info.remote_interested:
                    interested = True
                    break
            if interested:
                continue
            self.schedule_deactivate_torrent(th)

    def get_total_cache_usage_bytes(self):
        # also count files that do not belong to torrents
        usage = 0
        for root, dirs, files in os.walk(self.config.save_dir):
            for name in files:
                path = os.path.join(root, name)
                try:
                    st = os.stat(path)
                except FileNotFoundError:
                    continue
                usage += st.st_blocks * 512
        return usage

    def get_cache_usage_bytes(self):
        usage = 0
        visited = set()
        for th_list in self.torrent_handles.values():
            for th in th_list:
                ti = th.torrent_file()
                if ti is None:
                    continue
                save_path = th.status().save_path
                fs = ti.files()
                for file_index in range(fs.num_files()):
                    rel_path = fs.file_path(file_index)
                    full_path = os.path.join(save_path, rel_path)
                    # avoid double-counting shared files
                    if full_path in visited:
                        continue
                    visited.add(full_path)
                    try:
                        st = os.stat(full_path)
                    except FileNotFoundError:
                        continue
                    # actual allocated disk blocks
                    usage += st.st_blocks * 512
        return usage

    def set_piece_priority_1(self):
        # called periodically from monitor_loop
        now = time.time()
        for th, piece_later in self.todo_set_piece_priority_1.items():
            # we mutate piece_later
            # so we have to get a copy with list()
            for piece, later in list(piece_later.items()):
                if later < now:
                    continue
                # the time has come!
                th.piece_priority(piece, 1)
                del piece_later[piece]

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
            btih = str(tf.info_hashes().v1)

            # Collect fetching and have piece indices
            # fetching_pieces = [i for i, v in enumerate(status.pieces) if not v and th.piece_priority(i) > 0]
            # prefetching_pieces = [i for i, v in enumerate(status.pieces) if not v and th.piece_priority(i) == 7]
            have_pieces = [i for i, v in enumerate(status.pieces) if v]

            flags = th.flags()
            sequential_download = bool(flags & lt.torrent_flags.sequential_download)

            msg = (
                f"monitor_torrent: host={host}:"
                # f" btih={btih}"
                f" btih={btih[:7]}"
                f" state={status.state}"
                # f" progress={status.total_wanted_done}/{status.total_wanted} bytes ({status.progress:.2%})"
                f" progress={status.progress:.2%}"
                # f" done_pieces={len(have_pieces)}/{len(status.pieces)}"
                # f" download={status.download_rate} B/s"
                # f" upload={status.upload_rate} B/s"
                # torrent_settings: rate_limit_ip_overhead: false
                # noisy. dont add these to last_msg
                # f" download={status.download_payload_rate} B/s"
                # f" upload={status.upload_payload_rate} B/s"
                f" have={compress_ranges(have_pieces)}/{len(status.pieces)}"
                # f" fetching={compress_ranges(fetching_pieces)}"
                f" fetching={compress_ranges(self.active_prefetch[th])}"
                f" num_peers={status.num_peers}"
                f" num_seeds={status.num_seeds}"
                f" sequential_download={sequential_download}"
                # f" dir(status)={dir(status)}" # debug
            )
            if msg != self.monitor_torrent_last_msg:
                self.monitor_torrent_last_msg = msg
                msg += (
                    f" download={status.download_payload_rate} B/s"
                    f" upload={status.upload_payload_rate} B/s"
                )
                self.logger.info(msg)

            if status.state.downloading:
                self.ensure_hidden_peers_connected(th)

        except Exception as e:
            self.logger.info(f"Error fetching status for torrent: {e}")

    def evict_until_safe(self):
        target_rel = 0.8
        target = int(self.cache_size * target_rel)
        if self.cache_size_current <= self.cache_size:
            self.logger.info(
                f"evict_until_safe:"
                f" usage={self.cache_size_current/self.cache_size:%}"
                f" target={target_rel:%}"
            )
            return
        # self.logger.info(
        #     f"evict_until_safe:"
        #     f" usage={self.cache_size_current/self.cache_size:%}"
        #     f" target={target/self.cache_size:%}"
        # )
        self.logger.info(
            f"evict_until_safe:"
            f" usage={self.cache_size_current/self.cache_size:%}"
            f" target={target_rel:%}"
        )
        while (
            self.cache_size_current > target
            and self.cache_lru
        ):
            last_access, th, piece = self.cache_lru.pop()
            entry = self.cache_state[th][piece]
            # stale heap entry
            if entry.last_access != last_access:
                continue
            # already evicted
            if not entry.cached:
                continue
            # never evict active download
            if piece in self.active_prefetch[th]:
                continue
            self.evict_piece(th, piece)
            self.mark_piece_evicted(th, piece)

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


# https://gist.github.com/NicolasT/1194957

import ctypes
import ctypes.util
import io

c_off_t = ctypes.c_int64

def make_fallocate():
    libc_name = ctypes.util.find_library('c')
    libc = ctypes.CDLL(libc_name)

    _fallocate = libc.fallocate
    _fallocate.restype = ctypes.c_int
    _fallocate.argtypes = [ctypes.c_int, ctypes.c_int, c_off_t, c_off_t]

    del libc
    del libc_name

    def fallocate(fd, mode, offset, len_):
        if isinstance(fd, io.IOBase):
            fd = fd.fileno()
        res = _fallocate(fd, mode, offset, len_)
        if res != 0:
            raise IOError(res, 'fallocate')

    return fallocate

fallocate = make_fallocate()
del make_fallocate

FALLOC_FL_KEEP_SIZE = 0x01
FALLOC_FL_PUNCH_HOLE = 0x02

r'''
def main(db):
    orig_data = ''.join(chr(i) for i in xrange(10))
    format_ = lambda s: [ord(c) for c in s]

    with open(db, 'w') as fd:
        fd.write(orig_data)

    with open(db, 'r') as fd:
        data = fd.read()
        print 'Original value:', format_(data)

    print 'Punching hole at offset 2, length 3'
    with open(db, 'a') as fd:
        fallocate(fd, FALLOC_FL_KEEP_SIZE | FALLOC_FL_PUNCH_HOLE, 2, 3)

    print 'Reading file'
    with open(db, 'r') as fd:
        data = fd.read()
        print 'New value:', format_(data)
'''


def category_names(mask: int):
    names = []
    for name in dir(lt.alert.category_t):
        if name.startswith('_'):
            continue
        val = getattr(lt.alert.category_t, name)
        # Values in category_t are ints, ignore non-ints
        if isinstance(val, int) and (mask & val):
            names.append(name)
    if "all_categories" in names:
        names.remove("all_categories")
    return names


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
