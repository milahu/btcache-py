#!/usr/bin/env python3

import os
import re
import io
import time
import logging
import argparse
import ipaddress
import socket
import itertools
from urllib.parse import urlparse

import libtorrent as lt
import torf

# seconds between alert checks / actions
POLL_INTERVAL = 1.0

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
    lt.piece_finished_alert,
)
# ignore_alert_types = tuple()

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
    "piece_finished_alert:",
    ": on_piece_hashed, m_checking_piece:",
    ": fastresume data rejected:",
    ": start_checking, m_checking_piece:",
    ": on_piece_hashed, completed",
    " finished downloading",
]
# ignore_alert_strings = []


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
        # default="0.0.0.0:6881,[::]:6881",
        # NOTE These are also used for outgoing uTP and UDP tracker connections and DHT nodes.
        help="Listen address:port. example: 127.0.0.1:6881",
    )
    parser.add_argument(
        "--save", # args.save
        default="btcache-seeder-downloads",
        help="Folder where the torrent data is stored",
    )
    parser.add_argument(
        "--allowed-peers", # args.allowed_peers
        metavar="ADDR",
        nargs="+",
        help="List of allowed peers by IP address",
    )
    parser.add_argument(
        "--socks5-proxy", # args.socks5_proxy
        help=(
            "Send all connections through a SOCKS5 proxy. Example: 127.0.0.1:1080."
            " Example proxy server:"
            # TODO does this work for seeding?!
            # no, this is not needed for seeding!
            # for seeding, we need to listen on 127.0.0.1
            # and use port forwarding (ssh -R) like
            #   ssh user@example.com -4 -N -o ExitOnForwardFailure=yes -R 0.0.0.0:6881:127.0.0.1:6881
            # " ssh user@example.com -4 -N -o ExitOnForwardFailure=yes -D 127.0.0.1:1080 -R 0.0.0.0:6881:127.0.0.1:6881"
            # " ssh user@example.com -4 -N -o ExitOnForwardFailure=yes -R 0.0.0.0:6881:127.0.0.1:6881"
            " ssh user@example.com -4 -N -o ExitOnForwardFailure=yes -D 127.0.0.1:1080"
        ),
    )
    parser.add_argument(
        # https://www.libtorrent.org/reference-Settings.html#outgoing_interfaces
        # When outgoing interfaces are specified,
        # incoming connections or packets sent to a local interface or IP that's not in this list
        # will be rejected with a peer_blocked_alert with invalid_local_interface as the reason.
        "--outgoing-interfaces", # args.outgoing_interfaces
    )
    parser.add_argument(
        "--enable-trackers", # args.enable_trackers
        action="store_true",
    )
    parser.add_argument(
        "--enable-dht", # args.enable_dht
        action="store_true",
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
    settings['enable_dht'] = args.enable_dht
    settings["allow_multiple_connections_per_ip"] = True
    if not args.enable_trackers:
        # TODO implement the setting enable_trackers in libtorrent
        # https://github.com/arvidn/libtorrent/issues/8050
        if 'enable_trackers' in settings:
            settings['enable_trackers'] = False
        settings['active_tracker_limit'] = 0 # disable trackers # FIXME not working
    # settings['allow_multiple_connections_per_ip'] = True # only needed in btcache
    if debug_alerts:
        # Enable alerts
        settings["alert_mask"] = (
            lt.alert.category_t.status_notification
            | lt.alert.category_t.error_notification
            | lt.alert.category_t.peer_notification
            | lt.alert.category_t.peer_log_notification # peer_log_alert
            | lt.alert.category_t.storage_notification
            | lt.alert.category_t.tracker_notification
            | lt.alert.category_t.performance_warning
            # | lt.alert.category_t.all_categories # debug
        )

    if args.socks5_proxy:
        # https://www.libtorrent.org/reference-Settings.html#proxy_hostname
        # Note that when using a proxy,
        # the settings_pack::listen_interfaces setting is overridden
        # and only a single interface is created, just to contact the proxy.
        # This means a proxy cannot be combined with SSL torrents or multiple listen interfaces.
        # This proxy listen interface will not accept incoming TCP connections,
        # will not map ports with any gateway and will not enable local service discovery.
        # All traffic is supposed to be channeled through the proxy.
        if args.socks5_proxy.startswith("socks5://"):
            args.socks5_proxy = "socks5h://" + args.socks5_proxy.lstrip("socks5://")
        elif not args.socks5_proxy.startswith("socks5h://"):
            args.socks5_proxy = "socks5h://" + args.socks5_proxy
        logger.info(f"using proxy server {args.socks5_proxy}")
        proxy = urlparse(args.socks5_proxy)
        settings['proxy_type'] = lt.proxy_type_t.socks5
        settings['proxy_hostname'] = proxy.hostname
        settings['proxy_port'] = proxy.port
        settings['proxy_username'] = proxy.username or ""
        settings['proxy_password'] = proxy.password or ""
        settings['proxy_hostnames'] = True # avoid DNS leaks
        settings['proxy_peer_connections'] = True
        settings['proxy_tracker_connections'] = True
        settings['proxy_hostnames'] = True

    if args.outgoing_interfaces:
        settings["outgoing_interfaces"] = args.outgoing_interfaces

    # Create session
    ses = lt.session(settings)

    if args.allowed_peers:
        logger.info(f"setting ip filter: allowing peers {args.allowed_peers}")
        ses.set_ip_filter(get_ip_filter_of_allowed_peers(args.allowed_peers))
    else:
        logger.info("not setting ip filter")

    # Load torrent info
    ti = None
    if 'enable_trackers' in settings or args.enable_trackers:
        ti = lt.torrent_info(args.torrent)
        # ti.trackers = lambda: [] # not working
        # there is ti.add_tracker but no ti.remove_tracker or ti.remove_trackers
    else:
        # workaround: use torf to remove trackers
        # NOTE torf does not support v2 torrents
        torrent = torf.Torrent.read(args.torrent)
        torrent.trackers = [] # remove trackers
        buf = io.BytesIO()
        torrent.write_stream(buf)
        ti = lt.torrent_info(buf.getvalue())
        del buf

    # Add torrent with auto_managed=False, paused=False
    atp = lt.add_torrent_params()
    atp.ti = ti
    atp.save_path = args.save
    # disable PEX to keep our hidden peers hidden
    atp.flags = atp.flags | lt.torrent_flags.disable_pex
    atp.flags &= ~lt.torrent_flags.auto_managed
    atp.flags &= ~lt.torrent_flags.paused  # start immediately
    atp.trackers = []  # disable trackers # FIXME not working

    th = ses.add_torrent(atp)

    logger.info(f"Listening on {args.listen}")

    try:
        last_msg = None
        while True:
            status = th.status()
            peers = th.get_peer_info()
            msg = (
                f"Seeding torrent:"
                f" btih={th.info_hash()}"
                f" state={status.state}"
                # f" peers={peers}" # [<libtorrent.peer_info object>]
                f" uploaded={status.total_upload}"
            )
            if msg != last_msg:
                logger.info(msg)
                last_msg = msg
            for p in peers:
                ip, port = getattr(p, "ip", None)
                pieces_bitfield = getattr(p, "pieces", [])
                missing_pieces = [i for i, has in enumerate(pieces_bitfield) if not has]
                missing_piece_ranges = compress_ranges(missing_pieces)
                logger.info(f"  peer {ip}:{port} missing pieces: {missing_piece_ranges}")

            def get_message(alert):
                message = alert.message()
                # remove infohash and peer
                message = re.sub(r"^.*? peer \[ [0-9.:]+ client: .*? \]( \[[0-9.:]+\])? ", "", message)
                return message

            if debug_alerts:
                alerts = ses.pop_alerts()
                for a in alerts:
                    if isinstance(a, lt.peer_info_alert):
                        self.monitor_peer_info_alert(a)
                    elif isinstance(a, lt.peer_disconnected_alert):
                        logger.info(f"Peer disconnected: {get_message(a)}")
                    elif isinstance(a, lt.peer_error_alert):
                        logger.debug(f"ALERT {type(a).__name__}: category={category_names(a.category())} dir={dir(a)}")
                        logger.error(f"Peer error: {get_message(a)}")
                    elif isinstance(a, lt.peer_log_alert): # peer_log_notification
                        msg = get_message(a)
                        if re.search(r"HAVE|INTEREST|CHOKE|EXTENDED_HANDSHAKE", msg):
                            logger.info(f"Peer log: {msg}")
                    elif isinstance(a, lt.torrent_error_alert):
                        logger.debug(f"ALERT {type(a).__name__}: category={category_names(a.category())} dir={dir(a)}")
                        logger.error(f"Torrent error: {a.message()}")
                    elif isinstance(a, lt.block_finished_alert):
                        logger.debug(f"Block finished: torrent={a.handle.torrent_file().name()} index={a.piece_index}")
                        # trigger next incremental fetch
                        th = self.torrent_handles.get(a.handle)  # map handle -> torrent
                        if th:
                            self.monitor_peer_next_batch(th)
                    # elif isinstance(a, lt.piece_finished_alert):
                    #     logger.debug(f"Piece finished: torrent={a.handle.torrent_file().name()} index={a.piece_index}")
                    elif debug_alerts:
                        # Log all alerts for debugging
                        s = f"{type(a).__name__}: {a}"
                        ignore_alert = False
                        for _s in ignore_alert_strings:
                            if _s in s:
                                ignore_alert = True
                                break
                        if ignore_alert: continue
                        logger.debug(f"ALERT {type(a).__name__}: {a}")

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


if __name__ == "__main__":
    main()
