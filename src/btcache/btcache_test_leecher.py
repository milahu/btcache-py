#!/usr/bin/env python3

# btcache_test_leecher.py

import os
import re
import sys
import time
import socket
import logging
import argparse
import itertools

import libtorrent as lt

# seconds between alert checks / actions
POLL_INTERVAL = 1.0

debug_alerts = 0
# debug_alerts = 1

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
ignore_alert_types = tuple()

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
# ignore_alert_strings = []


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
    default_save_path = "btcache-test-leecher-downloads"
    parser.add_argument(
        "--save-path", # args.save_path
        default=default_save_path,
        help=f"downloads directory for metadata and content files. default: {default_save_path}",
    )
    parser.add_argument(
        "--enable-dht", # args.enable_dht,
        action="store_true",
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
    settings['enable_dht'] = args.enable_dht
    settings['active_tracker_limit'] = 0 # disable trackers?
    settings["allow_multiple_connections_per_ip"] = True
    # settings['allow_multiple_connections_per_ip'] = True # only needed in btcache
    if not args.enable_seeding:
        # disable seeding per session
        # FIXME what is upload_rate_limit=0? "disable upload" or "unlimited upload"?
        settings['upload_rate_limit'] = 0
        # no? this breaks leeching?
        # settings['enable_incoming_utp'] = False
        # settings['enable_incoming_tcp'] = False
    if debug_alerts:
        # Enable alerts
        settings["alert_mask"] = (
            0 
            | lt.alert.category_t.status_notification
            | lt.alert.category_t.error_notification
            | lt.alert.category_t.peer_notification
            | lt.alert.category_t.torrent_log_notification
            | lt.alert.category_t.stats_notification
            | lt.alert.category_t.peer_log_notification # peer_log_alert # verbose
            | lt.alert.category_t.storage_notification
            | lt.alert.category_t.tracker_notification
            | lt.alert.category_t.performance_warning
            # | lt.alert.category_t.progress_notification # block_finished_alert piece_finished_alert
            # | lt.alert.category_t.block_progress_notification # block_finished_alert
            # | lt.alert.category_t.piece_progress_notification # piece_finished_alert
            # TODO lt.peer_disconnected_alert
            # | lt.alert.category_t.all_categories # debug
            # TODO performance_alerts
            | lt.alert.category_t.block_progress_notification
            | lt.alert.category_t.connect_notification # peer_disconnected_alert
            | lt.alert.category_t.debug_notification
            | lt.alert.category_t.dht_log_notification
            | lt.alert.category_t.dht_notification
            | lt.alert.category_t.dht_operation_notification
            | lt.alert.category_t.error_notification
            | lt.alert.category_t.file_progress_notification
            | lt.alert.category_t.incoming_request_notification
            | lt.alert.category_t.ip_block_notification
            | lt.alert.category_t.peer_notification
            | lt.alert.category_t.performance_warning
            | lt.alert.category_t.picker_log_notification
            | lt.alert.category_t.piece_progress_notification
            | lt.alert.category_t.port_mapping_log_notification
            | lt.alert.category_t.port_mapping_notification
            | lt.alert.category_t.progress_notification
            | lt.alert.category_t.session_log_notification
            | lt.alert.category_t.stats_notification
            | lt.alert.category_t.storage_notification
            | lt.alert.category_t.torrent_log_notification
            | lt.alert.category_t.tracker_notification
            | lt.alert.category_t.upload_notification
        )
    ses = lt.session(settings)

    # create torrent handle
    torrent_path = os.path.join(args.save_path, f"{btih_hex}.torrent")
    info_hash_bytes = bytes.fromhex(btih_hex)
    # https://libtorrent.org/reference-Add_Torrent.html
    atp = lt.add_torrent_params()
    if os.path.exists(torrent_path):
        logger.info(f"Loading metadata from {torrent_path!r}")
        ti = lt.torrent_info(torrent_path)
        atp.ti = ti
    else:
        logger.info(f"No metadata file at {torrent_path!r}, using infohash mode")
        atp.info_hash = lt.sha1_hash(info_hash_bytes)
    atp.save_path = args.save_path
    atp.flags &= ~lt.torrent_flags.auto_managed
    atp.flags &= ~lt.torrent_flags.paused  # start immediately
    atp.flags |= lt.torrent_flags.sequential_download
    atp.trackers = []  # no trackers
    if not args.enable_seeding:
        # disable seeding per torrent
        atp.upload_limit = 0
    th = ses.add_torrent(atp)
    # th.set_upload_limit(0) # override session upload_limit

    # default?
    # if atp.ti:
    #     th.prioritize_pieces([1] * atp.ti.num_pieces())
    # else:
    #     pass
    #     # TODO later: call th.prioritize_pieces

    if not args.enable_seeding:
        # leech-only client
        th.set_upload_limit(0)  # no upload # TODO verify

    # manually add the peer
    th.connect_peer((peer_ip, peer_port))
    dt_connect_peer = 0

    logger.info(f"Listening on {args.listen}, trying to connect to peer {peer_ip}:{peer_port}")
    logger.info(f"Infohash: {btih_hex}")

    last_msg = None
    last_peer_msg = {}

    connect_peer_time = 0
    done_connect_peer = False

    while True:

        # # manually add the peer
        # th.connect_peer((peer_ip, peer_port))

        # if not done_connect_peer:
        #     if dt_connect_peer == connect_peer_time:
        #         logger.info(f"connecting to peer {peer_ip}:{peer_port}")
        #         th.connect_peer((peer_ip, peer_port))
        #         done_connect_peer = True
        #     else:
        #         dt_connect_peer += 1

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

        debug_alerts_2 = 0
        # debug_alerts_2 = 1

        live_status = None

        def get_message(alert):
            message = alert.message()
            # remove infohash and peer
            message = re.sub(r"^.*? peer \[ [0-9.:]+ client: .*? \]( \[[0-9.:]+\])? ", "", message)
            return message

        if debug_alerts:
            alerts = ses.pop_alerts()
            for a in alerts:
                # if isinstance(a, lt.peer_info_alert):
                #     self.monitor_peer_info_alert(a)
                if isinstance(a, lt.peer_disconnected_alert): # connect_notification
                    logger.info(f"Peer disconnected: {get_message(a)}")
                elif isinstance(a, lt.peer_error_alert):
                    logger.debug(f"ALERT {type(a).__name__}: category={category_names(a.category())} dir={dir(a)}")
                    logger.error(f"Peer error: {get_message(a)}")
                elif isinstance(a, lt.peer_log_alert): # peer_log_notification
                    msg = get_message(a)
                    # if 1: # debug
                    if re.search(r"HAVE|INTEREST|CHOKE", msg):
                        logger.info(f"Peer log: {msg}")
                    # if "<== EXTENDED_HANDSHAKE" in msg:
                    #     raise 555
                elif isinstance(a, lt.torrent_error_alert):
                    logger.debug(f"ALERT {type(a).__name__}: category={category_names(a.category())} dir={dir(a)}")
                    logger.error(f"Torrent error: {a.message()}")
                elif isinstance(a, lt.block_finished_alert):
                    # no. these alerts are not emmitted live
                    # logger.debug(f"ALERT {type(a).__name__}: category={category_names(a.category())} dir={dir(a)}")
                    # torrent={a.handle.torrent_file().name()}
                    # logger.debug(f"Block finished: piece={a.piece_index} block={a.block_index}")
                    pass
                elif isinstance(a, lt.piece_finished_alert):
                    # no. these alerts are not emmitted live
                    # logger.debug(f"ALERT {type(a).__name__}: category={category_names(a.category())} dir={dir(a)}")
                    # logger.debug(f"Piece finished: piece={a.piece_index}")
                    pass
                elif isinstance(a, lt.state_changed_alert): # status_notification
                    logger.debug(f"state_changed_alert: a.state: {a.prev_state} -> {a.state}")
                    # if a.state.seeding:
                    #     self.enable_super_seeding(a.handle)
                    # TODO
                    # if has metadata
                    #   prioritize_pieces(1)
                elif isinstance(a, lt.state_update_alert):
                    # logger.debug(f"state_update_alert")
                    # requested by ses.post_torrent_updates()
                    for st in a.status:
                        if st.handle == th:
                            # logger.debug(f"state_update_alert: updating live_status")
                            live_status = st # get live status
                            break
                elif debug_alerts_2:
                    # Log all alerts for debugging
                    s = f"{type(a).__name__}: {a}"
                    ignore_alert = False
                    for _s in ignore_alert_strings:
                        if _s in s:
                            ignore_alert = True
                            break
                    if ignore_alert: continue
                    logger.debug(f"ALERT {type(a).__name__}: category={category_names(a.category())} alert={a}")

        # logger.info connected peers
        try:
            peers = th.get_peer_info()
            # enable frequent updates of progress
            # request lt.state_update_alert
            ses.post_torrent_updates()
            # no. this has no effect on the frequency of progress updates
            # enable frequent updates of progress
            # by default, progress is updated only once per minute
            # status = th.status(lt.torrent_handle.query_pieces)
            if live_status:
                # logger.debug(f"status: using live status")
                status = live_status
            else:
                # FIXME this is always reached. why no live_status?
                # logger.debug(f"status: using cached status - FIXME")
                status = th.status()
            fetching_pieces = [i for i, v in enumerate(status.pieces) if not v and th.piece_priority(i) > 0]
            done_pieces = [i for i, v in enumerate(status.pieces) if v]
            num_done_pieces = len(list(filter(lambda x: x, status.pieces)))

            msg = (
                f"state={status.state}"
                # f" progress={status.total_wanted_done}/{status.total_wanted} bytes ({status.progress:.2%})"
                f" progress={status.progress:.2%}"
                # f" done_pieces={num_done_pieces}/{len(status.pieces)}"
                f" done_pieces={compress_ranges(done_pieces)}/{len(status.pieces)}"
                f" fetching_pieces={compress_ranges(fetching_pieces)}"
                # noisy. dont add these to last_msg
                # f" download={status.download_payload_rate} B/s"
                # f" upload={status.upload_payload_rate} B/s"
            )
            if msg != last_msg:
                last_msg = msg
                msg += (
                    f" download={status.download_payload_rate} B/s"
                    f" upload={status.upload_payload_rate} B/s"
                )
                logger.info(msg)

            for p in peers:
                ip, port = getattr(p, "ip", None)
                peer_id = f"{ip}:{port}"
                flags = p.flags
                msg = (
                    # f" "
                    f" peer={peer_id}"
                    f" interesting={bool(flags & lt.peer_info.interesting)}"
                    f" choked={bool(flags & lt.peer_info.choked)}"
                    f" remote_interested={bool(flags & lt.peer_info.remote_interested)}"
                    f" remote_choked={bool(flags & lt.peer_info.remote_choked)}"
                )
                if msg != last_peer_msg.get(peer_id):
                    logger.info(msg)
                    last_peer_msg[peer_id] = msg

            if status.progress == 1:
                logger.info(f"download is complete -> exit")
                sys.exit()

        except Exception as e:
            logger.info(f"Error querying peers: {e}")

        time.sleep(POLL_INTERVAL)


if __name__ == "__main__":
    main()
