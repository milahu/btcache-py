# btcache-py

a caching BitTorrent proxy for hidden seeders, written in Python

btcache-py is a proxy between hidden seeders and public leechers

It does ...

- Fetch `.torrent` files from "hidden peers" (seeders) and cache them locally
- Add torrents to a session with all piece priorities set to zero (no download by default)
- Observe torrent swarms and detect leechers
- Incrementally enable piece downloads to satisfy leechers
- Keep hidden peers hidden by disabling PEX
- Optionally store content files in a content-addressed storage (CAS) layout

## related

- https://code.google.com/archive/p/btcache/
- https://geti2p.net/en/docs/applications/bittorrent
- https://www.tribler.org/anonymity.html - Tor-inspired onion routing
- https://github.com/milahu/btcache-go
