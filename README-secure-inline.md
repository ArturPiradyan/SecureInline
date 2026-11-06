# Secure inline TCP packet prototype (Linux)

This lab prototype relays Ethernet frames between a host-facing and a peer-facing interface. It uses an authenticated ephemeral X25519 exchange on a separate TCP control connection, derives a 256-bit session key with HKDF-SHA-256, then protects selected IPv4/TCP payloads with AES-256-GCM. Protected frame payload bytes are encoded as:

```
ciphertext || 12-byte nonce || 16-byte GCM tag
```

No UDP tunnel or data-plane protocol header is added. The IPv4 and TCP headers are retained; IP total length and the IP/TCP checksums are updated to account for the trailer. Nonces have a role-specific 32-bit prefix and a monotonically increasing 64-bit counter. The two directions use separate prefixes. The shared PSK authenticates the handshake and must be provisioned identically at both devices.

## Build

Requires Linux, a C compiler, OpenSSL development headers/libraries, and root or `CAP_NET_RAW` privileges:

```sh
make
```

## Run

Run one command on each device. `host-if` faces its attached PC, `peer-if` faces the other device, `peer-mac` is the MAC address of the other device's peer-facing interface, `tcp-port` selects the TCP traffic to protect, and `host-mac` is the attached PC's MAC address.

Device 2, listening for the authenticated control connection:

```sh
sudo ./secure_inline listen 192.0.2.1 47000 <64-hex-character-PSK> eth-host eth-peer 02:00:00:00:00:01 443 02:00:00:00:00:10
```

Device 1, connecting to Device 2:

```sh
sudo ./secure_inline connect 192.0.2.2 47000 <same-PSK> eth-host eth-peer 02:00:00:00:00:02 443 02:00:00:00:00:20
```

The control port must be reachable between the devices, and the selected TCP traffic must traverse both devices. Start the listener before the connector. Use a fresh PSK or restart both peers for each lab session. Do not pass the PSK in a shared shell history in a real environment.

## Scope and limitations

This is a packet-format and crypto prototype, not a transparent general-purpose TCP security appliance. Adding the 28-byte nonce/tag trailer increases each protected TCP segment's sequence-space length. A generic TCP path therefore needs per-flow sequence and acknowledgment translation, plus retransmission, segmentation, SACK, fragmentation, and replay-window handling. This prototype does not implement those features, so ordinary end-to-end TCP applications should not be expected to work reliably. Test with crafted packets or an isolated lab harness. It also does not implement key rotation or robust session resumption. Do not use it on production traffic.

The handshake is mutually authenticated with a pre-shared key; plain unauthenticated DH would allow a man-in-the-middle to negotiate separate keys. Data packet authentication failures are dropped. Current packet selection is by IPv4 TCP port only.
