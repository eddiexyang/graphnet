# GraphNet

A centrally managed overlay network with administrator-defined graph topology,
weighted multi-hop routing and peer-to-peer data transport.

## Run the controller

```sh
go build -o bin/graphnet ./cmd/graphnet
# Required only for the first initialization. Choose your own strong password.
export GRAPHNET_ADMIN_PASSWORD='replace-with-your-own-password'
./bin/graphnet server --data-dir ./graphnet-data
```

The default listener is `https://127.0.0.1:8443`. The controller creates a private
CA and exports its public certificate to `graphnet-data/ca.pem`; trust this file
on administrative clients. Supply `--tls-hosts` with your deployment's DNS names
and IPs, and `--listen` to expose it on the intended interface. Keep the data
directory private and back it up: it contains the CA key and configuration.
`--http --listen 127.0.0.1:8080` enables a loopback-only development server.

Open the controller URL in a browser and sign in to the management UI. Setting
a different password environment variable on restart does not replace the stored password.

The administrative CLI supports `graphnet network create`,
`graphnet network list`, `graphnet node list` and `graphnet edge add`, with JSON
output, verified HTTPS and revision-checked updates.

## Run a Linux agent

Create an enrollment invitation from **Agents → Enroll agent**, save it as
`agent-invitation.txt`, then register and run:

```sh
sudo ./bin/graphnet agent enroll --invitation-file ./agent-invitation.txt \
  --name laptop --data-dir /var/lib/graphnet-agent
sudo ./bin/graphnet agent run --data-dir /var/lib/graphnet-agent
```

The invitation includes Server addresses, transport types, the cluster CA public
certificate and a one-use token. No separate `--server`, `--server-transport` or
`--ca` is required. Treat the invitation as a credential; Base64 is not encryption.
Use `--invitation-file -` for stdin or `GRAPHNET_AGENT_INVITATION` for automation.
Enrollment saves identity and exits without starting a service. Repeating it for
the same cluster preserves the existing identity; another cluster is rejected.
The legacy `graphnet agent --server ...` enrollment remains supported.

Agent control connections accept `--server-transport tcp|websocket|grpc|wss`
(default `tcp`, also configurable with `GRAPHNET_SERVER_TRANSPORT`). All four
carriers share the controller's existing listen port and preserve the inner
TLS 1.3 authentication and WebSocket control protocol. `--server` and
`--server-transport` apply only to first enrollment. After registration, the Agent
uses its persistent Server directory and cached CA, updates that directory from
controller snapshots, and automatically switches entrances or Servers on failure.
Restarting with different bootstrap flags does not override the cached directory.

TUN setup requires root or `CAP_NET_ADMIN`. Add the enrolled Agent to a Network
with a fixed virtual address, then create the desired Edges. Linux automatically
advertises TCP/UDP endpoints from underlay interfaces; manual endpoints are also
supported. QUIC uses explicit manual URLs.
New Agents automatically discover public mappings using configurable STUN services.
The default peer listen port is 24752. No controller packet relay is
used. Agents keep forwarding and can restart from cached configuration while the
controller is unavailable.

Nodes can advertise external subnets within a Network, with optional automatic
gateway forwarding and Linux SNAT. External OS routes remain administrator-managed.

## Known issues

- **Mixed packet and stream transport paths:** TCP from an Agent whose first hop is packet-only `udp` crosses as packets; a later stream-backed hop (`tcp`, `quic`) refuses it rather than run TCP over TCP, and a relay cannot seal it as a session for the Source. Datagrams cross any mix. Keep TCP paths that start on `udp` on `udp`, or start them on `tcp` or `quic`.

## Development

Requires Go 1.26 or newer. CI pins Go 1.26.8 and Node.js 24.21.0 in
`.go-version` and `.node-version`; use those versions to reproduce its builds.
Frontend development uses pnpm 10.33.3. Production assets are checked in so a Go-only checkout
builds a complete binary. Rebuild assets whenever frontend sources change.

```sh
go test ./...
pnpm --dir web install --frozen-lockfile
pnpm --dir web build
```

Version tags such as `v1.2.3` trigger cross-platform builds and a GitHub Release
with one standalone binary per target.
