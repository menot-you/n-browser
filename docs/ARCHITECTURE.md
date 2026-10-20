# nBROWSER architecture

```mermaid
flowchart LR
    Client[MCP or CLI caller] --> Inner[Observation and local computation]
    Inner --> Seam[AuthoritySeam]
    subgraph Effects[Effect boundary]
        Seam --> Guard[SSRF and request guard]
        Guard --> Browser[Isolated Chromium context]
        Guard --> Static[Static HTTP extraction]
        Browser --> Vault[Origin-bound login vault]
        Browser --> Capture[Explicit capture retention]
    end
    subgraph External[External network]
        Browser --> Site[Admitted web origins]
        Static --> Site
        Seam --> Search[Optional keyed search providers]
    end
    Inner --> Evidence[Snapshot and session-owned evidence]
    Evidence --> Client
```

The inner ring observes existing DOM or fixtures without host mutation.
The effect ring performs navigation, network access, capture, and interaction through `AuthoritySeam`.
The SSRF kernel judges public and loopback targets before egress.
The runtime interceptor also judges browser subresource requests.
The crawl frontier limits only navigation to the seed origin.

The vault encrypts passwords locally. Its request gate binds password use to the recorded origin.
Temporary contexts isolate browser profiles. Session references do not become durable history.
Capture retention needs an explicit choice and, for managed retention, a host grant.
Search sends terms to every configured keyed provider.
Fetched page text remains untrusted input.

[seam.py](../nbrowser/seam.py) defines effect admission.
[session.py](../nbrowser/session.py) owns the browser context.
[egress_guard.py](../nbrowser/egress_guard.py) owns request rules.
[auth.py](../nbrowser/auth.py) owns vault custody.

Use the [runbook](RUNBOOK.md) for setup, failure diagnosis, backup, and restoration.
The [reference](REFERENCE.md) links each public interface to its source.
