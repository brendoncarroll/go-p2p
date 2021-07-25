# Message Based Application Platform Protocol
MBAPP (*em-bee-app*) is a protocol for reliable Asks on top of a `SecureSwarm`.
It also allows passthrough of Tells.

MBAPP supports carrying deadline information, and status codes over the wire.
It also performs message fragmentation and reassembly.
This allows the application to send messages which exceed the MTU of the underlying transport.

## Wire Format
MBAPP prepends a 20 byte header to each message.

