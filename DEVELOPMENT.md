# Development for `swampd`

## Send test packet to swampd

The `send.py` script in `./scripts/` is a lightweight dummy client used solely for testing and debugging the daemon.

```sh
python3 ./scripts/send.py 0600_29f57a6d_f2ffffff
```

## Packet Layout

| Offset (bytes) | Size (bytes) | Field     | Type    | Description                                                                  |
| -------------- | ------------ | --------- | ------- | ---------------------------------------------------------------------------- |
| 0              | 2            | `length`  | `u16`   | Total packet length (including these 2 bytes). Must be < 1500.               |
| 2              | 4            | `hash`    | `u32`   | Universal Swamp Type hash of the payload (payload only). See Hash Algorithm. |
| 6              | *N*          | `payload` | `bytes` | Actual data payload. Length = (`length` − 4).                                |

> **Note:** Payload length = `length` minus the 4 bytes used by the `hash` field.
