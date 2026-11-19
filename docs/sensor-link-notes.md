# VN sensor link: protocol notes (incomplete)

The field sensor gateway (`10.20.0.77`) reports to the ground station (`10.20.0.10`) over **UDP, destination port 5555**. One UDP datagram carries exactly one VN frame. The office-network sample capture contains this traffic.

These notes were recovered from an old engineering wiki and are incomplete.

## Frame layout

| Offset | Size | Field | Notes |
|---|---|---|---|
| 0 | 2 | magic | ASCII `VN` (`56 4E`) |
| 2 | 1 | version | currently `1` |
| 3 | 1 | type | see below |
| 4 | 2 | seq | sequence counter |
| 6 | 1 | length | payload length in bytes (N) |
| 7 | N | payload | depends on type |
| 7+N | 2 | crc | CRC over bytes `0 .. 6+N` (everything before the CRC) |

## Frame types

| Type | Meaning | Payload |
|---|---|---|
| `0x01` | temperature | signed 16-bit integer, hundredths of a degree Celsius |
| `0x02` | battery | unsigned 16-bit integer, millivolts |
| `0x07` | text fragment | ASCII characters; a text message is split across several fragments |

## CRC

CRC-16/CCITT-FALSE: polynomial `0x1021`, initial value `0xFFFF`, no input or output reflection, final XOR `0x0000`. The standard check value for the ASCII string `123456789` is `0x29B1`.

## Worked example

The first VN frame in the sample capture, as it appears on the wire (the UDP payload):

```
56 4E 01 01 F0 00 02 34 09 93 D2
```

- payload `34 09` = 23.56 °C
- the CRC-16/CCITT-FALSE of the first 9 bytes is `0xD293`
