# ZK-CDS

 A hypothetical design of a zero-knowledge contact discovery service (CDS).

## Goals

 The top-level goal is for clients to map their address books of phone numbers to user IDs (or
 other equivalent tokens), while preserving the following properties:

1. The server only learns a phone number is in a client's address book when and if the client
   refers to their user ID.
2. The client can only refer to a user ID iff they know the phone number for that user ID.
3. The client cannot make offline guesses about phone numbers.

## Setup

### Server

 A server is initialized with a secret scalar, `d_S`, and a map of phone numbers to user IDs. The
 server creates an internal mapping of blinded data.

 For each `(p, u)` pair, the server performs the following steps:

1. Hashes the phone number to a point on the curve: `P = hash2curve(p)`
2. Calculates the server-blinded phone number point: `sP = [d_S]P`
3. Encodes the user ID via a bijective mapping (e.g. try-and-increment) as a point on the curve:
   `U = encode2curve(p)`
4. Hashes the phone number: `h = SHA256(p)`
5. Calculates the double-blinded phone number point: `psU = [h*d_S]U`

 The server then groups pairs of `(sP, hsU)` values by an `N`-bit prefix of `h`.

### Client

A client is initialized with a secret scalar, `d_C` and a set of phone numbers `{p_0…p_N}`.

## The Contact Discovery Flow

To map a phone number `p` to a user ID `u`, the client performs the following steps:

1. Hashes the phone number: `h = SHA256(p)`
2. Hashes the phone number to a point on the curve: `P = hash2curve(p)`
3. Calculates the client-blinded phone number point: `cP = [d_C]P`

The client sends an `N`-bit prefix of `h` and `cP` to the server (not necessarily in the same
request). The prefix of `h` can serve as an `N`-bit distinguisher of `p`, so `N` should be chosen to
ensure a collision rate which preserves the privacy of `p`. `cP` cannot serve as a distinguisher of
`p` without knowing `d_C`. Consequently, the server learns no information about `p` from this
request.

The server calculates the double-blinded point `scP = [d_S]cP` and returns it along with a set of
`(sP, hsU)` pairs with the corresponding prefix of `h`. Without `d_S`, the client cannot calculate
`P` or `U` values, and cannot learn anything about the original `p` or `u` values. At most, the
client learns the cardinality of the response set and can estimate the size of the server's full
address book.

The client calculates the server-blinded point `sP = [(1/d_C)]scP` and searches for it in the set
of pairs. If a pair exists with `sP`, the client calculates the server-blinded user ID point
`sU = [(1/h)]hsU`. The client sends `sU` to the server, who fully unblinds it (`U = [(1/d_S)]sU`)
and decodes the point into a user ID `u` (e.g. in order to connect the two users and i.e. without
returning `u` to the client). The use of `sU` as a proxy for `u` allows the server to keep `u`
values entirely private (if desired), and the server only learns of the client's knowledge of `p`
when and if the client attempts to use that client.

Finally, an attacker attempting to discover whether the server has specific `p` values will be
unable to do so without making online requests and can thus be rate-limited.

## Bucket Size

Assuming a user base of 100M users, a 15-bit hash prefix would yield buckets of around 3K phone
numbers, with a total response size of 197KiB. A 12-bit hash prefix would yield buckets of around
25K phone numbers, with a total response size of 1.54MiB.

## License

Copyright © 2023 Coda Hale
