# Account store fixture (0.12.0)

`accounts-plaintext.json` is the plaintext of an `accounts.dat` written by the 0.12.0 `AltStore`, built
from the v0.12.0 sources: three accounts added with `AltStore.addAccount` (one with every field and two
servers' bans, one with the fewest fields, one with an empty ban map and a non-ASCII name), flushed, and
decrypted with the 0.12.0 `EncryptionUtil`. `StoreFormatCompatTest` seals it as the store does, loads it
and saves it again, and requires the same bytes back. Never regenerate it: the test is against what 0.12
wrote.

The tokens and names in it are test values and grant nothing.
