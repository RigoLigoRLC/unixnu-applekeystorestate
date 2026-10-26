# AppleKeyStoreState

AppleKeyStore supplies the state queries and software key wrapping interface
used by the unchanged iPadOS 17.7.11 / 21H461 AppleKeyStore framework.

The board enables the service with `sheng-aks=1` and supplies the existing state,
registration and diagnostic callbacks. State queries and the existing handshake,
notification and assertion selectors retain their permanently unlocked behavior.

## Software key wrapping

The optional board callback
`bool native_aks_copy_software_key(uint8_t *out, size_t capacity)` copies the same
private 32-byte random root key on every boot. Its weak default returns false,
which leaves key operations unavailable. A board must persist that key outside
the public source and retain it across builds and ordinary Data updates. Replacing
it makes previously wrapped keychain keys unreadable.

The provider derives a separate 256-bit AES key for each key class using
HMAC-SHA256, then wraps keys with RFC 3394. Unwrapping checks the eight-byte
integrity value before copying plaintext to the caller. Temporary root keys,
derived keys, AES contexts and plaintext buffers are cleared after use.

| Selector | Input | Output |
| --- | --- | --- |
| 10, `aks_wrap_key` | Bag handle 0, class 1 through 11, 16 through 128 key bytes in multiples of eight | Wrapped key bytes and the unchanged actual class |
| 11, `aks_unwrap_key` | Bag handle 0, class 1 through 11, previously wrapped key bytes | Original key bytes after the integrity check |
| 23, `aks_get_bag_uuid` | Bag handle 0 | A stable 16-byte UUID derived from the private root key |
| 40, `aks_generation` | Bag handle 0 and options 0 | Generation 0 |

`securityd` retains ownership of item encryption, the keychain database and item
access rules. It stores the wrapped AES keys in its existing Data database. The
provider stores no separate database and creates no replacement pairing records.

The root key resides in software and has no hardware isolation or passcode
protection. Class 12, additional keybags, key rotation and Secure Enclave
reference-key operations remain unsupported. The user client reads the Boolean
`com.apple.keystore.access-keychain-keys` entitlement when it opens. Selectors 10
and 11 require that entitlement; other callers receive `kIOReturnNotPrivileged`.
Installed applications use the native Security service for ordinary item access.

The service publishes `KeyOperationsAvailable` and `SoftwareKeyWrapping` when
both the private root key and the registered crypto functions are available.
`HardwareKeyIsolation` is false.

Build and interface details: [documentation](https://unixnu.com/reference/components). Component sources and dependencies: [catalog](https://unixnu.com/reference/components).
