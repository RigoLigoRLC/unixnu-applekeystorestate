// SPDX-License-Identifier: BSD-2-Clause-Patent
// AppleKeyStore supplies the unchanged iPadOS 17.7.11 libaks state interface and
// software wrapping of ordinary keychain keys. The platform supplies a private,
// persistent 256-bit root key. securityd owns the keychain database and stores
// the wrapped keys there. The root key has no hardware isolation or passcode
// protection; the service remains unlocked and supports no Secure Enclave keys.
#include <IOKit/IOService.h>
#include <IOKit/IOUserClient.h>
#include <libkern/c++/OSBoolean.h>
#include <libkern/crypto/aes.h>
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wextern-c-compat"
#include <libkern/crypto/crypto_internal.h>
#pragma clang diagnostic pop
#include <corecrypto/cc.h>
extern "C" void native_keyevents_open_refused(void);
extern "C" bool native_aks_state_enabled(void);
extern "C" uint32_t native_aks_lock_state(void);
extern "C" void native_aks_call(uint32_t selector, int32_t result);
extern "C" void native_aks_opened(void);

// Platforms without a persistent private key retain the state-only interface.
extern "C" __attribute__((weak)) bool native_aks_copy_software_key(uint8_t *, size_t) {
    return false;
}

namespace {
constexpr uint32_t kSelLockState = 7, kSelGetSystem = 14, kSelDeviceState = 17, kSelExtendedDeviceState = 35;
constexpr uint32_t kSelWrapKey = 10;
constexpr uint32_t kSelUnwrapKey = 11;
constexpr uint32_t kSelBagUUID = 23;
constexpr uint32_t kSelGeneration = 40;
constexpr uint64_t kUnlockedSinceBoot = 4;
constexpr uint32_t kStateFlags = 4;
constexpr uint64_t kSystemHandle = 0;
constexpr size_t kRootKeyBytes = 32;
constexpr size_t kMaximumKeyBytes = 128;
constexpr size_t kWrapOverhead = 8;
constexpr IOReturn kAksError = (IOReturn)0xe00002bc;   // what libaks reports itself when the connection is missing
constexpr IOReturn kAksUnsupported = (IOReturn)0xe00002c7;

bool cryptoAvailable() {
    return g_crypto_funcs && g_crypto_funcs->ccaes_cbc_encrypt &&
        g_crypto_funcs->ccaes_cbc_decrypt && g_crypto_funcs->cchmac_fn &&
        g_crypto_funcs->ccsha256_di;
}

bool softwareKeyAvailable() {
    uint8_t key[kRootKeyBytes];
    bool available = cryptoAvailable() && native_aks_copy_software_key(key, sizeof(key));
    cc_clear(sizeof(key), key);

    return available;
}

void storeBigEndian32(uint8_t *out, uint32_t value) {
    for (unsigned index = 0; index < sizeof(value); ++index) {
        out[index] = static_cast<uint8_t>(value >> (24 - index * 8));
    }
}

// Each purpose and key class receives a separate HMAC-SHA256-derived AES key.
bool deriveSoftwareKey(const char *purpose, size_t purposeLength,
                       uint32_t keyClass, uint8_t out[kRootKeyBytes]) {
    uint8_t root[kRootKeyBytes];
    uint8_t input[64];
    if (!cryptoAvailable() || purposeLength > sizeof(input) - 8 ||
        !native_aks_copy_software_key(root, sizeof(root))) {
        cc_clear(sizeof(root), root);
        return false;
    }

    memcpy(input, purpose, purposeLength);
    storeBigEndian32(input + purposeLength, static_cast<uint32_t>(kSystemHandle));
    storeBigEndian32(input + purposeLength + 4, keyClass);
    g_crypto_funcs->cchmac_fn(g_crypto_funcs->ccsha256_di, sizeof(root), root,
        purposeLength + 8, input, out);
    cc_clear(sizeof(root), root);
    cc_clear(sizeof(input), input);

    return true;
}

bool hasOutputCapacity(const IOExternalMethodArguments *args, size_t length) {
    if (args->structureOutputDescriptor) {
        return length <= args->structureOutputDescriptor->getLength();
    }

    return args->structureOutput && length <= args->structureOutputSize;
}

IOReturn writeOutput(IOExternalMethodArguments *args, const uint8_t *bytes, size_t length) {
    if (!hasOutputCapacity(args, length)) {
        return kIOReturnNoSpace;
    }

    if (args->structureOutputDescriptor) {
        if (args->structureOutputDescriptor->writeBytes(0, bytes, length) != length) {
            return kIOReturnIOError;
        }
        args->structureOutputDescriptorSize = length;
    } else {
        memcpy(args->structureOutput, bytes, length);
        args->structureOutputSize = static_cast<uint32_t>(length);
    }

    return kIOReturnSuccess;
}

size_t inputLength(const IOExternalMethodArguments *args) {
    if (args->structureInputDescriptor) {
        return args->structureInputDescriptor->getLength();
    }

    return args->structureInputSize;
}

bool readInput(const IOExternalMethodArguments *args, uint8_t *bytes, size_t length) {
    if (args->structureInputDescriptor) {
        return args->structureInputDescriptor->readBytes(0, bytes, length) == length;
    }
    if (!args->structureInput) {
        return false;
    }

    memcpy(bytes, args->structureInput, length);

    return true;
}

// RFC 3394 stores [eight-byte integrity value, encrypted eight-byte key parts].
// The AES helpers apply one ECB block using the registered software CBC mode.
IOReturn wrapKey(const uint8_t key[kRootKeyBytes], const uint8_t *input,
                 size_t length, uint8_t *output) {
    aes_encrypt_ctx context;
    uint8_t block[16];
    uint8_t encrypted[16];
    memset(output, 0xa6, kWrapOverhead);
    memcpy(output + kWrapOverhead, input, length);
    int result = aes_encrypt_key(key, kRootKeyBytes, &context);
    size_t parts = length / kWrapOverhead;

    for (unsigned round = 0; round < 6 && !result; ++round) {
        for (size_t part = 1; part <= parts; ++part) {
            memcpy(block, output, kWrapOverhead);
            memcpy(block + kWrapOverhead, output + part * kWrapOverhead, kWrapOverhead);
            result = aes_encrypt(block, encrypted, &context);
            if (result) {
                break;
            }

            uint64_t counter = parts * round + part;
            for (unsigned index = 0; index < kWrapOverhead; ++index) {
                output[index] = encrypted[index] ^
                    static_cast<uint8_t>(counter >> (56 - index * 8));
            }
            memcpy(output + part * kWrapOverhead, encrypted + kWrapOverhead, kWrapOverhead);
        }
    }

    cc_clear(sizeof(context), &context);
    cc_clear(sizeof(block), block);
    cc_clear(sizeof(encrypted), encrypted);

    return result ? kAksError : kIOReturnSuccess;
}

IOReturn unwrapKey(const uint8_t key[kRootKeyBytes], const uint8_t *input,
                   size_t length, uint8_t *output) {
    aes_decrypt_ctx context;
    uint8_t accumulator[kWrapOverhead];
    uint8_t block[16];
    uint8_t decrypted[16];
    memcpy(accumulator, input, sizeof(accumulator));
    memcpy(output, input + kWrapOverhead, length - kWrapOverhead);
    int result = aes_decrypt_key(key, kRootKeyBytes, &context);
    size_t parts = length / kWrapOverhead - 1;

    for (int round = 5; round >= 0 && !result; --round) {
        for (size_t part = parts; part > 0; --part) {
            uint64_t counter = parts * static_cast<unsigned>(round) + part;
            for (unsigned index = 0; index < kWrapOverhead; ++index) {
                block[index] = accumulator[index] ^
                    static_cast<uint8_t>(counter >> (56 - index * 8));
            }
            memcpy(block + kWrapOverhead, output + (part - 1) * kWrapOverhead, kWrapOverhead);
            result = aes_decrypt(block, decrypted, &context);
            if (result) {
                break;
            }

            memcpy(accumulator, decrypted, sizeof(accumulator));
            memcpy(output + (part - 1) * kWrapOverhead, decrypted + kWrapOverhead, kWrapOverhead);
        }
    }

    uint8_t difference = 0;
    for (uint8_t byte : accumulator) {
        difference |= byte ^ 0xa6;
    }

    cc_clear(sizeof(context), &context);
    cc_clear(sizeof(accumulator), accumulator);
    cc_clear(sizeof(block), block);
    cc_clear(sizeof(decrypted), decrypted);

    return result || difference ? kAksError : kIOReturnSuccess;
}

IOReturn cryptKey(uint32_t selector, IOExternalMethodArguments *args) {
    bool wrapping = selector == kSelWrapKey;
    if (args->scalarInputCount != 2 || !args->scalarInput ||
        args->scalarInput[0] != kSystemHandle ||
        args->scalarOutputCount != (wrapping ? 1u : 0u) ||
        (wrapping && !args->scalarOutput)) {
        return kIOReturnBadArgument;
    }

    // Classes 1 through 11 cover file and ordinary keychain keys. Class 12
    // requires a passcode, which this permanently unlocked service cannot bind.
    uint64_t keyClass = args->scalarInput[1];
    if (keyClass == 0 || keyClass > 11) {
        return kAksUnsupported;
    }

    size_t length = inputLength(args);
    size_t minimum = wrapping ? 16 : 16 + kWrapOverhead;
    size_t maximum = wrapping ? kMaximumKeyBytes : kMaximumKeyBytes + kWrapOverhead;
    if (length < minimum || length > maximum || (length % kWrapOverhead) != 0) {
        return kIOReturnBadArgument;
    }

    size_t outputLength = wrapping ? length + kWrapOverhead : length - kWrapOverhead;
    if (!hasOutputCapacity(args, outputLength)) {
        return kIOReturnNoSpace;
    }

    uint8_t key[kRootKeyBytes];
    static constexpr char purpose[] = "UniXNU AppleKeyStore software key v1";
    if (!deriveSoftwareKey(purpose, sizeof(purpose), static_cast<uint32_t>(keyClass), key)) {
        return kIOReturnNotReady;
    }

    uint8_t input[kMaximumKeyBytes + kWrapOverhead];
    uint8_t output[kMaximumKeyBytes + kWrapOverhead];
    IOReturn result = kIOReturnBadArgument;
    if (readInput(args, input, length)) {
        result = wrapping ? wrapKey(key, input, length, output) :
            unwrapKey(key, input, length, output);
        if (result == kIOReturnSuccess) {
            result = writeOutput(args, output, outputLength);
        }
    }

    if (result == kIOReturnSuccess && wrapping) {
        args->scalarOutput[0] = keyClass;
        args->scalarOutputCount = 1;
    }
    cc_clear(sizeof(key), key);
    cc_clear(sizeof(input), input);
    cc_clear(sizeof(output), output);

    return result;
}

IOReturn bagUUID(IOExternalMethodArguments *args) {
    if (args->scalarInputCount != 1 || !args->scalarInput ||
        args->scalarInput[0] != kSystemHandle || args->scalarOutputCount != 0) {
        return kIOReturnBadArgument;
    }

    uint8_t key[kRootKeyBytes];
    static constexpr char purpose[] = "UniXNU AppleKeyStore bag uuid v1";
    if (!deriveSoftwareKey(purpose, sizeof(purpose), 0, key)) {
        return kIOReturnNotReady;
    }

    key[6] = (key[6] & 0x0f) | 0x40;
    key[8] = (key[8] & 0x3f) | 0x80;
    IOReturn result = writeOutput(args, key, 16);
    cc_clear(sizeof(key), key);

    return result;
}

struct DerWriter {
    uint8_t *p; size_t cap, n = 0; bool ok = true;
    void put(uint8_t b) { if (n < cap) p[n++] = b; else ok = false; }
    void len(size_t l) { if (l < 0x80) put((uint8_t)l); else { put(0x81); put((uint8_t)l); } }   // entries stay below 256 bytes
};
// Smallest two's-complement big-endian INTEGER content for a non-negative value.
size_t derIntegerContent(uint64_t v, uint8_t out[9]) {
    uint8_t raw[8];
    for (int i = 0; i < 8; ++i) raw[i] = (uint8_t)(v >> (56 - 8 * i));
    size_t start = 0;
    while (start < 7 && raw[start] == 0) ++start;
    size_t n = 0;
    if (raw[start] & 0x80) out[n++] = 0;
    while (start < 8) out[n++] = raw[start++];
    return n;
}
size_t entrySize(const char *key, uint64_t value) {
    uint8_t c[9]; size_t kl = 0; while (key[kl]) ++kl;
    size_t body = (2 + kl) + (2 + derIntegerContent(value, c));
    return 2 + body;
}
}  // namespace

// DER SET of SEQUENCE{UTF8String, INTEGER}. Returns the length, or 0 when the buffer is too small.
extern "C" size_t native_aks_encode_state(uint8_t *out, size_t capacity, uint32_t lockState) {
    struct Entry { const char *key; uint64_t value; };
    const Entry entries[] = {{"ss", kStateFlags}, {"sls", lockState}, {"sb", 0}, {"sfa", 0}, {"sgs", 0},
                             {"sas", 0}, {"sgpe", 0}, {"srcd", 0}, {"sms", 0}, {"bh", 0}};
    size_t total = 0;
    for (const Entry &e : entries) total += entrySize(e.key, e.value);
    DerWriter w{out, capacity};
    w.put(0x31); w.len(total);
    for (const Entry &e : entries) {
        uint8_t c[9]; size_t kl = 0; while (e.key[kl]) ++kl;
        size_t il = derIntegerContent(e.value, c);
        w.put(0x30); w.len((2 + kl) + (2 + il));
        w.put(0x0c); w.put((uint8_t)kl); for (size_t i = 0; i < kl; ++i) w.put((uint8_t)e.key[i]);
        w.put(0x02); w.put((uint8_t)il); for (size_t i = 0; i < il; ++i) w.put(c[i]);
    }
    return w.ok ? w.n : 0;
}

// AppleKeyStoreUserClient accepts the original libaks scalar and structure
// layouts. securityd persists wrapped keys; unwrapping releases plaintext only
// after the RFC 3394 integrity value has been checked.
class AppleKeyStoreUserClient final : public IOUserClient {
    OSDeclareDefaultStructors(AppleKeyStoreUserClient)
    bool keyOperationsAllowed = false;
public:
    void configureKeyAccess(task_t task) {
        OSObject *entitlement = IOUserClient::copyClientEntitlement(
            task, "com.apple.keystore.access-keychain-keys");
        keyOperationsAllowed = entitlement == kOSBooleanTrue;
        OSSafeReleaseNULL(entitlement);
    }

    IOReturn clientClose() override { terminate(); return kIOReturnSuccess; }
    IOReturn externalMethod(uint32_t selector, IOExternalMethodArguments *args, IOExternalMethodDispatch *,
                            OSObject *, void *) override {
        IOReturn rc = kAksUnsupported;
        if (!args) rc = kAksError;
        else switch (selector) {
        // Handshake right after IOServiceOpen (a failure makes libaks drop the connection and reopen on every call), and the
        // assertion and notification calls retain the permanently unlocked state.
        case 0: case 4: case 5: case 9: case 12: case 13: case 26: case 27: case 55: case 101: case 102:
            args->scalarOutputCount = 0;
            rc = kIOReturnSuccess;
            break;
        case kSelWrapKey:
        case kSelUnwrapKey:
            rc = keyOperationsAllowed ? cryptKey(selector, args) : kIOReturnNotPrivileged;
            break;
        case kSelBagUUID:
            rc = bagUUID(args);
            break;
        case kSelGeneration:
            if (args->scalarInputCount != 2 || !args->scalarInput ||
                args->scalarInput[0] != kSystemHandle || args->scalarInput[1] != 0 ||
                args->scalarOutputCount != 1 || !args->scalarOutput) {
                rc = kIOReturnBadArgument;
                break;
            }
            args->scalarOutput[0] = 0;
            args->scalarOutputCount = 1;
            rc = kIOReturnSuccess;
            break;
        case kSelGetSystem:
            if (args->scalarOutputCount < 1 || !args->scalarOutput) { rc = kIOReturnBadArgument; break; }
            args->scalarOutput[0] = kSystemHandle;
            args->scalarOutputCount = 1;
            rc = kIOReturnSuccess;
            break;
        case kSelLockState:
            rc = (args->scalarInputCount == 1 && args->scalarOutputCount == 1 && args->scalarOutput)
                     ? kIOReturnSuccess : kIOReturnBadArgument;
            if (rc == kIOReturnSuccess) args->scalarOutput[0] = kUnlockedSinceBoot;
            break;
        case kSelDeviceState:
        case kSelExtendedDeviceState: {
            if (args->scalarInputCount > 1 || args->scalarOutputCount != 0) { rc = kIOReturnBadArgument; break; }
            uint8_t der[160];
            size_t n = native_aks_encode_state(der, sizeof der, native_aks_lock_state());
            if (!n) { rc = kIOReturnNoSpace; break; }
            if (args->structureOutputDescriptor) {
                if (n > args->structureOutputDescriptor->getLength()) { rc = kIOReturnNoSpace; break; }
                args->structureOutputDescriptor->writeBytes(0, der, n);
                args->structureOutputDescriptorSize = (uint32_t)n;
                rc = kIOReturnSuccess;
            } else if (args->structureOutput && n <= args->structureOutputSize) {
                for (size_t k = 0; k < n; ++k) ((uint8_t *)args->structureOutput)[k] = der[k];
                args->structureOutputSize = (uint32_t)n;
                rc = kIOReturnSuccess;
            } else {
                rc = kIOReturnNoSpace;
            }
            break;
        }
        default: break;
        }
        native_aks_call(selector, (int32_t)rc);
        return rc;
    }
};
OSDefineMetaClassAndStructors(AppleKeyStoreUserClient, IOUserClient)

// AppleKeyStore publishes the original service name and software key wrapping
// availability. Board registration owns the private root key and service start.
class AppleKeyStore final : public IOService {
    OSDeclareDefaultStructors(AppleKeyStore)
    IOReturn open(task_t task, void *security, UInt32 type, OSDictionary *properties, IOUserClient **out) {
        if (out) *out = nullptr;
        if (!native_aks_state_enabled() || !out) { native_keyevents_open_refused(); return kIOReturnNotReady; }
        AppleKeyStoreUserClient *client = new AppleKeyStoreUserClient;
        if (!client) return kIOReturnNoMemory;
        if (!client->initWithTask(task, security, type, properties) || !client->attach(this)) {
            client->release(); return kIOReturnError;
        }
        client->configureKeyAccess(task);
        if (!client->start(this)) { client->detach(this); client->release(); return kIOReturnError; }
        native_aks_opened();
        *out = client;
        return kIOReturnSuccess;
    }
public:
    bool start(IOService *provider) override {
        if (!IOService::start(provider)) return false;
        bool softwareKeys = softwareKeyAvailable();
        setName("Native software keystore service");
        if (!setProperty("NativeKeyStoreEvents", true) ||
            !setProperty("KeyOperationsAvailable", softwareKeys) ||
            !setProperty("SoftwareKeyWrapping", softwareKeys) ||
            !setProperty("HardwareKeyIsolation", false)) {
            IOService::stop(provider);
            return false;
        }
        registerService();
        return true;
    }
    IOReturn newUserClient(task_t t, void *s, UInt32 type, OSDictionary *p, IOUserClient **out) override {
        return open(t, s, type, p, out);
    }
    IOReturn newUserClient(task_t t, void *s, UInt32 type, IOUserClient **out) override {
        return open(t, s, type, nullptr, out);
    }
};
OSDefineMetaClassAndStructors(AppleKeyStore, IOService)
extern "C" IOService *native_keyevents_allocate(void) { return new AppleKeyStore; }
