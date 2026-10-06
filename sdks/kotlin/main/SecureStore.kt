package com.snaplink.sso

import java.util.concurrent.ConcurrentHashMap

/**
 * The SDK's key/value boundary for app-private records: the one-use PKCE
 * transaction, the token set, and a pending activation ticket.
 *
 * Values are opaque, versioned records the client encodes; an implementation
 * stores them verbatim and never inspects them. A storage failure must raise
 * [SnaplinkAuthException] with code `secure_storage_error` rather than return
 * an empty value, because the client cannot tell a lost record from an absent
 * one and would treat a fabricated answer as a live session.
 *
 * Concurrency: transaction consumption is serialised inside one process only.
 * A store shared by several processes must make read-then-delete of a single
 * transaction effectively single-use.
 */
public interface SnaplinkSecureStore {
    /** Returns the stored record, or null when the key holds no record. */
    public fun read(key: String): String?

    /** Stores [value] under [key], replacing any previous record. */
    public fun write(key: String, value: String)

    /** Removes [key]. An absent key is a success, not a failure. */
    public fun delete(key: String)
}

/**
 * An unencrypted in-process [SnaplinkSecureStore], for unit tests, examples,
 * and single-process development. Tokens live in heap with no
 * confidentiality: this is not a production choice on a device, which is why
 * [AndroidSecureStore] remains the default for every public constructor.
 */
public class SnaplinkMemorySecureStore : SnaplinkSecureStore {
    private val values = ConcurrentHashMap<String, String>()

    override fun read(key: String): String? = values[key]

    override fun write(key: String, value: String) {
        values[key] = value
    }

    override fun delete(key: String) {
        values.remove(key)
    }
}