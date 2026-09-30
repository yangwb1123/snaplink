package com.snaplink.sso

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/** AES-GCM encrypted, app-private storage backed by an Android Keystore key. */
internal class AndroidSecureStore(context: Context) : SnaplinkSecureStore {
    private val preferences = context.applicationContext.getSharedPreferences(PREFERENCES, Context.MODE_PRIVATE)

    override fun read(key: String): String? = synchronized(KEY_LOCK) {
        val encoded = preferences.getString(storageKey(key), null) ?: return@synchronized null
        try {
            val packed = Base64.decode(encoded, Base64.NO_WRAP)
            if (packed.size <= GCM_NONCE_BYTES) throw IllegalArgumentException("truncated ciphertext")
            val nonce = packed.copyOfRange(0, GCM_NONCE_BYTES)
            val ciphertext = packed.copyOfRange(GCM_NONCE_BYTES, packed.size)
            val cipher = Cipher.getInstance(TRANSFORMATION)
            cipher.init(Cipher.DECRYPT_MODE, getOrCreateKey(), GCMParameterSpec(GCM_TAG_BITS, nonce))
            cipher.updateAAD(key.toByteArray(Charsets.UTF_8))
            val plaintext = cipher.doFinal(ciphertext)
            if (plaintext.size > MAX_VALUE_BYTES) throw IllegalArgumentException("secure value exceeds limit")
            plaintext.toString(Charsets.UTF_8)
        } catch (error: Exception) {
            throw SnaplinkAuthException("secure_storage_error", "could not decrypt secure SDK storage", cause = error)
        }
    }

    override fun write(key: String, value: String) = synchronized(KEY_LOCK) {
        val plaintext = value.toByteArray(Charsets.UTF_8)
        if (plaintext.size > MAX_VALUE_BYTES) {
            throw SnaplinkAuthException("secure_storage_error", "secure value exceeds the SDK storage limit")
        }
        try {
            val cipher = Cipher.getInstance(TRANSFORMATION)
            cipher.init(Cipher.ENCRYPT_MODE, getOrCreateKey())
            cipher.updateAAD(key.toByteArray(Charsets.UTF_8))
            val packed = cipher.iv + cipher.doFinal(plaintext)
            val saved = preferences.edit().putString(storageKey(key), Base64.encodeToString(packed, Base64.NO_WRAP)).commit()
            if (!saved) throw IllegalStateException("SharedPreferences commit failed")
        } catch (error: Exception) {
            if (error is SnaplinkAuthException) throw error
            throw SnaplinkAuthException("secure_storage_error", "could not encrypt secure SDK storage", cause = error)
        }
    }

    override fun delete(key: String) = synchronized(KEY_LOCK) {
        if (!preferences.edit().remove(storageKey(key)).commit()) {
            throw SnaplinkAuthException("secure_storage_error", "could not remove secure SDK storage")
        }
    }

    private fun storageKey(key: String): String {
        val digest = java.security.MessageDigest.getInstance("SHA-256").digest(key.toByteArray(Charsets.UTF_8))
        return Base64.encodeToString(digest, Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING)
    }

    private fun getOrCreateKey(): SecretKey {
        val keyStore = KeyStore.getInstance(ANDROID_KEY_STORE).apply { load(null) }
        (keyStore.getKey(KEY_ALIAS, null) as? SecretKey)?.let { return it }
        return KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEY_STORE).run {
            init(
                KeyGenParameterSpec.Builder(
                    KEY_ALIAS,
                    KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
                )
                    .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                    .setKeySize(256)
                    .setRandomizedEncryptionRequired(true)
                    .build(),
            )
            generateKey()
        }
    }

    private companion object {
        val KEY_LOCK = Any()
        const val PREFERENCES = "snaplink_sso_secure_v1"
        const val KEY_ALIAS = "com.snaplink.sso.secure-store.v1"
        const val ANDROID_KEY_STORE = "AndroidKeyStore"
        const val TRANSFORMATION = "AES/GCM/NoPadding"
        const val GCM_NONCE_BYTES = 12
        const val GCM_TAG_BITS = 128
        const val MAX_VALUE_BYTES = 64 * 1024
    }
}
