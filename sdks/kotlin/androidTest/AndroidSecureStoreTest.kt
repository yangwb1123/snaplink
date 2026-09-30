package com.snaplink.sso

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
public class AndroidSecureStoreTest {
    @Test
    public fun encryptsReadsAndDeletesRecordsUsingAndroidKeystore() {
        val context = ApplicationProvider.getApplicationContext<Context>()
        val store = AndroidSecureStore(context)
        val secret = "access-token-must-not-be-plaintext"
        val account = "snaplink-test-account"
        store.write(account, secret)

        assertEquals(secret, store.read(account))
        val preferences = context.getSharedPreferences("snaplink_sso_secure_v1", Context.MODE_PRIVATE)
        assertFalse(preferences.all.values.any { it.toString().contains(secret) })

        store.delete(account)
        assertNull(store.read(account))
    }
}
