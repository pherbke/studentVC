package com.tuberlin.mobilewallet

import android.content.Context
import android.security.KeyChain
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Log
import androidx.lifecycle.LiveData
import androidx.lifecycle.MutableLiveData
import com.google.gson.Gson
import com.tuberlin.mobilewallet.utils.WalletCredential
import io.jsonwebtoken.Jwts
import org.json.JSONObject
import java.security.KeyPair
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

data class CredentialStore(
    var credential: WalletCredential,
    var keyPair: KeyPair,
    var signature: String
)

class Wallet private constructor(private val context: Context) {

    private val TAG = "Wallet"
    private val keyAlias = "WalletKeyAlias" // Alias for the KeyStore key

    // Singleton
    companion object {
        @Volatile
        private var instance: Wallet? = null

        fun getInstance(context: Context) =
            instance ?: synchronized(this) {
                instance ?: Wallet(context).also { instance = it }
            }
    }

    // Mutable LiveData
    private val _data = MutableLiveData<List<CredentialStore>>()
    val data: LiveData<List<CredentialStore>> get() = _data

    init {
        // Initialize or create the KeyStore entry for encryption
        createKeyIfNotExists()
    }

    // Helper method to centralize updates to _data
    private fun updateData(updateAction: (MutableList<CredentialStore>) -> Unit) {
        val currentList = _data.value?.toMutableList() ?: mutableListOf()
        updateAction(currentList)
        _data.postValue(currentList)
    }

    fun addJWT(jwt: JSONObject, keyPair: KeyPair) {
        val newData = jwt.getString("credential")

        Log.i(TAG, "New Student ID will be saved in the Wallet\n$newData")

        // Parse the JWT
        val i = newData.lastIndexOf('.')
        val withoutSignature = newData.substring(0, i + 1)
        val untrusted = Jwts.parser().setAllowedClockSkewSeconds(5).parseClaimsJwt(withoutSignature)

        // Create JSON from the given VC
        val vcJSON = Gson().toJson(untrusted.body, MutableMap::class.java)
        Log.i(TAG, "ParsedJWT\n${vcJSON.toString().replace(",", ",\n")}")

        // Create a VC object out of the VC-JSON
        val vc = Gson().fromJson(vcJSON, WalletCredential::class.java)

        // Check if JWT is already added
        if (isJWTAlreadySaved(newData)) {
            Log.i(TAG, "JWT is already saved in the KeyChain.")
            return
        }

        // Save JWT into local storage (KeyChain)
        saveJWTToKeyChain(newData)

        Log.i(TAG, "New Student ID is added\n${vc.toString().replace(",", ",\n")}")

        val credentialStore = CredentialStore(
            credential = vc,
            keyPair = keyPair,
            signature = jwt.getString("signature")
        )

        // Add to LiveData using the centralized helper
        updateData { it.add(credentialStore) }
    }

    fun getVc(id: String): CredentialStore? {
        return _data.value?.find { it.credential.vc.id == id }
    }


    private fun createKeyIfNotExists() {
        val keyStore = KeyStore.getInstance("AndroidKeyStore")
        keyStore.load(null)

        if (!keyStore.containsAlias(keyAlias)) {
            val keyGen = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
            keyGen.init(
                KeyGenParameterSpec.Builder(
                    keyAlias,
                    KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
                )
                    .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                    .build()
            )
            keyGen.generateKey()
        }
    }

    private fun saveJWTToKeyChain(jwt: String) {
        val keyStore = KeyStore.getInstance("AndroidKeyStore")
        keyStore.load(null)
        val secretKey = keyStore.getKey(keyAlias, null) as SecretKey

        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, secretKey)

        val iv = cipher.iv
        val encryptedJWT = cipher.doFinal(jwt.toByteArray(Charsets.UTF_8))

        // Save the encrypted JWT and IV to shared preferences
        val sharedPreferences = context.getSharedPreferences("WalletPrefs", Context.MODE_PRIVATE)
        sharedPreferences.edit().apply {
            putString("jwt_iv", iv.joinToString(","))
            putString("jwt_data", encryptedJWT.joinToString(","))
            apply()
        }
    }

    private fun isJWTAlreadySaved(jwt: String): Boolean {
        val keyStore = KeyStore.getInstance("AndroidKeyStore")
        keyStore.load(null)
        val secretKey = keyStore.getKey(keyAlias, null) as SecretKey

        val sharedPreferences = context.getSharedPreferences("WalletPrefs", Context.MODE_PRIVATE)
        val savedIV = sharedPreferences.getString("jwt_iv", null)?.split(",")?.map { it.toByte() }?.toByteArray()
        val encryptedJWT = sharedPreferences.getString("jwt_data", null)?.split(",")?.map { it.toByte() }?.toByteArray()

        if (savedIV != null && encryptedJWT != null) {
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.DECRYPT_MODE, secretKey, GCMParameterSpec(128, savedIV))
            val decryptedJWT = cipher.doFinal(encryptedJWT).toString(Charsets.UTF_8)
            return jwt == decryptedJWT
        }
        return false
    }
}