package com.tuberlin.mobilewallet.qrHandler

import android.content.Context
import android.net.Uri
import android.util.Base64
import android.util.Log
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Warning
import androidx.lifecycle.MutableLiveData
import com.tuberlin.mobilewallet.DialogInfo
import com.tuberlin.mobilewallet.Wallet
import com.tuberlin.mobilewallet.utils.encodeToBase58String
import io.jsonwebtoken.Jwts
import okhttp3.Call
import okhttp3.Callback
import okhttp3.HttpUrl
import okhttp3.HttpUrl.Companion.toHttpUrlOrNull
import okhttp3.MediaType.Companion.toMediaTypeOrNull
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import okhttp3.Response
import org.json.JSONObject
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.SecureRandom
import java.security.interfaces.ECPublicKey
import java.util.Date

private const val TAG = "IssueHandler"

fun getCredentialOffer(
    urlString: String,
    context: Context,
    dialogLiveData: MutableLiveData<DialogInfo>
) {
    val client = getClient()

    val request = Request.Builder()
        .url(urlString)
        .build()

    client.newCall(request).enqueue(object : Callback {
        override fun onFailure(call: Call, e: java.io.IOException) {
            dialogLiveData.postValue(DialogInfo(
                "Connection Error",
                e.message.toString(),
                Icons.Default.Warning))
            Log.e(TAG, "Client Call Error", e)
        }

        override fun onResponse(call: Call, response: Response) {
            // Handle success
            val result = response.body?.string() ?: ""
            // extract the issuer_state from the result
            val jsonResult = JSONObject(result)
            val issuerState = jsonResult.getJSONObject("grants")
                .getJSONObject("authorization_code")
                .getString("issuer_state")

            requestAuthorisation(urlString, issuerState, context)
        }
    })
}

fun createCodeVerifier(): String? {
    val secureRandom = SecureRandom()
    val code = ByteArray(32)
    secureRandom.nextBytes(code)
    return Base64.encodeToString(
        code,
        Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING
    )
}

fun getCodeChallenge(verifier: String): String {
    val bytes: ByteArray = verifier.toByteArray(Charsets.US_ASCII)
    val md: MessageDigest = MessageDigest.getInstance("SHA-256")
    md.update(bytes, 0, bytes.size)
    val digest: ByteArray = md.digest()
    return Base64.encodeToString(
        digest,
        Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING
    )
}

fun getX962PublicKey(publicKey: ECPublicKey): ByteArray {
    // Get ECPoint (x, y coordinates)
    val ecPoint = publicKey.w
    val xCoord = ecPoint.affineX
    val yCoord = ecPoint.affineY

    // Convert x and y to byte arrays
    val xBytes = xCoord.toByteArray().let { if (it[0] == 0.toByte()) it.drop(1).toByteArray() else it } // Remove leading zero if present
    val yBytes = yCoord.toByteArray().let { if (it[0] == 0.toByte()) it.drop(1).toByteArray() else it }

    // Ensure they are 32 bytes (P-256 coordinates are 32 bytes each)
    val paddedX = ByteArray(32) { 0 }
    val paddedY = ByteArray(32) { 0 }
    System.arraycopy(xBytes, 0, paddedX, 32 - xBytes.size, xBytes.size)
    System.arraycopy(yBytes, 0, paddedY, 32 - yBytes.size, yBytes.size)

    // Prepend uncompressed point indicator (0x04)
    return byteArrayOf(0x04) + paddedX + paddedY
}


// /authorize
private fun requestAuthorisation(urlString: String, issuerState: String, context: Context) {
    val client = getClient(false)

    //https://127.0.0.1:8080/credential-offer/5de031e2-7427 --> https://127.0.0.1:8080
    val baseUrl = urlString.split("credential-offer")[0]
    val urlBuilder: HttpUrl.Builder? = ("$baseUrl/authorize").toHttpUrlOrNull()?.newBuilder()

    if (urlBuilder != null) {

        // used for DID / UserID and to sign JWT
        val kpg = KeyPairGenerator.getInstance("EC")
        kpg.initialize(256)
        val keyPair = kpg.genKeyPair()

        val codeVerifier = createCodeVerifier()
        val codeChallenge = getCodeChallenge(codeVerifier!!)

        val did = generateDID(keyPair)

        urlBuilder.addQueryParameter("response_type", "code")
        urlBuilder.addQueryParameter("code_challenge_method", "S256")
        urlBuilder.addQueryParameter("code_challenge", codeChallenge)
        urlBuilder.addQueryParameter("redirect_uri", baseUrl)
        urlBuilder.addQueryParameter("issuer_state", issuerState)
        urlBuilder.addQueryParameter("client_id", did)
        // nonce

        val request = Request.Builder()
            .url(urlBuilder.build().toString())
            .build()

        client.newCall(request).enqueue(object : Callback {
            override fun onFailure(call: Call, e: java.io.IOException) {
                e.printStackTrace()
            }

            override fun onResponse(call: Call, response: Response) {
                // Process the response data
                if (response.header("Location") != null) {
                    val req: Request = Request.Builder().url(response.header("Location")!!).head().build()
                    Log.i(TAG, "RequestAuthorisation")
                    Log.i(TAG, response.header("Location") ?: "")

                    requestDirectPost(baseUrl, req, codeChallenge, codeVerifier, keyPair, context)
                }
            }
        })
    }
}


fun generateDID(keyPair: KeyPair): String {
    // 0x1200
    val multicodecPrefix = byteArrayOf(18, 0)
    val publicKey = keyPair.public as ECPublicKey
    getX962PublicKey(publicKey)
    val multicodecKey = getX962PublicKey(publicKey)
    val keyBytes = multicodecPrefix + multicodecKey
    val key = keyBytes.encodeToBase58String()
    return "did:key:z$key"
}

private fun createJWT(codeChallenge: String, keyPair: KeyPair): String? {

    val did = generateDID(keyPair)

    val currentTime = System.currentTimeMillis()
    val expirationTime = Date(currentTime + 864000000L) // ten days in milliseconds
    val claims = mapOf(
        "exp" to expirationTime.time / 1000,
        "iss" to did,
        //"nonce" to "generateNonce()", create nonce and use it in authorize as well
        "state" to "generateSecureState()", // maybe from response from authorize?
        "code_challenge" to codeChallenge
    )

    val jwtToken = Jwts.builder()
        .setClaims(claims)
        .setHeaderParam("typ","JWT")
        .signWith(keyPair.private)
        .compact()

    return jwtToken
}

private fun requestDirectPost(
    baseUrl: String,
    req: Request,
    codeChallenge: String,
    codeVerifier: String,
    keyPair: KeyPair,
    context: Context
) {
    val client = getClient(false)

    //will create JWT ey...
    val jwtToken = createJWT(codeChallenge, keyPair)

    Log.i(TAG, "direct_post JWT")
    Log.i(TAG, jwtToken ?: "")

    val urlBuilder: HttpUrl.Builder? = ("$baseUrl/direct_post").toHttpUrlOrNull()?.newBuilder()
    urlBuilder?.addQueryParameter("id_token", jwtToken)

    val request = Request.Builder()
        .url(urlBuilder?.build().toString())
        .post("".toRequestBody(null))
        .build()

    client.newCall(request).enqueue(object : Callback {
        override fun onFailure(call: Call, e: java.io.IOException) {
            e.printStackTrace()
        }

        override fun onResponse(call: Call, response: Response) {
            // Handle success
            // Process the response data
            Log.i(TAG, "requestDirectPost")
            Log.i(TAG, response.header("Location") ?: "")

            //get query parameter
            val string: String = response.header("Location")?.replace("#", "?") ?: ""
            val code = Uri.parse(string).getQueryParameter("code")


            if (code == null){
                Log.e(
                    TAG, "NO CODE\n" +
                        response.body?.string()+"\n"+
                        response.header("Location")
                )
            }else{
                Log.i(TAG, "Code:\n$code")
                requestToken(baseUrl, code, codeVerifier, keyPair, context)
            }


        }
    })

}


private fun requestToken(baseUrl: String, code: String, codeVerifier: String, keyPair: KeyPair, context: Context) {
    val client = getClient()


    val urlBuilder: HttpUrl.Builder? = ("$baseUrl/token").toHttpUrlOrNull()?.newBuilder()
    urlBuilder?.addQueryParameter("grant_type", "authorization_code")
    urlBuilder?.addQueryParameter("client_id", generateDID(keyPair))
    urlBuilder?.addQueryParameter("code", code)
    urlBuilder?.addQueryParameter("code_verifier", codeVerifier)
    urlBuilder?.addQueryParameter("redirect_uri", baseUrl)
    //jsonObject.put("preAuthorisedCode", "")
    //jsonObject.put("userPin", "")
    //jsonObject.put("clientAssertion", "")
    //jsonObject.put("clientAssertionType", "")

    val request = Request.Builder()
        .url(urlBuilder?.build().toString())
        .post("".toRequestBody(null))
        .build()

    client.newCall(request).enqueue(object : Callback {
        override fun onFailure(call: Call, e: java.io.IOException) {
            e.printStackTrace()
        }

        override fun onResponse(call: Call, response: Response) {
            // Handle success
            val result = response.body?.string() ?: ""
            // Process the response data
            Log.i(TAG, "RequestToken\n$result")
            //get access_token
            val accessToken = JSONObject(result).getString("access_token")

            // Pass context to the next function
            requestCredential(baseUrl, accessToken, keyPair, context)
        }
    })
}

private fun requestCredential(baseUrl: String, accessToken: String, keyPair: KeyPair, context: Context){
    val client = getClient()

    val urlBuilder: HttpUrl.Builder? = ("$baseUrl/credential").toHttpUrlOrNull()?.newBuilder()

    val request = Request.Builder()
        .url(urlBuilder?.build().toString())
        .header("Authorization", "Bearer $accessToken")
        .post("".toRequestBody("application/json; charset=utf-8".toMediaTypeOrNull()))
        .build()

    client.newCall(request).enqueue(object : Callback {
        override fun onFailure(call: Call, e: java.io.IOException) {
            e.printStackTrace()
        }

        override fun onResponse(call: Call, response: Response) {
            // Process the response data
            Log.i(TAG, "RequestCredential")
            val result = response.body?.string() ?: ""
            Log.i(TAG, result)

            try {
                val jwt = JSONObject(result)

                //eg:
                //eyJhbGciOiJFUzI1NiIsImtpZCI6ImRpZDprZXk6elh3cFJrR1VWZXdOTUVNS2tRMURwNEFHQjVmdDhyNDhZVmZNZWVyY2I3ODRaOGZqTHUzYW1vU29QdGNEdUJpNDNRQnE5aDE2ZmloS2NRYkpyaHB6OWo1VVlGcGMja2V5LTEiLCJ0eXAiOiJKV1QifQ.eyJpYXQiOjE3MzQ2MjQwNzIsImlzcyI6ImRpZDprZXk6elh3cFJrR1VWZXdOTUVNS2tRMURwNEFHQjVmdDhyNDhZVmZNZWVyY2I3ODRaOGZqTHUzYW1vU29QdGNEdUJpNDNRQnE5aDE2ZmloS2NRYkpyaHB6OWo1VVlGcGMiLCJzdWIiOiJkaWQ6a2V5OnpYd3BVbThjeXhSQjkxMjRGaVZ1OGNuaTRBaW1XZXVMQjZCR1J2RGpGUmc1RnNMTkRXMVhQSmJMcUJOTmZURUt2NUZHcEc0Yk1KdXZEbnZDeDVOakh4WnFaa3dIIiwiZXhwIjoxNzM0NjI3NjcyLCJuYmYiOjE3MzQ2MjQwNzIsImp0aSI6InVybjp1dWlkOjk0YTgzMzU3LTc3MzYtNGRjMC04ZmUxLTYzYTExN2JjYzZkZSIsInZjIjp7IkBjb250ZXh0IjpbImh0dHBzOi8vd3d3LnczLm9yZy8yMDE4L2NyZWRlbnRpYWxzL3YxIl0sInR5cGUiOlsiVmVyaWZpYWJsZUNyZWRlbnRpYWwiLCJWZXJpZmlhYmxlQXR0ZXN0YXRpb24iLCJTdHVkZW50SURDYXJkIl0sImlkIjoidXJuOnV1aWQ6OTRhODMzNTctNzczNi00ZGMwLThmZTEtNjNhMTE3YmNjNmRlIiwiaXNzdWVyIjoiZGlkOmtleTp6WHdwUmtHVVZld05NRU1La1ExRHA0QUdCNWZ0OHI0OFlWZk1lZXJjYjc4NFo4ZmpMdTNhbW9Tb1B0Y0R1Qmk0M1FCcTloMTZmaWhLY1FiSnJocHo5ajVVWUZwYyIsImlzc3VhbmNlRGF0ZSI6IjIwMjQtMTItMTlUMTY6MDE6MTIuOTE2NDIzIiwidmFsaWRGcm9tIjoiMjAyNC0xMi0xOVQxNjowMToxMi45MTY0MzciLCJjcmVkZW50aWFsU3ViamVjdCI6eyJpZCI6ImRpZDprZXk6elh3cFVtOGN5eFJCOTEyNEZpVnU4Y25pNEFpbVdldUxCNkJHUnZEakZSZzVGc0xORFcxWFBKYkxxQk5OZlRFS3Y1RkdwRzRiTUp1dkRudkN4NU5qSHhacVprd0giLCJmaXJzdE5hbWUiOiJNYXhpIiwibGFzdE5hbWUiOiJNdXN0ZXJmcmF1IiwiaW1hZ2UiOiJCYXNlNjRoZXJlT2YzNXg0NUltYWdlNjAwRFBJIiwic3R1ZGVudElkIjoiMTIzNDU2IiwidmVyaWZ5VXJsIjoiVVJMRlx1MDBmY3JRUkNvZGVEZXJTYWd0SXN0VmFsaWQiLCJ0aGVtZSI6eyJuYW1lIjoiVGVjaG5pc2NoZSBVbml2ZXJzaXRcdTAwZTR0IEJlcmxpbiIsImljb24iOiJ1bml2ZXJzaXR5SWNvbkJhc2U2NCIsImJnQ29sb3JDYXJkIjoiQzQwRDFFIiwiYmdDb2xvclNlY3Rpb25Ub3AiOiJDNDBEMUUiLCJiZ0NvbG9yU2VjdGlvbkJvdCI6IkZGRkZGRiIsImZnQ29sb3JUaXRsZSI6IkZGRkZGRiJ9fSwiY3JlZGVudGlhbFNjaGVtYSI6eyJpZCI6Imh0dHBzOi8vYXBpLWNvbmZvcm1hbmNlLmVic2kuZXUvdHJ1c3RlZC1zY2hlbWFzLXJlZ2lzdHJ5L3YzL3NjaGVtYXMvekRwV0dVQmVubXFYenVyc2tyeTlOc2s2dnEyUjh0aGg5VlNlb1JxZ3VveU1EIiwidHlwZSI6IkZ1bGxKc29uU2NoZW1hVmFsaWRhdG9yMjAyMSJ9LCJleHBpcmF0aW9uRGF0ZSI6IjIwMjQtMTItMTlUMTc6MDE6MTIuOTE2NDQ1In19.OzHdu7S83742zKxSSjBBz530TpLQNtkU7ziMtba836Z5wdWKY2txCP20C7-Gikzf8Tuvr0Hhv4nuK1WaEAUF-A

                val wallet = Wallet.getInstance(context)
                wallet.addJWT(jwt, keyPair)
            } catch (exc: Exception) {
                Log.e(TAG, "JWT Error", exc)
            }


        }
    })
}