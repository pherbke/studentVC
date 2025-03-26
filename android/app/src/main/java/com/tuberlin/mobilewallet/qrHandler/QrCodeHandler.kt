package com.tuberlin.mobilewallet.qrHandler

import android.annotation.SuppressLint
import android.content.Context
import android.util.Log
import androidx.lifecycle.MutableLiveData
import com.tuberlin.mobilewallet.CredentialStore
import com.tuberlin.mobilewallet.DialogInfo
import okhttp3.OkHttpClient
import java.security.SecureRandom
import java.security.cert.X509Certificate
import javax.net.ssl.SSLContext
import javax.net.ssl.TrustManager
import javax.net.ssl.X509TrustManager

private const val TAG = "QrCodeHandler"

fun qrCodeHandler(
    barcode: String,
    context: Context,
    dialogLiveData: MutableLiveData<DialogInfo>,
    cs: CredentialStore?
): String {
    // barcode = openid-credential-offer://?credential_offer_uri=https://127.0.0.1:8080/credential-offer/6c1d3521-2b95-4b23-b086-bcd4eadd658c
    if (barcode.startsWith("openid-credential-offer://?credential_offer_uri=")) {
        val url = barcode.split("=")[1]

        try {
            getCredentialOffer(url, context, dialogLiveData)
            return "QR Code Scanned"
        } catch (exc: Exception) {
            Log.e(TAG, "Network Call Failed", exc)
            return "Network Problem"
        }
    } else if (barcode.startsWith("openid4vp://") && cs != null) {
        val url = barcode.split("=")[1]

        try {
            requestPresentationRequest(url, context, dialogLiveData, cs)
            return "QR Code Scanned"
        } catch (exc: Exception) {
            Log.e(TAG, "Network Call Failed", exc)
            return "Network Problem"
        }
    }
    return "Wrong QR Code"
}

fun getClient(followRedirects: Boolean = true): OkHttpClient {
    // Set self-signed certificate
    val trustAllCerts = arrayOf<TrustManager>(@SuppressLint("CustomX509TrustManager")
    object : X509TrustManager {
        @SuppressLint("TrustAllX509TrustManager")
        override fun checkClientTrusted(
            chain: Array<out X509Certificate>?,
            authType: String?
        ) {
        }

        @SuppressLint("TrustAllX509TrustManager")
        override fun checkServerTrusted(
            chain: Array<out X509Certificate>?,
            authType: String?
        ) {
        }

        override fun getAcceptedIssuers() = arrayOf<X509Certificate>()
    })

    val sslContext = SSLContext.getInstance("SSL")
    sslContext.init(null, trustAllCerts, SecureRandom())

    // Create an SSL socket factory with our all-trusting manager
    val sslSocketFactory = sslContext.socketFactory

    // Connect to server
    return OkHttpClient.Builder()
        .sslSocketFactory(sslSocketFactory, trustAllCerts[0] as X509TrustManager)
        .hostnameVerifier { _, _ -> true }
        .followRedirects(followRedirects)
        .followSslRedirects(followRedirects)
        .build()
}

