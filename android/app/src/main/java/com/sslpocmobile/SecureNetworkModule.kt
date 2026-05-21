package com.sslpocmobile

import android.provider.Settings
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Log
import com.facebook.react.bridge.*
import com.facebook.react.module.annotations.ReactModule
import com.google.android.gms.tasks.Tasks
import com.google.android.play.core.integrity.IntegrityManagerFactory
import com.google.android.play.core.integrity.IntegrityTokenRequest
import okhttp3.*
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.RequestBody.Companion.toRequestBody
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder
import org.json.JSONObject
import java.io.ByteArrayInputStream
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.security.spec.ECGenParameterSpec
import java.text.SimpleDateFormat
import java.util.*
import javax.net.ssl.KeyManagerFactory
import javax.net.ssl.SSLContext
import javax.net.ssl.TrustManagerFactory
import javax.net.ssl.X509TrustManager

@ReactModule(name = "SecureNetwork")
class SecureNetworkModule(
    reactContext: ReactApplicationContext,
) : NativeSecureNetworkSpec(reactContext) {
    private val refreshLock = Any()
    private var secureClient: OkHttpClient? = null
    private var initError: String? = null
    private var caCert: java.security.cert.Certificate? = null

    private val ANDROID_KEYSTORE = "AndroidKeyStore"
    private val KEY_ALIAS = "mtls_client_key"
    private val CERT_ALIAS = "mtls_client_cert"
    private val DEVICE_ID_PREFS = "secure_network_prefs"
    private val DEVICE_ID_KEY = "persistent_device_id"
    private val CERT_EXPIRY_KEY = "cert_expiry"
    private val API_KEY_KEY = "api_key"

    private val API_KEY_ENDPOINT = "https://192.168.0.179:8443/api/v1/attest-key"
    private val CSR_ENDPOINT = "https://192.168.0.179:8443/csr/sign"

    private val prefs by lazy { reactContext.getSharedPreferences(DEVICE_ID_PREFS, android.content.Context.MODE_PRIVATE) }
    private val deviceID: String by lazy { loadOrCreateDeviceID() }

    init {
        loadCACert()
        // TODO: Remove in production (Dev mode only)
        wipeIdentityState()
        if (isProvisioned()) {
            initializeSecureClient()
        }
        checkAndRenewCertificate()
    }

    override fun getName() = "SecureNetwork"

    // Exported turbo modules function to init provision on app start
    @ReactMethod
    override fun provisionIdentity(promise: Promise) {
        Thread {
            try {
                if (isProvisioned()) {
                    return@Thread promise.resolve("already_provisioned")
                }

                generateKeyPairWithFallback()

                val apiKey = fetchAPIKeyViaAttestation() ?: throw Exception("Failed to obtain API key via attestation")
                storeAPIKey(apiKey)

                val (csrPEM, csrDER) = createCSR(deviceID)
                val (certPEM, expiresAt) = submitCSR(csrDER, deviceID, apiKey)

                storeCertificate(certPEM)
                expiresAt?.let { storeCertExpiry(it) }

                initializeSecureClient()
                promise.resolve("provisioned")
            } catch (e: Exception) {
                promise.reject("PROVISION_ERROR", "${e.javaClass.simpleName}: ${e.message}", e)
            }
        }.start()
    }

    // Exported turbo modules function to handle post request on the app with mtls
    @ReactMethod
    override fun postWithMTLS(
        endpoint: String,
        body: String,
        headers: ReadableMap,
        promise: Promise,
    ) {
        if (!isProvisioned()) return promise.reject("NOT_PROVISIONED", "Call provisionIdentity() first", null)
        performRequest("POST", endpoint, body, headers, promise)
    }

    // Exported turbo modules function to handle get request on the app with mtls
    @ReactMethod
    override fun getWithMTLS(
        endpoint: String,
        headers: ReadableMap,
        promise: Promise,
    ) {
        if (!isProvisioned()) return promise.reject("NOT_PROVISIONED", "Call provisionIdentity() first", null)
        performRequest("GET", endpoint, null, headers, promise)
    }

    private fun fetchAPIKeyViaAttestation(): String? {
        val challenge = generateChallenge()
        // TODO: Uncomment this on real target app. Currently using mock
        // val attestationToken = generateAndroidAttestationToken(challenge)
        val attestationToken = "mock-android-token"
        return exchangeAttestationForAPIKey(attestationToken, challenge, deviceID)
    }

    private fun submitCSR(
        csrDER: ByteArray,
        deviceID: String,
        apiKey: String,
    ): Pair<String, Date?> {
        val client = createCSROkHttpClient()
        // TODO: Uncomment this on real target app. Currently using mock
        // val attestationToken = generateAndroidAttestationToken(challenge)
        // val attestationToken = generateAndroidAttestationToken(generateChallenge())
        val attestationToken = "mock-android-token"

        val json =
            JSONObject().apply {
                put("csr_base64", Base64.getEncoder().encodeToString(csrDER))
                put("device_id", deviceID)
                put("common_name", deviceID)
                put("attest_token", attestationToken)
                put("platform", "android")
            }

        val request =
            Request
                .Builder()
                .url(
                    CSR_ENDPOINT,
                ).post(json.toString().toRequestBody("application/json".toMediaType()))
                .header("X-API-Key", apiKey)
                .build()

        client.newCall(request).execute().use { response ->
            val body = response.body?.string() ?: throw Exception("Empty response")
            if (!response.isSuccessful) throw Exception("CSR signing failed: HTTP ${response.code} - $body")

            val respJson = JSONObject(body)
            val certPEM = respJson.getString("certificate_pem")
            var expiryDate: Date? = null

            if (respJson.has("expires_at")) {
                try {
                    expiryDate = SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ssXXX", Locale.US).parse(respJson.getString("expires_at"))
                } catch (
                    e: Exception,
                ) {
                    Log.w("SecureNetwork", "Failed to parse expiry date", e)
                }
            }
            return Pair(certPEM, expiryDate)
        }
    }

    private fun initializeSecureClient() {
        try {
            val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
            val kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm()).apply { init(keyStore, null) }
            val trustStore =
                KeyStore.getInstance(KeyStore.getDefaultType()).apply {
                    load(null, null)
                    setCertificateEntry("ca", caCert)
                }
            val tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm()).apply { init(trustStore) }

            val sslContext = SSLContext.getInstance("TLSv1.2").apply { init(kmf.keyManagers, tmf.trustManagers, null) }

            val refreshInterceptor =
                Interceptor { chain ->
                    val request = chain.request()
                    var currentKey = loadAPIKey()

                    if (currentKey == null) {
                        synchronized(refreshLock) {
                            currentKey = loadAPIKey()
                            if (currentKey == null) {
                                currentKey = fetchAPIKeyViaAttestation()
                                currentKey?.let { storeAPIKey(it) }
                            }
                        }
                    }

                    val authenticatedRequest =
                        if (currentKey != null && !request.headers.names().contains("X-API-Key")) {
                            request.newBuilder().addHeader("X-API-Key", currentKey).build()
                        } else {
                            request
                        }

                    val response = chain.proceed(authenticatedRequest)

                    if (response.code == 401 && response.header("X-Token-Expired") == "true") {
                        synchronized(refreshLock) {
                            response.close()
                            val latestKey = loadAPIKey()
                            if (latestKey != null && latestKey != currentKey) {
                                return@Interceptor chain.proceed(request.newBuilder().header("X-API-Key", latestKey).build())
                            }
                            val newApiKey = fetchAPIKeyViaAttestation()
                            if (newApiKey != null) {
                                storeAPIKey(newApiKey)
                                return@Interceptor chain.proceed(request.newBuilder().header("X-API-Key", newApiKey).build())
                            }
                        }
                    }
                    response
                }

            secureClient =
                OkHttpClient
                    .Builder()
                    .sslSocketFactory(sslContext.socketFactory, tmf.trustManagers[0] as X509TrustManager)
                    .hostnameVerifier { hostname, _ ->
                        hostname in
                            listOf("192.168.0.179", "qa-communicator.eaterynote.com", "uat-communicator.eaterynote.com")
                    }.addInterceptor(refreshInterceptor)
                    .build()
        } catch (e: Exception) {
            initError = e.message
        }
    }

    private fun performRequest(
        method: String,
        endpoint: String,
        body: String?,
        headers: ReadableMap,
        promise: Promise,
    ) {
        val client = secureClient ?: return promise.reject("INIT_ERROR", "Secure client not initialized: $initError", null)

        try {
            val builder = Request.Builder().url(endpoint)
            if (method == "POST" &&
                body != null
            ) {
                builder.post(body.toRequestBody("application/json; charset=utf-8".toMediaType()))
            } else {
                builder.get()
            }

            loadAPIKey()?.let { if (!headers.hasKey("X-API-Key")) builder.addHeader("X-API-Key", it) }

            val iterator = headers.keySetIterator()
            while (iterator.hasNextKey()) {
                val key = iterator.nextKey()
                headers.getString(key)?.let { builder.addHeader(key, it) }
            }

            client.newCall(builder.build()).execute().use { promise.resolve(it.body?.string() ?: "") }
        } catch (e: javax.net.ssl.SSLHandshakeException) {
            KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }.run { if (containsAlias(KEY_ALIAS)) deleteEntry(KEY_ALIAS) }
            promise.reject("MTLS_REJECTED", "Certificate rejected by server, identity wiped. Please retry.", e)
        } catch (e: Exception) {
            promise.reject("NETWORK_ERROR", e.message, e)
        }
    }

    private fun createCSROkHttpClient(): OkHttpClient {
        val trustStore =
            KeyStore.getInstance(KeyStore.getDefaultType()).apply {
                load(null, null)
                setCertificateEntry("ca", caCert)
            }
        val trustManager =
            TrustManagerFactory
                .getInstance(TrustManagerFactory.getDefaultAlgorithm())
                .apply {
                    init(trustStore)
                }.trustManagers[0] as X509TrustManager
        val sslContext = SSLContext.getInstance("TLSv1.2").apply { init(null, arrayOf(trustManager), null) }

        return OkHttpClient
            .Builder()
            .sslSocketFactory(sslContext.socketFactory, trustManager)
            .hostnameVerifier { hostname, _ ->
                hostname in
                    listOf("192.168.0.179", "qa-communicator.eaterynote.com", "uat-communicator.eaterynote.com")
            }.build()
    }

    private fun generateKeyPairWithFallback() {
        val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
        if (keyStore.containsAlias(KEY_ALIAS)) keyStore.deleteEntry(KEY_ALIAS)

        val kpg = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, ANDROID_KEYSTORE)
        val specBuilder =
            KeyGenParameterSpec
                .Builder(KEY_ALIAS, KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY)
                .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
                .setDigests(KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_NONE)
                .setUserAuthenticationRequired(false)
                .setRandomizedEncryptionRequired(false)

        if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.P) {
            try {
                kpg.initialize(specBuilder.setIsStrongBoxBacked(true).build())
                kpg.generateKeyPair()
                return
            } catch (e: Exception) {
                Log.w("SecureNetwork", "StrongBox unavailable, falling back to TEE", e)
            }
        }
        kpg.initialize(specBuilder.setIsStrongBoxBacked(false).build())
        kpg.generateKeyPair()
    }

    private fun createCSR(deviceID: String): Pair<String, ByteArray> {
        val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
        val privateKey = keyStore.getKey(KEY_ALIAS, null) as PrivateKey
        val publicKey = keyStore.getCertificate(KEY_ALIAS).publicKey

        val csr =
            JcaPKCS10CertificationRequestBuilder(X500Name("CN=$deviceID, O=YourOrg, OU=Mobile Devices"), publicKey)
                .build(JcaContentSignerBuilder("SHA256withECDSA").build(privateKey))

        val pem =
            "-----BEGIN CERTIFICATE REQUEST-----\n" +
                Base64
                    .getEncoder()
                    .encodeToString(
                        csr.encoded,
                    ).chunked(64)
                    .joinToString("\n") + "\n-----END CERTIFICATE REQUEST-----\n"
        return Pair(pem, csr.encoded)
    }

    private fun generateChallenge(): String {
        val cert =
            KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }.getCertificate(KEY_ALIAS) ?: throw Exception("KeyPair not found")
        return Base64.getEncoder().encodeToString(
            java.security.MessageDigest
                .getInstance("SHA-256")
                .digest(cert.publicKey.encoded),
        )
    }

    private fun generateAndroidAttestationToken(challenge: String): String {
        val request =
            IntegrityTokenRequest
                .builder()
                .setNonce(Base64.getUrlEncoder().withoutPadding().encodeToString(challenge.toByteArray(Charsets.UTF_8)))
                .setCloudProjectNumber(31242871483L)
                .build()
        return Tasks.await(IntegrityManagerFactory.create(reactApplicationContext).requestIntegrityToken(request)).token()
    }

    private fun exchangeAttestationForAPIKey(
        attestation: String,
        challenge: String,
        deviceID: String,
    ): String? {
        val json =
            JSONObject().apply {
                put("attestation", attestation)
                put("challenge", challenge)
                put("device_id", deviceID)
                put("platform", "android")
            }
        val request =
            Request
                .Builder()
                .url(API_KEY_ENDPOINT)
                .post(json.toString().toRequestBody("application/json".toMediaType()))
                .build()

        createCSROkHttpClient().newCall(request).execute().use { response ->
            if (!response.isSuccessful) return null
            return JSONObject(response.body?.string() ?: return null).optString("api_key", null)
        }
    }

    private fun isProvisioned(): Boolean {
        val ks = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
        if (!ks.containsAlias(KEY_ALIAS)) return false
        try {
            ks.getKey(KEY_ALIAS, null) as? PrivateKey ?: return false
        } catch (e: Exception) {
            return false
        }
        return ks.getCertificateChain(KEY_ALIAS)?.isNotEmpty() == true
    }

    private fun loadCACert() {
        try {
            caCert = CertificateFactory.getInstance("X.509").generateCertificate(reactApplicationContext.assets.open("ca.crt"))
        } catch (
            e: Exception,
        ) {
            Log.e("SecureNetwork", "Failed to load CA cert", e)
        }
    }

    private fun checkAndRenewCertificate() {
        val expiry = loadCertExpiry() ?: return
        if (expiry <= Date(Date().time + 24 * 3600 * 1000)) {
            Log.i("SecureNetwork", "Certificate expiring, background renewing...")
            Thread {
                try {
                    generateKeyPairWithFallback()
                    val apiKey = fetchAPIKeyViaAttestation() ?: throw Exception("Renewal failed")
                    storeAPIKey(apiKey)

                    val (csrPEM, csrDER) = createCSR(deviceID)
                    val (certPEM, expiresAt) = submitCSR(csrDER, deviceID, apiKey)

                    storeCertificate(certPEM)
                    expiresAt?.let { storeCertExpiry(it) }
                    initializeSecureClient()
                    Log.i("SecureNetwork", "Certificate renewed successfully")
                } catch (e: Exception) {
                    Log.e("SecureNetwork", "Background renewal failed: ${e.message}")
                }
            }.start()
        }
    }

    private fun wipeIdentityState() {
        KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }.run { if (containsAlias(KEY_ALIAS)) deleteEntry(KEY_ALIAS) }
        prefs
            .edit()
            .remove(API_KEY_KEY)
            .remove(CERT_EXPIRY_KEY)
            .apply()
        secureClient = null
    }

    private fun storeCertificate(certPEM: String) {
        val cert =
            CertificateFactory
                .getInstance(
                    "X.509",
                ).generateCertificate(ByteArrayInputStream(certPEM.toByteArray())) as X509Certificate
        val ks = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
        ks.setKeyEntry(KEY_ALIAS, ks.getKey(KEY_ALIAS, null) as PrivateKey, null, arrayOf(cert, caCert))
    }

    private fun storeAPIKey(key: String) {
        prefs.edit().putString(API_KEY_KEY, key).apply()
    }

    private fun loadAPIKey(): String? = prefs.getString(API_KEY_KEY, null)

    private fun storeCertExpiry(date: Date) {
        prefs.edit().putLong(CERT_EXPIRY_KEY, date.time).apply()
    }

    private fun loadCertExpiry(): Date? = prefs.getLong(CERT_EXPIRY_KEY, 0L).let { if (it > 0) Date(it) else null }

    private fun loadOrCreateDeviceID(): String =
        prefs.getString(DEVICE_ID_KEY, null) ?: UUID.randomUUID().toString().also { prefs.edit().putString(DEVICE_ID_KEY, it).apply() }
}
