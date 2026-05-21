import CertificateSigningRequest
import CryptoKit
import DeviceCheck
import Foundation
import Security

@objc(SecureNetwork)
class SecureNetwork: NSObject, URLSessionDelegate {
  private var identity: SecIdentity?
  private var caCert: SecCertificate?
  private var apiKey: String?

  private let refreshLock = NSLock()
  private var isRefreshing = false
  private var refreshQueue: [(Bool) -> Void] = []

  private let KEY_TAG = "com.yourapp.mtls_key"
  private let PUB_KEY_TAG = "com.yourapp.mtls_key_pub"
  private let CERT_TAG = "com.yourapp.mtls_cert"
  private let DEVICE_ID_KEY = "com.yourapp.device_id"
  private let CERT_EXPIRY_KEY = "com.yourapp.cert_expiry"
  private let ATTEST_KEY_TAG = "com.yourapp.attest_key"

  private let API_KEY_ENDPOINT = "https://192.168.0.179:8443/api/v1/attest-key"
  private let CSR_ENDPOINT = "https://192.168.0.179:8443/csr/sign"

  private lazy var deviceID: String = { loadOrCreateDeviceID() }()

  override init() {
    super.init()
    loadCACert()
    // TODO: Remove in production (Dev mode only)
    wipeIdentityState()
    _ = loadExistingIdentity()
    checkAndRenewCertificate()
  }

  // Exported turbo modules function to init provision on app start
  @objc func provisionIdentity(
    _ resolve: @escaping RCTPromiseResolveBlock, reject: @escaping RCTPromiseRejectBlock
  ) {
    DispatchQueue.global(qos: .userInitiated).async {
      do {
        self.identity = nil

        if self.loadExistingIdentity() {
          DispatchQueue.main.async { resolve("already_provisioned") }
          return
        }

        guard let keyPair = self.generateKeypair() else {
          DispatchQueue.main.async { reject("KEYGEN_ERROR", "Key generation failed", nil) }
          return
        }

        self.fetchAPIKeyViaAttestation(publicKey: keyPair.publicKey) { apiKeyResult in
          guard let key = apiKeyResult else {
            DispatchQueue.main.async {
              reject("ATTESTATION_ERROR", "Failed to obtain API key", nil)
            }
            return
          }
          self.apiKey = key

          guard
            let csrDER = self.createCSR(
              publicKey: keyPair.publicKey, privateKey: keyPair.privateKey)
          else {
            DispatchQueue.main.async { reject("CSR_ERROR", "CSR Generation failed", nil) }
            return
          }

          self.submitCSR(csrDER: csrDER, deviceID: self.deviceID) { certPEM, expiresAt in
            guard let validCertPEM = certPEM else {
              DispatchQueue.main.async {
                reject("NETWORK_ERROR", "Backend failed to return certificate", nil)
              }
              return
            }

            guard self.storeCertificate(certPEM: validCertPEM) else {
              DispatchQueue.main.async {
                reject("STORAGE_ERROR", "Failed to store certificate", nil)
              }
              return
            }

            if let expiry = expiresAt { self.storeCertExpiry(expiry) }

            guard self.loadExistingIdentity() else {
              DispatchQueue.main.async { reject("IDENTITY_ERROR", "Failed to link Identity", nil) }
              return
            }

            DispatchQueue.main.async { resolve("provisioned") }
          }
        }
      }
    }
  }

  // Exported turbo modules function to handle post request on the app with mtls
  @objc func postWithMTLS(
    _ endpoint: String, body: String, headers: NSDictionary,
    resolve: @escaping RCTPromiseResolveBlock, reject: @escaping RCTPromiseRejectBlock
  ) {
    performRequest(
      method: "POST", endpoint: endpoint, body: body, headers: headers, resolve: resolve,
      reject: reject)
  }

  // Exported turbo modules function to handle get request on the app with mtls
  @objc func getWithMTLS(
    _ endpoint: String, headers: NSDictionary, resolve: @escaping RCTPromiseResolveBlock,
    reject: @escaping RCTPromiseRejectBlock
  ) {
    performRequest(
      method: "GET", endpoint: endpoint, body: nil, headers: headers, resolve: resolve,
      reject: reject)
  }

  private func fetchAPIKeyViaAttestation(publicKey: SecKey, completion: @escaping (String?) -> Void)
  {
    let challenge = self.generateChallenge(publicKey: publicKey)

    #if targetEnvironment(simulator)
      self.exchangeAttestationForAPIKey(
        keyId: "mock-ios-key", attestation: Data("mock-ios-token".utf8), challenge: challenge,
        deviceID: self.deviceID, completion: completion)
    #else
      guard DCAppAttestService.shared.isSupported else {
        completion(nil)
        return
      }

      DCAppAttestService.shared.generateKey { keyId, error in
        guard let validKeyId = keyId, error == nil else {
          completion(nil)
          return
        }

        UserDefaults.standard.set(validKeyId, forKey: self.ATTEST_KEY_TAG)
        let hashData = Data(SHA256.hash(data: Data(challenge.utf8)))

        DCAppAttestService.shared.attestKey(validKeyId, clientDataHash: hashData) {
          attestation, error in
          guard let validAttestation = attestation, error == nil else {
            completion(nil)
            return
          }

          self.exchangeAttestationForAPIKey(
            keyId: validKeyId, attestation: validAttestation, challenge: challenge,
            deviceID: self.deviceID, completion: completion)
        }
      }
    #endif
  }

  private func submitCSR(
    csrDER: Data, deviceID: String, completion: @escaping (String?, Date?) -> Void
  ) {
    guard let url = URL(string: CSR_ENDPOINT) else { return completion(nil, nil) }

    var request = URLRequest(url: url)
    request.httpMethod = "POST"
    request.addValue(self.apiKey ?? self.loadAPIKey() ?? "", forHTTPHeaderField: "X-API-Key")
    request.addValue("application/json", forHTTPHeaderField: "Content-Type")

    let json: [String: Any] = [
      "csr_base64": csrDER.base64EncodedString(),
      "device_id": deviceID,
      "common_name": deviceID,
      "attest_token": generateAppleAttestationToken(deviceID: deviceID),
      "platform": "ios",
    ]

    request.httpBody = try? JSONSerialization.data(withJSONObject: json)

    URLSession(configuration: .ephemeral, delegate: self, delegateQueue: nil).dataTask(
      with: request
    ) { data, _, error in
      guard let data = data, error == nil,
        let jsonResponse = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
        let certPEM = jsonResponse["certificate_pem"] as? String
      else {
        return completion(nil, nil)
      }

      var expiryDate: Date?
      if let expiresAt = jsonResponse["expires_at"] as? String {
        expiryDate = ISO8601DateFormatter().date(from: expiresAt)
      }
      completion(certPEM, expiryDate)
    }.resume()
  }

  private func performRequest(
    method: String, endpoint: String, body: String?, headers: NSDictionary, retryCount: Int = 3,
    resolve: @escaping RCTPromiseResolveBlock, reject: @escaping RCTPromiseRejectBlock
  ) {
    guard identity != nil else {
      return reject("NOT_PROVISIONED", "Call provisionIdentity() first", nil)
    }
    guard let url = URL(string: endpoint) else {
      return reject("INVALID_URL", "Invalid endpoint", nil)
    }

    let currentKey = self.apiKey ?? self.loadAPIKey()
    if currentKey == nil && retryCount > 0 {
      self.safelyRefreshAPIKey { success in
        success
          ? self.performRequest(
            method: method, endpoint: endpoint, body: body, headers: headers, retryCount: 0,
            resolve: resolve, reject: reject) : reject("AUTH_ERROR", "Failed to fetch API Key", nil)
      }
      return
    }

    var request = URLRequest(url: url)
    request.httpMethod = method
    if let body = body { request.httpBody = body.data(using: .utf8) }
    if let key = currentKey { request.addValue(key, forHTTPHeaderField: "X-API-Key") }

    for (key, value) in headers {
      if let k = key as? String, let v = value as? String {
        request.addValue(v, forHTTPHeaderField: k)
      }
    }

    URLSession(configuration: .ephemeral, delegate: self, delegateQueue: nil).dataTask(
      with: request
    ) { data, response, error in
      if let nsError = error as NSError? {
        if nsError.domain == NSURLErrorDomain
          && (nsError.code == NSURLErrorClientCertificateRejected
            || nsError.code == NSURLErrorSecureConnectionFailed)
        {
          self.wipeIdentityState()
          return reject("MTLS_REJECTED", "Certificate rejected, identity wiped.", nsError)
        }
        return reject("NETWORK_ERROR", nsError.localizedDescription, nsError)
      }

      if let httpResponse = response as? HTTPURLResponse, httpResponse.statusCode == 401,
        httpResponse.value(forHTTPHeaderField: "X-Token-Expired") == "true", retryCount > 0
      {
        self.safelyRefreshAPIKey { success in
          success
            ? self.performRequest(
              method: method, endpoint: endpoint, body: body, headers: headers, retryCount: 0,
              resolve: resolve, reject: reject)
            : reject("REFRESH_FAILED", "Failed to refresh API key", nil)
        }
        return
      }

      resolve(String(data: data ?? Data(), encoding: .utf8) ?? "")
    }.resume()
  }

  private func safelyRefreshAPIKey(completion: @escaping (Bool) -> Void) {
    refreshLock.lock()
    if isRefreshing {
      refreshQueue.append(completion)
      refreshLock.unlock()
      return
    }
    isRefreshing = true
    refreshQueue.append(completion)
    refreshLock.unlock()

    guard let publicKey = loadPublicKey() else { return completion(false) }

    self.fetchAPIKeyViaAttestation(publicKey: publicKey) { newKey in
      let success = (newKey != nil)
      if success { self.apiKey = newKey }

      self.refreshLock.lock()
      self.isRefreshing = false
      let queue = self.refreshQueue
      self.refreshQueue.removeAll()
      self.refreshLock.unlock()

      queue.forEach { $0(success) }
    }
  }

  func urlSession(
    _ session: URLSession, didReceive challenge: URLAuthenticationChallenge,
    completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void
  ) {
    let ps = challenge.protectionSpace

    if ps.authenticationMethod == NSURLAuthenticationMethodClientCertificate {
      if let identity = self.identity {
        var leafCert: SecCertificate?
        SecIdentityCopyCertificate(identity, &leafCert)
        let certChain = [leafCert, self.caCert].compactMap { $0 }
        completionHandler(
          .useCredential,
          URLCredential(identity: identity, certificates: certChain, persistence: .forSession))
        return
      }
      completionHandler(.performDefaultHandling, nil)
      return
    }

    if ps.authenticationMethod == NSURLAuthenticationMethodServerTrust {
      guard let trust = ps.serverTrust, let ca = caCert else {
        return completionHandler(.cancelAuthenticationChallenge, nil)
      }

      SecTrustSetPolicies(trust, SecPolicyCreateSSL(true, ps.host as CFString))
      SecTrustSetAnchorCertificates(trust, [ca] as CFArray)
      SecTrustSetAnchorCertificatesOnly(trust, true)

      var error: CFError?
      if SecTrustEvaluateWithError(trust, &error),
        ["192.168.0.179", "qa-communicator.eaterynote.com", "uat-communicator.eaterynote.com"]
          .contains(ps.host)
      {
        return completionHandler(.useCredential, URLCredential(trust: trust))
      }
    }
    completionHandler(.cancelAuthenticationChallenge, nil)
  }

  private func generateKeypair() -> (publicKey: SecKey, privateKey: SecKey)? {
    deleteKey(tag: KEY_TAG)
    deleteKey(tag: PUB_KEY_TAG)

    var attributes: [String: Any] = [
      kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
      kSecAttrKeySizeInBits as String: 256,
      kSecPrivateKeyAttrs as String: [
        kSecAttrIsPermanent as String: true,
        kSecAttrApplicationTag as String: KEY_TAG.data(using: .utf8)!,
        kSecAttrLabel as String: CERT_TAG,
        kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
      ],
    ]

    #if !targetEnvironment(simulator)
      attributes[kSecAttrTokenID as String] = kSecAttrTokenIDSecureEnclave
    #endif

    var publicKey: SecKey?
    var privateKey: SecKey?
    guard SecKeyGeneratePair(attributes as CFDictionary, &publicKey, &privateKey) == errSecSuccess
    else { return nil }
    return (publicKey!, privateKey!)
  }

  private func createCSR(publicKey: SecKey, privateKey: SecKey) -> Data? {
    let csrBuilder = CertificateSigningRequest(
      commonName: self.deviceID, organizationName: "YourOrg",
      organizationUnitName: "Mobile Devices", countryName: nil, stateOrProvinceName: nil,
      localityName: nil, keyAlgorithm: KeyAlgorithm.ec(signatureType: .sha256))

    var error: Unmanaged<CFError>?
    guard let publicKeyData = SecKeyCopyExternalRepresentation(publicKey, &error) as Data? else {
      return nil
    }
    return csrBuilder.build(publicKeyData, privateKey: privateKey)
  }

  private func generateChallenge(publicKey: SecKey) -> String {
    var error: Unmanaged<CFError>?
    guard let keyData = SecKeyCopyExternalRepresentation(publicKey, &error) as Data? else {
      return "fallback-error"
    }

    let spkiHeader: [UInt8] = [
      0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08,
      0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
    ]
    var derKeyData = Data(spkiHeader)
    derKeyData.append(keyData)
    return Data(SHA256.hash(data: derKeyData)).base64EncodedString()
  }

  private func generateAppleAttestationToken(deviceID: String) -> String {
    // TODO: Remove in production (Dev mode only)
    #if targetEnvironment(simulator)
      return "mock-ios-token"
    #else
      guard DCAppAttestService.shared.isSupported,
        let keyId = UserDefaults.standard.string(forKey: ATTEST_KEY_TAG)
      else {
        return "unsupported"
      }

      let challengeData = Data("\(deviceID):\(Int(Date().timeIntervalSince1970))".utf8)
      var attestationResult = ""
      let semaphore = DispatchSemaphore(value: 0)

      DCAppAttestService.shared.attestKey(keyId, clientDataHash: challengeData) { attestation, _ in
        attestationResult = attestation?.base64EncodedString() ?? "attest-error"
        semaphore.signal()
      }
      semaphore.wait()
      return attestationResult
    #endif
  }

  private func exchangeAttestationForAPIKey(
    keyId: String, attestation: Data, challenge: String, deviceID: String,
    completion: @escaping (String?) -> Void
  ) {
    guard let url = URL(string: API_KEY_ENDPOINT), let ca = self.caCert else {
      return completion(nil)
    }

    var request = URLRequest(url: url)
    request.httpMethod = "POST"
    request.addValue("application/json", forHTTPHeaderField: "Content-Type")
    request.httpBody = try? JSONSerialization.data(withJSONObject: [
      "key_id": keyId, "attestation": attestation.base64EncodedString(), "challenge": challenge,
      "device_id": deviceID, "platform": "ios",
    ])

    URLSession(
      configuration: .ephemeral, delegate: AttestationDelegate(caCert: ca), delegateQueue: nil
    ).dataTask(with: request) { data, response, error in
      guard let data = data, error == nil,
        let jsonResponse = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
        let apiKey = jsonResponse["api_key"] as? String
      else {
        return completion(nil)
      }
      self.storeAPIKey(apiKey)
      completion(apiKey)
    }.resume()
  }

  private class AttestationDelegate: NSObject, URLSessionDelegate {
    let caCert: SecCertificate
    init(caCert: SecCertificate) { self.caCert = caCert }

    func urlSession(
      _ session: URLSession, didReceive challenge: URLAuthenticationChallenge,
      completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void
    ) {

      let ps = challenge.protectionSpace

      if ps.authenticationMethod == NSURLAuthenticationMethodClientCertificate {
        print(
          "DEBUG: Server requested client cert, but we are in bootstrap phase. Proceeding without cert."
        )
        completionHandler(.performDefaultHandling, nil)
        return
      }

      if ps.authenticationMethod == NSURLAuthenticationMethodServerTrust,
        let trust = ps.serverTrust
      {

        SecTrustSetPolicies(trust, SecPolicyCreateSSL(true, ps.host as CFString))
        SecTrustSetAnchorCertificates(trust, [caCert] as CFArray)
        SecTrustSetAnchorCertificatesOnly(trust, true)

        var error: CFError?
        if SecTrustEvaluateWithError(trust, &error) {
          return completionHandler(.useCredential, URLCredential(trust: trust))
        } else {
          print("DEBUG: CA Pinning Error: \(String(describing: error))")
        }
      }

      completionHandler(.cancelAuthenticationChallenge, nil)
    }
  }

  private func storeCertificate(certPEM: String) -> Bool {
    var cleanBase64 =
      certPEM
      .replacingOccurrences(of: "-----BEGIN CERTIFICATE-----", with: "")
      .replacingOccurrences(of: "-----END CERTIFICATE-----", with: "")
      .replacingOccurrences(of: "\n", with: "")
      .replacingOccurrences(of: "\r", with: "")
      .replacingOccurrences(of: " ", with: "")
      .trimmingCharacters(in: .whitespacesAndNewlines)

    print("DEBUG: Cleaning PEM string. Length: \(cleanBase64.count)")

    guard let derData = Data(base64Encoded: cleanBase64, options: .ignoreUnknownCharacters) else {
      print("DEBUG: CRITICAL - Base64 Decoding Failed. The string contains illegal characters.")
      return false
    }

    guard let cert = SecCertificateCreateWithData(nil, derData as CFData) else {
      print("DEBUG: CRITICAL - SecCertificateCreateWithData returned nil. Is the data valid DER?")
      return false
    }

    let query: [String: Any] = [
      kSecClass as String: kSecClassCertificate,
      kSecAttrLabel as String: CERT_TAG,
    ]
    let deleteStatus = SecItemDelete(query as CFDictionary)
    print("DEBUG: Delete status (ignoring -25300): \(deleteStatus)")

    let addQuery: [String: Any] = [
      kSecClass as String: kSecClassCertificate,
      kSecValueRef as String: cert,
      kSecAttrLabel as String: CERT_TAG,
      kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
    ]

    let status = SecItemAdd(addQuery as CFDictionary, nil)

    if status != errSecSuccess {
      print("DEBUG: CRITICAL - SecItemAdd failed with OSStatus code: \(status)")
    } else {
      print("DEBUG: Successfully stored certificate in Keychain!")
    }

    return status == errSecSuccess
  }

  private func loadExistingIdentity() -> Bool {
    guard let cert = loadCertificate() else { return false }
    var result: AnyObject?
    guard
      SecItemCopyMatching(
        [
          kSecClass as String: kSecClassIdentity, kSecAttrLabel as String: CERT_TAG,
          kSecReturnRef as String: true, kSecMatchLimit as String: kSecMatchLimitOne,
        ] as CFDictionary, &result) == errSecSuccess
    else { return false }

    let ident = result as! SecIdentity
    var certRef: SecCertificate?
    SecIdentityCopyCertificate(ident, &certRef)

    if let identityCert = certRef,
      (SecCertificateCopyData(identityCert) as Data) == (SecCertificateCopyData(cert) as Data)
    {
      self.identity = ident
      return true
    }
    return false
  }

  private func wipeIdentityState() {
    deleteKey(tag: KEY_TAG)
    deleteKey(tag: PUB_KEY_TAG)
    [
      [kSecClass as String: kSecClassCertificate, kSecAttrLabel as String: CERT_TAG],
      [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrAccount as String: "com.yourapp.api_key",
      ],
      [kSecClass as String: kSecClassGenericPassword, kSecAttrAccount as String: CERT_EXPIRY_KEY],
    ].forEach { SecItemDelete($0 as CFDictionary) }
    self.identity = nil
    self.apiKey = nil
  }

  private func checkAndRenewCertificate() {
    if let expiry = loadCertExpiry(), expiry <= Date().addingTimeInterval(24 * 3600) {
      provisionIdentity({ _ in }, reject: { _, _, _ in })
    }
  }

  private func loadCACert() {
    guard let url = Bundle.main.url(forResource: "ca", withExtension: "crt") else {
      print("DEBUG: CRITICAL - 'ca.crt' file not found in App Bundle!")
      return
    }

    guard let data = try? Data(contentsOf: url) else {
      print("DEBUG: CRITICAL - Failed to read data from ca.crt")
      return
    }

    if let cert = SecCertificateCreateWithData(nil, data as CFData) {
      self.caCert = cert
      print("DEBUG: Successfully loaded ca.crt as DER (binary)")
      return
    }

    if let str = String(data: data, encoding: .utf8) {
      let clean = str.replacingOccurrences(of: "-----BEGIN CERTIFICATE-----", with: "")
        .replacingOccurrences(of: "-----END CERTIFICATE-----", with: "")
        .replacingOccurrences(of: "\n", with: "")
        .replacingOccurrences(of: "\r", with: "")
        .replacingOccurrences(of: " ", with: "")
        .trimmingCharacters(in: .whitespacesAndNewlines)

      if let derData = Data(base64Encoded: clean, options: .ignoreUnknownCharacters),
        let cert = SecCertificateCreateWithData(nil, derData as CFData)
      {
        self.caCert = cert
        print("DEBUG: Successfully loaded ca.crt as PEM (Base64)")
        return
      }
    }

    print("DEBUG: CRITICAL - Failed to parse ca.crt as either DER or PEM.")
  }

  private func loadPublicKey() -> SecKey? {
    var result: CFTypeRef?
    guard
      SecItemCopyMatching(
        [
          kSecClass as String: kSecClassKey,
          kSecAttrApplicationTag as String: KEY_TAG.data(using: .utf8)!,
          kSecAttrKeyClass as String: kSecAttrKeyClassPrivate, kSecReturnRef as String: true,
        ] as CFDictionary, &result) == errSecSuccess
    else { return nil }
    return SecKeyCopyPublicKey(result as! SecKey)
  }

  private func deleteKey(tag: String) {
    SecItemDelete(
      [
        kSecClass as String: kSecClassKey,
        kSecAttrApplicationTag as String: tag.data(using: .utf8)!,
      ] as CFDictionary)
  }

  private func storeAPIKey(_ key: String) {
    SecItemDelete(
      [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrAccount as String: "com.yourapp.api_key",
      ] as CFDictionary)
    SecItemAdd(
      [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrAccount as String: "com.yourapp.api_key",
        kSecValueData as String: key.data(using: .utf8)!,
        kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
      ] as CFDictionary, nil)
  }

  private func loadAPIKey() -> String? {
    var result: AnyObject?
    return SecItemCopyMatching(
      [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrAccount as String: "com.yourapp.api_key", kSecReturnData as String: true,
        kSecMatchLimit as String: kSecMatchLimitOne,
      ] as CFDictionary, &result) == errSecSuccess
      ? String(data: result as! Data, encoding: .utf8) : nil
  }

  private func loadOrCreateDeviceID() -> String {
    var result: AnyObject?
    if SecItemCopyMatching(
      [
        kSecClass as String: kSecClassGenericPassword, kSecAttrAccount as String: DEVICE_ID_KEY,
        kSecReturnData as String: true, kSecMatchLimit as String: kSecMatchLimitOne,
      ] as CFDictionary, &result) == errSecSuccess
    {
      return String(data: result as! Data, encoding: .utf8)!
    }
    let id = UIDevice.current.identifierForVendor?.uuidString ?? UUID().uuidString
    SecItemAdd(
      [
        kSecClass as String: kSecClassGenericPassword, kSecAttrAccount as String: DEVICE_ID_KEY,
        kSecValueData as String: id.data(using: .utf8)!,
        kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
      ] as CFDictionary, nil)
    return id
  }

  private func storeCertExpiry(_ date: Date) {
    SecItemDelete(
      [kSecClass as String: kSecClassGenericPassword, kSecAttrAccount as String: CERT_EXPIRY_KEY]
        as CFDictionary)
    SecItemAdd(
      [
        kSecClass as String: kSecClassGenericPassword, kSecAttrAccount as String: CERT_EXPIRY_KEY,
        kSecValueData as String: ISO8601DateFormatter().string(from: date).data(using: .utf8)!,
        kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
      ] as CFDictionary, nil)
  }

  private func loadCertExpiry() -> Date? {
    var result: AnyObject?
    return SecItemCopyMatching(
      [
        kSecClass as String: kSecClassGenericPassword, kSecAttrAccount as String: CERT_EXPIRY_KEY,
        kSecReturnData as String: true, kSecMatchLimit as String: kSecMatchLimitOne,
      ] as CFDictionary, &result) == errSecSuccess
      ? ISO8601DateFormatter().date(from: String(data: result as! Data, encoding: .utf8)!) : nil
  }

  private func loadCertificate() -> SecCertificate? {
    var result: AnyObject?
    return SecItemCopyMatching(
      [
        kSecClass as String: kSecClassCertificate, kSecAttrLabel as String: CERT_TAG,
        kSecReturnRef as String: true,
      ] as CFDictionary, &result) == errSecSuccess ? (result as! SecCertificate) : nil
  }
}
