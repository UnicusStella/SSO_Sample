package com.dreamsecurity.sso.server.crypto.api;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Calendar;
import java.util.Date;
import java.util.LinkedList;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import com.dreamsecurity.jcaos.Environment;
import com.dreamsecurity.jcaos.cms.SignedAndEnvelopedData;
import com.dreamsecurity.jcaos.cms.SignedAndEnvelopedDataGenerator;
import com.dreamsecurity.jcaos.cms.SignedData;
import com.dreamsecurity.jcaos.pkcs.PKCS8;
import com.dreamsecurity.jcaos.pkcs.PKCS8PrivateKeyInfo;
import com.dreamsecurity.jcaos.util.FileUtil;
import com.dreamsecurity.jcaos.util.encoders.Hex;
import com.dreamsecurity.jcaos.x509.X500Principal;
import com.dreamsecurity.jcaos.x509.X509Certificate;
import com.dreamsecurity.jcaos.x509.X509CertificateGenerator;
import com.dreamsecurity.kcmv.jce.provider.MJCIvParameterSpec;
import com.dreamsecurity.kcmv.jce.provider.MJCSecretKey;
import com.dreamsecurity.kcmv.jce.provider.MagicJCryptoProvider;
import com.dreamsecurity.kcmv.jce.provider.Zeroize;
import com.dreamsecurity.sso.lib.slf.Logger;
import com.dreamsecurity.sso.lib.slf.LoggerFactory;
import com.dreamsecurity.sso.server.api.audit.vo.AuditVO;
import com.dreamsecurity.sso.server.common.MStatus;
import com.dreamsecurity.sso.server.config.SSOConfig;
import com.dreamsecurity.sso.server.crypto.CryptoApi;
import com.dreamsecurity.sso.server.crypto.CryptoApiException;
import com.dreamsecurity.sso.server.crypto.SSOSecretKey;
import com.dreamsecurity.sso.server.util.Util;

public class MJCryptoApi implements CryptoApi
{
	private static Logger log = LoggerFactory.getLogger(MJCryptoApi.class);

	private final String providerName = "MJC";

	private int status = -1;

	protected SSOSecretKey KEK = null;
	protected byte[] DEK = null;

	private String randomAlgorithm = "SHA256DRBG";
	private String cryptoAlgorithm = "SEED";
	private String cipherAlgorithm = "SEED/CBC/PKCS5Padding";
	private String hashAlgorithm = "SHA256";
	private String hmacAlgorithm = "HMAC-SHA256";
	private String pssAlgorithm = "MGF1";
	private String rsaAlgorithm = "OAEPWithSHA256AndMGF1Padding";

	private LinkedList<AuditVO> auditList = null;

	static {
		MagicJCryptoProvider.installProvider();
		log.info("### MagicJCrypto Initialization");
	}

	public MJCryptoApi()
	{
		MagicJCryptoProvider mjc = new MagicJCryptoProvider();
		mjc.setKCMV();

		if (MagicJCryptoProvider.isKCMV()) {
			log.info("### MagicJCrypto run KCMV mode");
		}
		else {
			log.info("### MagicJCrypto run non-KCMV mode");
		}
	}

	public int init(LinkedList<AuditVO> auditList)
	{
		this.auditList = auditList;

		SSOConfig config = SSOConfig.getInstance();
		String licensePath = config.getHomePath("license");

		if (Util.isEmpty(licensePath)) {
			licensePath = ".";
		}

		Environment.setLicensePath(licensePath);
		Environment.setJCEProvider(providerName);

		if (!MagicJCryptoProvider.selfTest(true)) {
			AuditVO audit = new AuditVO();
			audit.setDate(Util.getDateFormat("yyyyMMdd"));
			audit.setTime(Util.getDateFormat("HHmmss"));
			audit.setUser(config.getServerName());
			audit.setType("AC");
			audit.setResult("1");
			audit.setDetail(config.getServerName() + ", 시동 시 테스트, Self Test");
			auditList.add(audit);

			status = -1;
			return MStatus.CRYPTO_SELF_TEST;
		}
		else {
			AuditVO audit = new AuditVO();
			audit.setDate(Util.getDateFormat("yyyyMMdd"));
			audit.setTime(Util.getDateFormat("HHmmss"));
			audit.setUser(config.getServerName());
			audit.setType("AC");
			audit.setResult("0");
			audit.setDetail(config.getServerName() + ", 시동 시 테스트");
			auditList.add(audit);

			status = 0;

			try {
				loadSecret();
			}
			catch (CryptoApiException e) {
				status = -2;
				return MStatus.CRYPTO_INITIALIZE;
			}
		}

		return MStatus.SUCCESS;
	}

	public void clearKey()
	{
		Util.zeroize(this.DEK);

		// 암호키 파기
		Util.setAuditInfo(Util.getDateFormat("yyyyMMdd"), Util.getDateFormat("HHmmss"),
				SSOConfig.getInstance().getServerName(), "AW", "0", "Data Encrypt Key 파기, 0 으로 덮어쓰기");

		this.KEK.finalize();

		// 암호키 파기
		Util.setAuditInfo(Util.getDateFormat("yyyyMMdd"), Util.getDateFormat("HHmmss"),
				SSOConfig.getInstance().getServerName(), "AW", "0", "Key Encrypt Key 파기, 0 으로 덮어쓰기");
	}

	public String getProviderName()
	{
		return providerName;
	}

	public int getStatus()
	{
		return status;
	}

	private void loadSecret() throws CryptoApiException
	{
		String code = System.getProperty("dreamsso.code");
		System.setProperty("dreamsso.code", "");

		if (!Util.isEmpty(code)) {
			this.KEK = generateKEKByPwd(code);

			try {
				Util.zeroize(code);
			}
			catch (Exception e) {
				throw new CryptoApiException(MStatus.ERR_ZEROIZE, e);
			}
		}
		else {
			this.KEK = generateKEKByPwd(SSOConfig.getInstance().getServerName());

			try {
				Util.zeroize(code);
			}
			catch (Exception e) {
				throw new CryptoApiException(MStatus.ERR_ZEROIZE, e);
			}
		}

		try {
			String dek = SSOConfig.getInstance().getServerCode();
			this.DEK = Hex.decode(dek);

			String block = SSOConfig.getInstance().getServerBlock();
			this.KEK.setIv(Hex.decode(block));

			byte[] decDEK = decrypt(this.KEK.getKey().clone(), this.KEK.getIv().clone(), this.DEK, this.cryptoAlgorithm, this.cipherAlgorithm);
			Util.zeroize(decDEK);
		}
		catch (Exception e) {
			throw new CryptoApiException(MStatus.CRYPTO_DECRYPT_DEK, e);
		}
	}

	private SSOSecretKey generateKEKByPwd(String password) throws CryptoApiException
	{
		try {
			SSOConfig config = SSOConfig.getInstance();
			String certFile = config.getHomePath("cert/" + config.getServerName() + "_Enc.der");

			byte[] cert = FileUtil.read(certFile);
			byte[] byteData = new byte[password.getBytes().length + cert.length];
			System.arraycopy(password.getBytes(), 0, byteData, 0, password.getBytes().length);
			System.arraycopy(cert, 0, byteData, password.getBytes().length, cert.length);

			byte[] bytePwd = digest(byteData, this.hashAlgorithm);

			byte[] out = digest(bytePwd, this.hashAlgorithm);

			byte[] salt = new byte[16];
			System.arraycopy(out, 0, salt, 0, salt.length);
			int iterationCount = 1024;

			// PBKDF2 start
			byte[] macValue = null;
			byte[] dk = new byte[32];

			Mac mac = Mac.getInstance(this.hmacAlgorithm, this.providerName);
			SecretKey sk = new SecretKeySpec(bytePwd, this.hmacAlgorithm);

			for (int i = 0; i < iterationCount; i++) {
				if (i == 0) {
					byte[] tmp = new byte[salt.length + 4];
					/* salt || Int(i) */
					System.arraycopy(salt, 0, tmp, 0, salt.length);
					tmp[tmp.length - 1] = 1;

					mac.init(sk);
					macValue = mac.doFinal(tmp);

					tmp = Util.zeroize(tmp);
				}
				else {
					/* PRF(p, Uc) */
					mac.init(sk);
					macValue = mac.doFinal(macValue);
				}

				/* Tl = U1 xor U2 xor ... xor Uc */
				for (int j = 0; j < 32; j++)
					dk[j] ^= macValue[j];
			}
			// PBKDF2 end

			byte[] skParam = new byte[16];
			byte[] ivParam = new byte[16];
			System.arraycopy(dk, 0, skParam, 0, skParam.length);

			SSOSecretKey ssoSeckey = new SSOSecretKey(this.cryptoAlgorithm, skParam.clone(), ivParam.clone());

			Util.zeroize(bytePwd);
			Util.zeroize(out);
			Util.zeroize(salt);
			Util.zeroize(dk);
			Util.zeroize(skParam);
			Util.zeroize(ivParam);

			AuditVO audit = new AuditVO();
			audit.setDate(Util.getDateFormat("yyyyMMdd"));
			audit.setTime(Util.getDateFormat("HHmmss"));
			audit.setUser(SSOConfig.getInstance().getServerName());
			audit.setType("AM");  // 암호키 생성
			audit.setResult("0");
			audit.setDetail("Key Encrypt Key, SEED/CBC");
			auditList.add(audit);

			return ssoSeckey;
		}
		catch (Exception e) {
			AuditVO audit = new AuditVO();
			audit.setDate(Util.getDateFormat("yyyyMMdd"));
			audit.setTime(Util.getDateFormat("HHmmss"));
			audit.setUser(SSOConfig.getInstance().getServerName());
			audit.setType("AM");  // 암호키 생성
			audit.setResult("1");
			audit.setDetail("Key Encrypt Key, SEED/CBC");
			auditList.add(audit);

			throw new CryptoApiException(MStatus.CRYPTO_GEN_KEK, e);
		}
	}

	public byte[] getRandom(int size, String algorithm) throws CryptoApiException
	{
		try {
			byte[] result = new byte[size];
			SecureRandom random = SecureRandom.getInstance(algorithm, providerName);
			random.nextBytes(result);

			return result;
		}
		catch (Exception e) {
			throw new CryptoApiException(MStatus.CRYPTO_GEN_RANDOM, e);
		}
	}

	public byte[] digest(byte[] input, String algorithm) throws CryptoApiException
	{
		try {
			MessageDigest md = MessageDigest.getInstance(algorithm, providerName);
			byte[] result = md.digest(input);

			return result;
		}
		catch (Exception e) {
			throw new CryptoApiException(MStatus.CRYPTO_DIGEST, e);
		}
	}

	public byte[] hmac(byte[] key, byte[] input, String algorithm) throws CryptoApiException
	{
		try {
			SecretKey macKey = new MJCSecretKey(key.clone(), algorithm);

			Mac mac = Mac.getInstance(algorithm, providerName);
			mac.init(macKey);
			mac.update(input);
			byte[] result = mac.doFinal();

			Zeroize.zeroize(macKey);

			return result;
		}
		catch (Exception e) {
			throw new CryptoApiException(MStatus.CRYPTO_HMAC, e);
		}
	}

	public KeyPair genKeyPair(String algorithm, int keyLen, String curvedName) throws CryptoApiException
	{
		try {
			KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance(algorithm, providerName);
			keyPairGen.initialize(keyLen);
			KeyPair keyPair = keyPairGen.generateKeyPair();
	
			return keyPair;
		}
		catch (Exception e) {
			throw new CryptoApiException(MStatus.CRYPTO_KEY_PAIR, e);
		}
	}

	public X509Certificate generatePublic(KeyPair serverPair, X509Certificate caCert, PrivateKey caPrivate, String cnName, String useType, int period) throws CryptoApiException
	{
		try {
			X509CertificateGenerator x509Cert = X509CertificateGenerator.getInstance(caCert, caPrivate);

			// Certificate Serial Number
			byte[] serialNumber = getRandom(10, randomAlgorithm);
			x509Cert.setSerialNumber(serialNumber);

			// Subject Name
			x509Cert.setSubjectDN(new X500Principal("CN=" + cnName + ",OU=SSO,O=DreamSecurity,C=KR"));

			// validity Period
			Date notBefore, notAfter;

			Calendar cal = Calendar.getInstance();

			notBefore = cal.getTime();

			cal.add(Calendar.YEAR, period);
			notAfter = cal.getTime();
		
			x509Cert.setValidity(notBefore, notAfter);

			// Subject Public Key
			x509Cert.setSubjectPublicKey(serverPair.getPublic());

			// Authority Key Identifier
			x509Cert.setAuthorityKeyIdentifier(X509CertificateGenerator.AKI_KEY_ID | X509CertificateGenerator.AKI_AUTH_CERT_ISSUER_AND_SERIAL_NUM, false);

			// Subject Key Identifier
			x509Cert.setSubjectKeyIdentifier(false);

			// Key Usage
			if (useType.equalsIgnoreCase("S")) {
				x509Cert.setKeyUsage(X509CertificateGenerator.KEY_USAGE_DIGITAL_SIGNATURE | X509CertificateGenerator.KEY_USAGE_NONT_REPUDIATION, true);
			}
			else {
				x509Cert.setKeyUsage(X509CertificateGenerator.KEY_USAGE_KEY_ENCIPHERMENT | X509CertificateGenerator.KEY_USAGE_DATA_ENCIPHERMENT, true);
			}

			return x509Cert.generate(hashAlgorithm);
		}
		catch (Exception e) {
			throw new CryptoApiException(MStatus.CRYPTO_GEN_PUBLIC, e);
		}
	}

	public byte[] generatePrivate(PrivateKey priKey, byte[] key) throws CryptoApiException
	{
		try {
			PKCS8 pkcs8 = new PKCS8(key);
			pkcs8.setPBES2Algorithm("SEED/CBC", 128, "HmacSHA256");
			PKCS8PrivateKeyInfo priKeyInfo = PKCS8PrivateKeyInfo.getInstance(priKey.getEncoded());

			return pkcs8.encrypt(priKeyInfo);
		}
		catch (Exception e) {
			throw new CryptoApiException(MStatus.CRYPTO_GEN_PRIVATE, e);
		}
	}

	public byte[] hmacByDEK(byte[] input, String algorithm) throws CryptoApiException
	{
		try {
			byte[] decDEK = decrypt(this.KEK.getKey().clone(), this.KEK.getIv().clone(), this.DEK, this.cryptoAlgorithm, this.cipherAlgorithm);
			SSOSecretKey sKey = new SSOSecretKey(this.cryptoAlgorithm, decDEK);

			SecretKey macKey = new MJCSecretKey(sKey.getKey().clone(), algorithm);

			Mac mac = Mac.getInstance(algorithm, providerName);
			mac.init(macKey);
			mac.update(input);
			byte[] result = mac.doFinal();

			Zeroize.zeroize(macKey);
			sKey.finalize();
			Util.zeroize(decDEK);

			return result;
		}
		catch (Exception e) {
			throw new CryptoApiException(MStatus.CRYPTO_HMAC, e);
		}
	}

	public String encryptByDEK(String input) throws CryptoApiException
	{
		try {
			byte[] decDEK = decrypt(this.KEK.getKey().clone(), this.KEK.getIv().clone(), this.DEK, this.cryptoAlgorithm, this.cipherAlgorithm);
			SSOSecretKey sKey = new SSOSecretKey(this.cryptoAlgorithm, decDEK);

			byte[] encData = encrypt(sKey.getKey(), sKey.getIv(), input.getBytes(), this.cryptoAlgorithm, this.cipherAlgorithm);

			Util.zeroize(decDEK);
			sKey.finalize();

			return new String(Hex.encode(encData));
		}
		catch (Exception e) {
			throw new CryptoApiException(MStatus.CRYPTO_DECRYPT_DEK, e);
		}
	}

	public byte[] decryptByDEK(String input) throws CryptoApiException
	{
		try {
			byte[] encText = Hex.decode(input);

			byte[] decDEK = decrypt(this.KEK.getKey().clone(), this.KEK.getIv().clone(), this.DEK, this.cryptoAlgorithm, this.cipherAlgorithm);
			SSOSecretKey sKey = new SSOSecretKey(this.cryptoAlgorithm, decDEK);

			byte[] decData = decrypt(sKey.getKey(), sKey.getIv(), encText, this.cryptoAlgorithm, this.cipherAlgorithm);

			Util.zeroize(decDEK);
			sKey.finalize();

			return decData;
		}
		catch (Exception e) {
			throw new CryptoApiException(MStatus.CRYPTO_DECRYPT_DEK, e);
		}
	}

	public byte[] encrypt(byte[] key, byte[] iv, byte[] input, String algorithm, String cipherAlgorithm) throws CryptoApiException
	{
		try {
			SecretKey sk = new MJCSecretKey(key.clone(), algorithm);
			AlgorithmParameterSpec ips = new MJCIvParameterSpec(iv.clone());

			Cipher cipher = Cipher.getInstance(cipherAlgorithm, providerName);
			cipher.init(Cipher.ENCRYPT_MODE, sk, ips);
			byte[] result = cipher.doFinal(input);

			Zeroize.zeroize(sk);
			Zeroize.zeroize(ips);

			return result;
		}
		catch (Exception e) {
			throw new CryptoApiException(MStatus.CRYPTO_ENCRYPT_KEY, e);
		}
	}

	public byte[] decrypt(byte[] key, byte[] iv, byte[] input, String algorithm, String cipherAlgorithm) throws CryptoApiException
	{
		try {
			SecretKey sk = new MJCSecretKey(key.clone(), algorithm);
			AlgorithmParameterSpec ips = new MJCIvParameterSpec(iv.clone());

			Cipher cipher = Cipher.getInstance(cipherAlgorithm, providerName);
			cipher.init(Cipher.DECRYPT_MODE, sk, ips);
			byte[] result = cipher.doFinal(input);

			Zeroize.zeroize(sk);
			Zeroize.zeroize(ips);

			return result;
		}
		catch (Exception e) {
			throw new CryptoApiException(MStatus.CRYPTO_DECRYPT_KEY, e);
		}
	}

	public byte[] encrypt(byte[] key, byte[] input, String algorithm, String cipherAlgorithm) throws CryptoApiException
	{
		try {
			SecretKey sk = new MJCSecretKey(key.clone(), algorithm);

			Cipher cipher = Cipher.getInstance(cipherAlgorithm, providerName);
			cipher.init(Cipher.ENCRYPT_MODE, sk);
			byte[] result = cipher.doFinal(input);

			Zeroize.zeroize(sk);

			return result;
		}
		catch (Exception e) {
			throw new CryptoApiException(MStatus.CRYPTO_ENCRYPT_KEY, e);
		}
	}

	public byte[] decrypt(byte[] key, byte[] input, String algorithm, String cipherAlgorithm) throws CryptoApiException
	{
		try {
			SecretKey sk = new MJCSecretKey(key.clone(), algorithm);

			Cipher cipher = Cipher.getInstance(cipherAlgorithm, providerName);
			cipher.init(Cipher.DECRYPT_MODE, sk);
			byte[] result = cipher.doFinal(input);

			Zeroize.zeroize(sk);

			return result;
		}
		catch (Exception e) {
			throw new CryptoApiException(MStatus.CRYPTO_DECRYPT_KEY, e);
		}
	}

	public byte[] encryptPrivateKey(byte[] key, byte[] input, String algorithm) throws CryptoApiException
	{
		try {
			PKCS8PrivateKeyInfo cert = PKCS8PrivateKeyInfo.getInstance(key.clone());
			PrivateKey priKey = cert.getPrivateKey();

			Cipher cipher = Cipher.getInstance(algorithm, providerName);
			cipher.init(Cipher.ENCRYPT_MODE, priKey);
			byte[] result = cipher.doFinal(input);

			Zeroize.zeroize(priKey);

			return result;
		}
		catch (Exception e) {
			throw new CryptoApiException(MStatus.CRYPTO_ENCRYPT_PRIVATEKEY, e);
		}
	}

	public byte[] decryptPrivateKey(byte[] key, byte[] input, String algorithm) throws CryptoApiException
	{
		try {
			PKCS8PrivateKeyInfo cert = PKCS8PrivateKeyInfo.getInstance(key.clone());
			PrivateKey priKey = cert.getPrivateKey();

			Cipher cipher = Cipher.getInstance(algorithm, providerName);
			cipher.init(Cipher.DECRYPT_MODE, priKey);
			byte[] result = cipher.doFinal(input);

			Zeroize.zeroize(priKey);

			return result;
		}
		catch (Exception e) {
			throw new CryptoApiException(MStatus.CRYPTO_DECRYPT_PRIVATEKEY, e);
		}
	}

	public byte[] encryptPublicKey(byte[] key, byte[] input, String algorithm) throws CryptoApiException
	{
		try {
			X509Certificate cert = X509Certificate.getInstance(key.clone());
			PublicKey pubKey = cert.getPublicKey();

			Cipher cipher = Cipher.getInstance(algorithm, providerName);
			cipher.init(Cipher.ENCRYPT_MODE, pubKey);
			byte[] result = cipher.doFinal(input);

			return result;
		}
		catch (Exception e) {
			throw new CryptoApiException(MStatus.CRYPTO_ENCRYPT_PUBLICKEY, e);
		}
	}

	public byte[] encryptPublicKey(PublicKey pubKey, byte[] input, String algorithm) throws CryptoApiException
	{
		try {
			Cipher cipher = Cipher.getInstance(algorithm, providerName);
			cipher.init(Cipher.ENCRYPT_MODE, pubKey);
			byte[] result = cipher.doFinal(input);

			return result;
		}
		catch (Exception e) {
			throw new CryptoApiException(MStatus.CRYPTO_ENCRYPT_PUBLICKEY, e);
		}
	}

	public byte[] decryptPublicKey(byte[] key, byte[] input, String algorithm) throws CryptoApiException
	{
		try {
			X509Certificate cert = X509Certificate.getInstance(key.clone());
			PublicKey pubKey = cert.getPublicKey();

			Cipher cipher = Cipher.getInstance(algorithm, providerName);
			cipher.init(Cipher.DECRYPT_MODE, pubKey);
			byte[] result = cipher.doFinal(input);

			Zeroize.zeroize(pubKey);

			return result;
		}
		catch (Exception e) {
			throw new CryptoApiException(MStatus.CRYPTO_DECRYPT_PUBLICKEY, e);
		}
	}

	public byte[] signature(byte[] key, byte[] input, String algorithm) throws CryptoApiException
	{
		try {
			PKCS8PrivateKeyInfo cert = PKCS8PrivateKeyInfo.getInstance(key.clone());
			PrivateKey priKey = cert.getPrivateKey();

			Signature sign = Signature.getInstance(algorithm, providerName);
			sign.initSign(priKey);
			sign.update(input);

			byte[] result = sign.sign();

			Zeroize.zeroize(priKey);

			return result;
		}
		catch (Exception e) {
			throw new CryptoApiException(MStatus.CRYPTO_SIGNATURE, e);
		}
	}

	public void verify(byte[] key, byte[] signature, byte[] input, String algorithm) throws CryptoApiException
	{
		try {
			X509Certificate cert = X509Certificate.getInstance(key.clone());
			PublicKey pubKey = cert.getPublicKey();

			Signature verify = Signature.getInstance(algorithm, providerName);
			verify.initVerify(pubKey);
			verify.update(input);

			boolean result = verify.verify(signature);

			Zeroize.zeroize(pubKey);

			if (!result)
				throw new Exception("Verify Failure");
		}
		catch (Exception e) {
			throw new CryptoApiException(MStatus.CRYPTO_VERIFY, e);
		}
	}

	public byte[] signature(PrivateKey priKey, byte[] input, String algorithm) throws CryptoApiException
	{
		try {
			Signature sign = Signature.getInstance(algorithm, providerName);
			sign.initSign(priKey);
			sign.update(input);
			byte[] result = sign.sign();

			return result;
		}
		catch (Exception e) {
			throw new CryptoApiException(MStatus.CRYPTO_SIGNATURE, e);
		}
	}

	public void verify(PublicKey pubKey, byte[] signature, byte[] input, String algorithm) throws CryptoApiException
	{
		try {
			Signature verify = Signature.getInstance(algorithm, providerName);
			verify.initVerify(pubKey);
			verify.update(input);
			boolean result = verify.verify(signature);

			if (!result) {
				throw new Exception("Verify Failure");
			}
		}
		catch (Exception e) {
			throw new CryptoApiException(MStatus.CRYPTO_VERIFY, e);
		}
	}

	public byte[] generateSignedEnvelopedData(byte[] enccert, byte[] signcert, byte[] privatekey, byte[] input) throws CryptoApiException
	{
		try {
			X509Certificate encCert = X509Certificate.getInstance(enccert.clone());
			X509Certificate signCert = X509Certificate.getInstance(signcert.clone());
			PKCS8PrivateKeyInfo privatekeyinfo = PKCS8PrivateKeyInfo.getInstance(privatekey.clone());

			SignedAndEnvelopedDataGenerator genSignedAndEnvelopedData = new SignedAndEnvelopedDataGenerator(cryptoAlgorithm);
			genSignedAndEnvelopedData.setContent(input);
			genSignedAndEnvelopedData.addRecipient(encCert, rsaAlgorithm);
			byte[] envData = genSignedAndEnvelopedData.generate(signCert, privatekeyinfo, hashAlgorithm, pssAlgorithm).getEncoded();

			return envData;
		}
		catch (Exception e) {
			throw new CryptoApiException(MStatus.CRYPTO_GEN_ENVELOPED, e);
		}
	}

	public byte[] processSignedEnvelopedData(byte[] enccert, byte[] privatekey, byte[] input) throws CryptoApiException
	{
		try {
			X509Certificate encCert = X509Certificate.getInstance(enccert.clone());
			PKCS8PrivateKeyInfo privatekeyinfo = PKCS8PrivateKeyInfo.getInstance(privatekey.clone());

			SignedAndEnvelopedData signedAndEnvelopedData = SignedAndEnvelopedData.getInstance(input);
			byte[] decData = signedAndEnvelopedData.decryptAndVerify(encCert, privatekeyinfo);

			return decData;
		}
		catch (Exception e) {
			throw new CryptoApiException(MStatus.CRYPTO_PROC_ENVELOPED, e);
		}
	}

	public SignedData processSignedData(byte[] input) throws CryptoApiException
	{
		try {
			SignedData signedData = SignedData.getInstance(input);
			signedData.verify();

			return signedData;
		}
		catch (Exception e) {
			throw new CryptoApiException(MStatus.CRYPTO_PROC_SIGNED, e);
		}
	}

	public SSOSecretKey generateSecretKey(String algorithm, String randomAlgorithm) throws CryptoApiException
	{
		try {
			KeyGenerator keyGen = KeyGenerator.getInstance(algorithm, providerName);
			keyGen.init(128);
			SecretKey secKey = keyGen.generateKey();

			byte[] ivParam = new byte[16];
			SecureRandom rand = SecureRandom.getInstance(randomAlgorithm, providerName);
			rand.nextBytes(ivParam);

			SSOSecretKey ssoSeckey = new SSOSecretKey(keyGen.getAlgorithm(), secKey.getEncoded().clone(), ivParam.clone());

			Zeroize.zeroize(secKey);
			Util.zeroize(ivParam);

			return ssoSeckey;
		}
		catch (Exception e) {
			throw new CryptoApiException(MStatus.CRYPTO_GEN_SECRETKEY, e);
		}
	}
}