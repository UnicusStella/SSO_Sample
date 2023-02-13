package com.dreamsecurity.sso.agent.crypto;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.StringWriter;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateFactory;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NamedNodeMap;
import org.w3c.dom.Node;

import com.dreamsecurity.jcaos.asn1.oid.AlgorithmObjectIdentifiers;
import com.dreamsecurity.jcaos.asn1.oid.PKCS5ObjectIdentifiers;
import com.dreamsecurity.jcaos.util.FileUtil;
import com.dreamsecurity.jcaos.util.encoders.Hex;
import com.dreamsecurity.jcaos.x509.X509Certificate;
import com.dreamsecurity.kcmv.jce.provider.MagicJCryptoProvider;
import com.dreamsecurity.sso.agent.common.MStatus;
import com.dreamsecurity.sso.agent.config.SSOConfig;
import com.dreamsecurity.sso.agent.exception.SSOException;
import com.dreamsecurity.sso.agent.log.Logger;
import com.dreamsecurity.sso.agent.log.LoggerFactory;
import com.dreamsecurity.sso.agent.metadata.CredentialRepository;
import com.dreamsecurity.sso.agent.metadata.MetadataRepository;
import com.dreamsecurity.sso.agent.util.ByteUtil;
import com.dreamsecurity.sso.agent.util.SAMLUtil;
import com.dreamsecurity.sso.agent.util.Util;
import com.dreamsecurity.sso.lib.dss.Configuration;
import com.dreamsecurity.sso.lib.dss.s2.core.Assertion;
import com.dreamsecurity.sso.lib.dss.s2.core.AuthnRequest;
import com.dreamsecurity.sso.lib.dss.s2.core.EncryptedAssertion;
import com.dreamsecurity.sso.lib.dss.s2.core.NameID;
import com.dreamsecurity.sso.lib.dss.s2.core.Subject;
import com.dreamsecurity.sso.lib.dss.s2.core.SubjectConfirmation;
import com.dreamsecurity.sso.lib.dss.s2.core.SubjectConfirmationData;
import com.dreamsecurity.sso.lib.dsx.encryption.CipherValue;
import com.dreamsecurity.sso.lib.dsx.encryption.EncryptedKey;
import com.dreamsecurity.sso.lib.dsx.io.Unmarshaller;
import com.dreamsecurity.sso.lib.dsx.parse.BasicParserPool;
import com.dreamsecurity.sso.lib.dsx.parse.ParserPool;
import com.dreamsecurity.sso.lib.dsx.schema.XSString;
import com.dreamsecurity.sso.lib.dsx.security.SecurityHelper;
import com.dreamsecurity.sso.lib.dsx.security.credential.Credential;
import com.dreamsecurity.sso.lib.dsx.security.keyinfo.KeyInfoGenerator;
import com.dreamsecurity.sso.lib.dsx.security.x509.BasicX509Credential;
import com.dreamsecurity.sso.lib.dsx.signature.KeyInfo;
import com.dreamsecurity.sso.lib.dsx.signature.KeyValue;
import com.dreamsecurity.sso.lib.dsx.signature.SignableXMLObject;
import com.dreamsecurity.sso.lib.dsx.signature.Signature;
import com.dreamsecurity.sso.lib.dsx.signature.SignatureConstants;
import com.dreamsecurity.sso.lib.dsx.signature.impl.SignatureBuilder;
import com.dreamsecurity.sso.lib.jsn.JSONObject;
import com.dreamsecurity.sso.lib.jsn.parser.JSONParser;
import com.dreamsecurity.sso.lib.jsn.parser.ParseException;
import com.dreamsecurity.sso.lib.jtm.DateTime;
import com.dreamsecurity.sso.lib.jtm.DateTimeZone;
import com.dreamsecurity.sso.lib.jtm.format.DateTimeFormat;
import com.dreamsecurity.sso.lib.jtm.format.DateTimeFormatter;
import com.dreamsecurity.sso.lib.xsc.algorithms.MessageDigestAlgorithm;
import com.dreamsecurity.sso.lib.xsc.c14n.Canonicalizer;
import com.dreamsecurity.sso.lib.xsc.utils.Base64;

public class SSOCryptoApi
{
	private static Logger log = LoggerFactory.getInstance().getLogger(SSOCryptoApi.class);

	private static SSOCryptoApi instance = null;
	private static CryptoApi crypto = null;

	private Credential encCert = null;
	private Credential signCert = null;

	private String providerName = null;

	private String randomAlgorithm = "SHA256DRBG";
	private String cryptoAlgorithm = "SEED";
	private String cipherAlgorithm = "SEED/CBC/PKCS5Padding";
	private String rsaAlgorithm = "RSA/NONE/OAEPWithSHA256andMGF1Padding";
	private String signAlgorithm = "SHA256withRSA/PSS";
	private String hashAlgorithm = "SHA256";
	private String hmacAlgorithm = "HMAC-SHA256";

	private SSOCryptoApi() throws CryptoApiException
	{
		crypto = CryptoApiFactory.getCryptoApi();
		providerName = crypto.getProviderName();

		loadCert();
	}

	public static SSOCryptoApi getInstance() throws CryptoApiException
	{
		if (instance == null) {
			synchronized (SSOCryptoApi.class) {
				if (instance == null) {
					instance = new SSOCryptoApi();
				}
			}
		}

		return instance;
	}

	public void setInitCryptoAuditInfo()
	{
		CryptoApiFactory.setInitCryptoAuditInfo();
	}

	private void loadCert() throws CryptoApiException
	{
		try {
			this.encCert = CredentialRepository.getCredential(SSOConfig.getInstance().getServerName(), MStatus.ENC_CERT);
			this.signCert = CredentialRepository.getCredential(SSOConfig.getInstance().getServerName(), MStatus.SIGN_CERT);
		}
		catch (Exception e) {
			log.error(e.toString());
			throw new CryptoApiException(MStatus.CRYPTO_LOAD_CERT, e);
		}
	}

	public void startSsoIntegrity()
	{
		String errorFile = "";

		SSOConfig config = SSOConfig.getInstance();

		if (config.getAuthStatus() == 1) {
			//log.info("### Magic SSO Self Test failed.");
			//Util.setAuditInfo(config.getServerName(), "AD", "1", config.getServerName() + ", 시동 시 테스트, 암호모듈 오류 상태");
			return;
		}

		try {
			errorFile = checkJarIntegrity();
			if (!Util.isEmpty(errorFile))
				throw new Exception("### " + errorFile + " Integrity Failure");

			errorFile = checkFileIntegrity();
			if (!Util.isEmpty(errorFile))
				throw new Exception("### " + errorFile + " Integrity Failure");

			config.setAuthStatus(0);
			log.info("### Magic SSO Self Test ... OK");
			Util.setAuditInfo(config.getServerName(), "AD", "0", config.getServerName() + ", 시동 시 테스트");
		}
		catch (Exception e) {
			config.setAuthStatus(2);
			log.error("### Magic SSO Self Test failed.");
			log.error(e.toString());
			Util.setAuditInfo(config.getServerName(), "AD", "1", config.getServerName() + ", 시동 시 테스트, " + errorFile);
		}

		return;
	}

	public void cryptoIntegrity(String adminId, String detail)
	{
		SSOConfig config = SSOConfig.getInstance();

		try {
			if (!MagicJCryptoProvider.selfTest(true)) {
				config.setAuthStatus(1);
				log.error("### MagicJCrypto Self Test failed.");
				Util.setAuditInfo(adminId, "AC", "1", config.getServerName() + ", " + detail + ", Self Test");
				return;
			}
			else {
				String path = com.dreamsecurity.sso.sp.crypto.api.MJCryptoApi.class
						.getProtectionDomain().getCodeSource().getLocation().getPath();

				if (path.length() >= 4 && !path.substring(path.length() - 4).equalsIgnoreCase(".jar")) {
					path = SSOConfig.getInstance().getHomePath("config/" + SSOConfig.getJarVersion() + ".jar");
				}

				String hmacPath = SSOConfig.getInstance().getHomePath("config/" + SSOConfig.getJarVersion() + ".jar.hmac");

				byte[] hmacBytes = FileUtil.read(hmacPath);
				if ((hmacBytes == null) || (hmacBytes.length < 0)) {
					config.setAuthStatus(1);
					log.error("### " + hmacPath + " is not exist.");
					log.error("### MagicJCrypto Self Test failed.");
					Util.setAuditInfo(adminId, "AC", "1", config.getServerName() + ", " + detail + ", HMAC Test(1)");
					return;
				}

				String fileStr = new String(hmacBytes);
				String arrStr[] = fileStr.split("\n");
				String fileHmac = "";
				if (arrStr.length != 2) {
					config.setAuthStatus(1);
					log.error("### " + path + ".hmac invalid value.");
					log.error("### MagicJCrypto Self Test failed.");
					Util.setAuditInfo(adminId, "AC", "1", config.getServerName() + ", " + detail + ", HMAC Test(2)");
					return;
				}
				else {
					fileHmac = arrStr[0];
				}

				String cryptopath = com.dreamsecurity.kcmv.jce.provider.MagicJCryptoProvider.class
						.getProtectionDomain().getCodeSource().getLocation().getPath() + ".hmac";

				byte[] fileByte = FileUtil.read(cryptopath);
				if (fileByte == null || fileByte.length < 0) {
					config.setAuthStatus(1);
					log.error("### " + cryptopath + " is not exist.");
					log.error("### MagicJCrypto Self Test failed.");
					Util.setAuditInfo(adminId, "AC", "1", config.getServerName() + ", " + detail + ", HMAC Test(3)");
					return;
				}

				String calcHmac = hmacByDEK(fileByte);
				if (!fileHmac.equals(calcHmac)) {
					config.setAuthStatus(1);
					log.error("### " + cryptopath + " integrity failed.");
					log.error("### MagicJCrypto Self Test failed.");
					Util.setAuditInfo(adminId, "AC", "1", config.getServerName() + ", " + detail + ", HMAC Test(4)");
				}
				else {
					config.setAuthStatus(0);
					log.info("### MagicJCrypto Self Test ... OK");
					Util.setAuditInfo(adminId, "AC", "0", config.getServerName() + ", " + detail);
				}
			}
		}
		catch (Exception e) {
			config.setAuthStatus(1);
			log.error(e.toString());
			log.error("### MagicJCrypto Self Test failed.");
			Util.setAuditInfo(adminId, "AC", "1", config.getServerName() + ", " + detail + ", Exception: " + e.getMessage());
		}

		return;
	}

	public void ssoIntegrity(String adminId, String detail)
	{
		String errorFile = "";

		SSOConfig config = SSOConfig.getInstance();

		if (config.getAuthStatus() == 1) {
			//log.info("### Magic SSO Self Test failed.");
			//Util.setAuditInfo(adminId, "AD", "1", config.getServerName() + ", " + detail + ", 암호모듈 오류 상태");
			return;
		}

		try {
			errorFile = checkJarIntegrity();
			if (!Util.isEmpty(errorFile))
				throw new Exception("### " + errorFile + " integrity failed.");

			errorFile = checkFileIntegrity();
			if (!Util.isEmpty(errorFile))
				throw new Exception("### " + errorFile + " integrity failed.");

			config.setAuthStatus(0);
			log.info("### Magic SSO Self Test ... OK");
			Util.setAuditInfo(adminId, "AD", "0", config.getServerName() + ", " + detail);
		}
		catch (Exception e) {
			config.setAuthStatus(2);
			log.info("### Magic SSO Self Test failed.");
			Util.setAuditInfo(adminId, "AD", "1", config.getServerName() + ", " + detail + ", " + errorFile);
			log.error(e.toString());
		}

		return;
	}

	private String checkJarIntegrity()
	{
		String path = com.dreamsecurity.sso.sp.crypto.api.MJCryptoApi.class
							.getProtectionDomain().getCodeSource().getLocation().getPath();
		if (Util.isEmpty(path)) {
			log.error("### " + SSOConfig.getJarVersion() + ".jar is not exist.");
			return SSOConfig.getJarVersion() + ".jar";
		}

		if (path.length() >= 4 && !path.substring(path.length() - 4).equalsIgnoreCase(".jar")) {
			path = SSOConfig.getInstance().getHomePath("config/" + SSOConfig.getJarVersion() + ".jar");
		}

		String hmacPath = SSOConfig.getInstance().getHomePath("config/" + SSOConfig.getJarVersion() + ".jar.hmac");

		// log.info("### modulePath     = " + path);
		// log.info("### moduleHmacPath = " + hmacPath);

		try {
			byte[] hmacBytes = FileUtil.read(hmacPath);

			if (hmacBytes.length == 0) {
				log.error("### " + hmacPath + " is empty.");
				return SSOConfig.getJarVersion() + ".jar";
			}

			String fileStr = new String(hmacBytes);
			String arrStr[] = fileStr.split("\n");
			String fileHmac = "";

			if (arrStr.length != 2) {
				log.error("### " + path + ".hmac invalid value.");
				return SSOConfig.getJarVersion() + ".jar";
			}
			else {
				fileHmac = arrStr[1];
			}

			byte[] jarBytes = FileUtil.read(path);

			if ((jarBytes == null) || (jarBytes.length < 0)) {
				log.error("### " + path + " is not exist.");
				return SSOConfig.getJarVersion() + ".jar";
			}

			byte[] calcHmacBytes = crypto.hmacByDEK(jarBytes, hmacAlgorithm);
			String calcHmac = new String(Hex.encode(calcHmacBytes));

			if (!fileHmac.equals(calcHmac)) {
				log.error("### " + path + " integrity failed.");
				return SSOConfig.getJarVersion() + ".jar";
			}

			return "";
		}
		catch (IOException e) {
			log.error("### " + path + " is not exist.");
			return SSOConfig.getJarVersion() + ".jar";
		}
		catch (CryptoApiException e) {
			log.error("### " + path + " integrity failed.");
			return SSOConfig.getJarVersion() + ".jar";
		}
	}

	private String checkFileIntegrity()
	{
		SSOConfig config = SSOConfig.getInstance();
		String inFile = config.getHomePath("config/integrity.cfg");
		String errorFile = "integrity.cfg";

		try {
			if (!config.isIntegrityVerify()) {
				return "";
			}

			byte[] hmacByte = FileUtil.read(inFile + ".hmac");
			if (hmacByte.length == 0) {
				log.error("### " + inFile + ".hmac is empty.");
				return errorFile;
			}

			String cfgHmac = (new String(hmacByte)).trim();

			byte[] cfgByte = FileUtil.read(inFile);
			if (cfgByte.length == 0) {
				log.error("### " + inFile + " is empty.");
				return errorFile;
			}

			byte[] calHmacBytes = crypto.hmacByDEK(cfgByte, hmacAlgorithm);
			String calHmac = new String(Hex.encode(calHmacBytes));

			if (!cfgHmac.equals(calHmac)) {
				log.error("### " + inFile + " integrity failed.");
				return errorFile;
			}

			BufferedReader br = new BufferedReader(new FileReader(inFile));
			String line;
			String path = "";

			while ((line = br.readLine()) != null) {
				line = line.trim();
				if (Util.isEmpty(line)) continue;
				int index1 = line.indexOf("[");
				int index2 = line.indexOf("]");
				if (index1 == 0 && index2 > 0) {
					path = line.substring(index1 + 1, index2);
				}
				else {
					String file = "";
					String fileHmac = "";
					int index = line.indexOf(";");
					if (index < 0) {
						log.error("### " + line + " hmac is not exist.");

						if (br != null)  br.close();
						return line;
					}
					else {
						file = line.substring(0, index);
						fileHmac = line.substring(index + 1);
						errorFile = file;
					}

					String fullpathfile = "";
					int idxsso = path.indexOf("/sso");
					if (idxsso == 0) {
						fullpathfile = config.getSsoHomepath() + path.substring(4) + "/" + file;
					}
					else {
						fullpathfile = config.getHomePath() + path + "/" + file;
					}

					// log.debug("### file = " + fullpathfile);

					byte[] fileByte = FileUtil.read(fullpathfile);
					if (fileByte.length == 0) {
						log.error("### " + fullpathfile + " is empty.");
						if (br != null)  br.close();
						return file;
					}

					byte[] calcHmacBytes = crypto.hmacByDEK(fileByte, hmacAlgorithm);
					String calcHmac = new String(Hex.encode(calcHmacBytes));

					if (!fileHmac.equals(calcHmac)) {
						log.error("### " + fullpathfile + " integrity failed.");
						if (br != null)  br.close();
						return file;
					}
				}
	        }

			if (br != null)  br.close();
			return "";
		}
		catch (IOException e) {
			log.error("### " + errorFile + " is not exist.");
			return errorFile;
		}
		catch (CryptoApiException e) {
			log.error("### " + errorFile + " integrity failed.");
			return errorFile;
		}
	}

	public void startSsoProcess()
	{
		SSOConfig config = SSOConfig.getInstance();

		if (config.getAuthStatus() == 1) {
			//log.info("### Magic SSO Process ... Failed");
			//Util.setAuditInfo(config.getServerName(), "BB", "1", config.getServerName() + ", 시동 시 테스트, 암호모듈 오류 상태");
			return;
		}

		if (config.getAuthStatus() == 2) {
			//log.info("### Magic SSO Process ... Failed");
			//Util.setAuditInfo(config.getServerName(), "BB", "1", config.getServerName() + ", 시동 시 테스트, SSO모듈 오류 상태");
			return;
		}

		config.setAuthStatus(0);
		log.info("### Magic SSO Process ... OK");
		Util.setAuditInfo(config.getServerName(), "BB", "0", config.getServerName() + ", 시동 시 테스트");
		return;

		/***
		try {
			String OS = System.getProperty("os.name").toLowerCase();

			if (OS.indexOf("win") >= 0) {
				config.setAuthStatus(0);
				log.info("### Magic SSO Process ... OK");
				Util.setAuditInfo(config.getServerName(), "BB", "0", config.getServerName() + ", 시동 시 테스트");
				return;
			}
			else {
				String readline;

				Process ps = new ProcessBuilder("/bin/sh", "-c", "ps -ef | grep java | grep dreamsso.conf | grep -v grep").start();
				BufferedReader stdOut = new BufferedReader(new InputStreamReader(ps.getInputStream()));

				while ((readline = stdOut.readLine()) != null) {
					int idx = readline.indexOf("dreamsso.conf=");
					if (idx >= 0) {
						String encData = readline.substring(idx + "dreamsso.conf=".length(), idx + "dreamsso.conf=".length() + 44);

						if (isProcessCode(encData)) {
							config.setAuthStatus(0);
							log.info("### Magic SSO Process ... OK");
							Util.setAuditInfo(config.getServerName(), "BB", "0", config.getServerName() + ", 시동 시 테스트");
							return;
						}
					}
				}

				config.setAuthStatus(3);
				log.info("### Magic SSO Process ... Failed");
				Util.setAuditInfo(config.getServerName(), "BB", "1", config.getServerName() + ", 시동 시 테스트, Tomcat process not found");
			}
		}
		catch (IOException e) {
			config.setAuthStatus(3);
			e.printStackTrace();
			log.info("### Magic SSO Process ... Failed");
			Util.setAuditInfo(config.getServerName(), "BB", "1", config.getServerName() + ", 시동 시 테스트, Exception: " + e.getMessage());
		}

		return;
		***/
	}

	public void ssoProcess(String adminId, String detail)
	{
		SSOConfig config = SSOConfig.getInstance();

		if (config.getAuthStatus() == 1) {
			//log.info("### Magic SSO Process ... Failed");
			//Util.setAuditInfo(adminId, "BB", "1", config.getServerName() + ", " + detail + ", 암호모듈 오류 상태");
			return;
		}

		if (config.getAuthStatus() == 2) {
			//log.info("### Magic SSO Process ... Failed");
			//Util.setAuditInfo(adminId, "BB", "1", config.getServerName() + ", " + detail + ", SSO모듈 오류 상태");
			return;
		}

		config.setAuthStatus(0);
		log.info("### Magic SSO Process ... OK");
		Util.setAuditInfo(adminId, "BB", "0", config.getServerName() + ", " + detail);
		return;

		/***
		try {
			String OS = System.getProperty("os.name").toLowerCase();

			if (OS.indexOf("win") >= 0) {
				config.setAuthStatus(0);
				log.info("### Magic SSO Process ... OK");
				Util.setAuditInfo(adminId, "BB", "0", config.getServerName() + ", " + detail);
				return;
			}
			else {
				String readline;

				Process ps = new ProcessBuilder("/bin/sh", "-c", "ps -ef | grep java | grep dreamsso.conf | grep -v grep").start();
				BufferedReader stdOut = new BufferedReader(new InputStreamReader(ps.getInputStream()));

				while ((readline = stdOut.readLine()) != null) {
					int idx = readline.indexOf("dreamsso.conf=");
					if (idx >= 0) {
						String encData = readline.substring(idx + "dreamsso.conf=".length(), idx + "dreamsso.conf=".length() + 44);

						if (isProcessCode(encData)) {
							config.setAuthStatus(0);
							log.info("### Magic SSO Process ... OK");
							Util.setAuditInfo(adminId, "BB", "0", config.getServerName() + ", " + detail);
							return;
						}
					}
				}

				config.setAuthStatus(3);
				log.info("### Magic SSO Process ... Failed");
				Util.setAuditInfo(adminId, "BB", "1", config.getServerName() + ", " + detail + ", Tomcat process not found");
			}
		}
		catch (IOException e) {
			config.setAuthStatus(3);
			e.printStackTrace();
			log.info("### Magic SSO Process ... Failed");
			Util.setAuditInfo(adminId, "BB", "1", config.getServerName() + ", " + detail + ", Exception: " + e.getMessage());
		}

		return;
		***/
	}

	private boolean isProcessCode(String cipher)
	{
		//System.out.println("### Process code = [" + cipher + "]");
		if (Util.isEmpty(cipher)) {
			return false;
		}

		try {
			String OS = System.getProperty("os.name").toLowerCase();

			if (OS.indexOf("win") >= 0) {
				return true;
			}
			else {
				StringBuffer sb = new StringBuffer();
				sb.append("echo '").append(cipher).append("' | openssl enc -aes-256-cbc -a -pass pass:'Dre@mM@gicSS0' -d");

				Process ps = new ProcessBuilder("/bin/sh", "-c", sb.toString()).start();

				BufferedReader stdOut = new BufferedReader(new InputStreamReader(ps.getInputStream()));
				String readline = stdOut.readLine();
				//System.out.println("### Process pwd = [" + readline + "]");

				if (readline.equals("ProcessNormal")) {
					return true;
				}
			}
		}
		catch (final Exception e) {
			e.printStackTrace();
		}

		return false;
	}

	public byte[] createRandomByte(int size) throws CryptoApiException
	{
		return crypto.getRandom(size, randomAlgorithm);
	}

	public String createRandom(int size) throws CryptoApiException
	{
		byte[] rand = crypto.getRandom(size, randomAlgorithm);
		return new String(Hex.encode(rand));
	}

	public SSOSecretKey generateSecretKey() throws Exception
	{
		return crypto.generateSecretKey(cryptoAlgorithm, randomAlgorithm);
	}

	public String encryptPublicKey(Credential credential, byte[] input) throws CryptoApiException
	{
		try {
			byte[] certBytes = ((BasicX509Credential) credential).getEntityCertificate().getEncoded();
			byte[] inputBytes = this.makeHashedPlainData(input);

			String result = Base64.encode(crypto.encryptPublicKey(certBytes, inputBytes, rsaAlgorithm));
			return result;
		}
		catch (CertificateEncodingException e) {
			log.error("### " + e.toString());
			throw new CryptoApiException(MStatus.CRYPTO_ENCRYPT_PUBLICKEY, e.toString());
		}
	}

	public byte[] decryptPrivateKey(String input) throws CryptoApiException
	{
		byte[] certBytes = null;
		byte[] decBytes = null;
		byte[] result = null;

		try {
			certBytes = getPrivateKey(MStatus.ENC_CERT);
			byte[] encBytes = decode64(input);
			decBytes = crypto.decryptPrivateKey(certBytes, encBytes, rsaAlgorithm);
			result = extractHash(decBytes);

			Util.zeroize(certBytes);
			Util.zeroize(decBytes);

			return result;
		}
		catch (CryptoApiException e) {
			Util.zeroize(certBytes);
			Util.zeroize(decBytes);

			log.error("### SAMLCryptoApi.decryptPrivateKey() CryptoApiException");
			throw new CryptoApiException(e.getCode(), e.getMessage());
		}
	}

	public String encrypt(SSOSecretKey secKey, String input) throws CryptoApiException
	{
		String result = "";

		try {
			byte[] inputBytes = makeHashedPlainData(input.getBytes("UTF-8"));
			byte[] encTextBytes = crypto.encrypt(secKey.getKey().clone(), secKey.getIv().clone(), inputBytes, cryptoAlgorithm, cipherAlgorithm);

			result = Base64.encode(encTextBytes);
		}
		catch (Exception e) {
			log.error("### Encrypt Failure", e);
			throw new CryptoApiException(MStatus.CRYPTO_ENCRYPT, e);
		}

		return result;
	}

	public byte[] decrypt(SSOSecretKey secKey, String input) throws CryptoApiException
	{
		byte[] result = null;
		byte[] decBytes = null;

		try {
			byte[] encBytes = decode64(input);
			decBytes = crypto.decrypt(secKey.getKey().clone(), secKey.getIv().clone(), encBytes, cryptoAlgorithm, cipherAlgorithm);
			result = extractHash(decBytes);

			Util.zeroize(decBytes);
			return result;
		}
		catch (Exception e) {
			Util.zeroize(decBytes);

			log.error("### Encrypt Failure", e);
			throw new CryptoApiException(MStatus.CRYPTO_DECRYPT, e);
		}
	}

	public String hash(String input) throws CryptoApiException
	{
		byte[] hashBytes = crypto.digest(input.getBytes(), hashAlgorithm);
		return Base64.encode(hashBytes);
	}

	public byte[] hash(byte[] input, String algorithm) throws CryptoApiException
	{
		return crypto.digest(input, algorithm);
	}

	public String hmacByDEK(byte[] input) throws CryptoApiException
	{
		byte[] hmacBytes = crypto.hmacByDEK(input, hmacAlgorithm);
		String result = new String(Hex.encode(hmacBytes));

		return result;
	}

	public byte[] makeHashedPlainData(byte[] input) throws CryptoApiException
	{
		byte[] hashBytes = crypto.digest(input, hashAlgorithm);
		return Util.concatBytes(hashBytes, input);
	}

	public byte[] extractHash(byte[] input) throws CryptoApiException
	{
		int hashLen = 32;

		if (input.length <= hashLen)
			throw new CryptoApiException(MStatus.CRYPTO_PARAM_SIZE, "Invalid encrypted data");

		byte[] hashBytes = new byte[hashLen];
		byte[] textBytes = new byte[input.length - hashLen];
		Util.splitBytes(input, hashBytes, textBytes);

		byte[] calcHashBytes = crypto.digest(textBytes, hashAlgorithm);

		if (!Util.compareBytes(hashBytes, calcHashBytes))
			throw new CryptoApiException(MStatus.CRYPTO_HASH_DATA, "Different hashed data");

		return textBytes;
	}

	private byte[] getPrivateKey(int type) throws CryptoApiException
	{
		try {
			SSOConfig config = SSOConfig.getInstance();

			String path = (type == MStatus.ENC_CERT ?
					config.getHomePath(config.getCertKeypath()) : config.getHomePath(config.getCertSignpath()));
			String code = (type == MStatus.ENC_CERT ? config.getCertKeycode() : config.getCertSigncode());

			byte[] privateBytes = loadPrivateKey(path, code);

			Util.zeroize(code);

			return privateBytes;
		}
		catch (Exception e) {
			log.error(e.toString());
			throw new CryptoApiException(MStatus.ERR_GET_PRIVATEKEY, e);
		}
	}

	private byte[] loadPrivateKey(String path, String pwd) throws CryptoApiException
	{
		/***
		<rfc5208 - PKCS#8>: Encrypted Private-Key Information Syntax
		EncryptedPrivateKeyInfo ::= SEQUENCE {
			encryptionAlgorithm  EncryptionAlgorithmIdentifier,
			encryptedData        EncryptedData }
			********************************************************
			EncryptionAlgorithmIdentifier ::= AlgorithmIdentifier
			EncryptedData ::= OCTET STRING
			********************************************************
			AlgorithmIdentifier  ::=  SEQUENCE  {
				algorithm	OBJECT IDENTIFIER,
				parameters	ANY DEFINED BY algorithm OPTIONAL  }
							-- contains a value of the type
							-- registered for use with the
							-- algorithm object identifier value
		***/

		try {
			byte[][] binNode = ASN1Util.getSequence(FileUtil.read(path));

			/*
			 * encryptionAlgorithm EncryptionAlgorithmIdentifier
			 */
			byte[][] algorithmIndenfier = ASN1Util.getSequence(binNode[0]);

			/*
			 * algorithm OBJECT IDENTIFIER ( 알고리즘 방식 비교 )
			 */
			byte[] objectIdenfier = algorithmIndenfier[0];

			/*
			 * encryptedData EncryptedData
			 */
			byte[] encryptedData = ASN1Util.getOctetString(binNode[1]);

			/*
			 * parameters ANY DEFINED BY algorithm OPTIONAL
			 */
			byte[][] parameters = ASN1Util.getSequence(algorithmIndenfier[1]);
			byte[] salt = null;
			int iterationC = 0;

			byte[] derivedKey = null;
			byte[] key = null;
			byte[] iv = null;

			SecretKeySpec sKeySpec = null;
			IvParameterSpec ivParamSepc = null;
			String szAlgorithm = null;
			byte[] result = null;

			// objectIndenfier is PBES2
			if (Arrays.equals(objectIdenfier, PKCS5ObjectIdentifiers.id_PBES2.getEncoded())) {

				byte[][] paramDerivedKey = ASN1Util.getSequence(parameters[0]);
				byte[] paramIdentifier = paramDerivedKey[0];

				if (!Arrays.equals(paramIdentifier, PKCS5ObjectIdentifiers.id_PBKDF2.getEncoded())) {
					throw new NoSuchAlgorithmException("This key object identifier is not PBKDF2");
				}

				/*
				 * Get Salt(S) and Iteration count(C)
				 */
				byte[][] paramParameters = ASN1Util.getSequence(paramDerivedKey[1]);
				salt = ASN1Util.getOctetString(paramParameters[0]);
				iterationC = ASN1Util.getInteger(paramParameters[1]).intValue();

				/*
				 * Get Encryption Algorithm and IV
				 */
				byte[][] paramEncryptInfo = ASN1Util.getSequence(parameters[1]);
				paramIdentifier = paramEncryptInfo[0];
				iv = ASN1Util.getOctetString(paramEncryptInfo[1]);

				if (iv != null) {
					ivParamSepc = new IvParameterSpec(iv);
				}

				// Encryption Algorithm SEED/CBC
				if (Arrays.equals(paramIdentifier, AlgorithmObjectIdentifiers.seedCBC.getEncoded())) {
					/*
					 * Get DK
					 */
					derivedKey = pbkdf2(pwd.getBytes(), salt, iterationC, 16);

					/*
					 * Get Encryption key
					 */
					key = derivedKey;

					szAlgorithm = "SEED/CBC/PKCS5Padding";
					sKeySpec = new SecretKeySpec(key, "SEED");

				}
			}

			if (szAlgorithm == null || sKeySpec == null)
				return null;

			Cipher cipher = Cipher.getInstance(szAlgorithm, this.providerName);
			cipher.init(Cipher.DECRYPT_MODE, sKeySpec, ivParamSepc);
			result = cipher.doFinal(encryptedData);

			return result;
		}
		catch (Exception e) {
			log.error(e.toString());
			throw new CryptoApiException(MStatus.ERR_LOAD_PRIVATEKEY, e);
		}
	}

	private byte[] pbkdf2(byte[] pwd, byte[] salt, int count, int len) throws NoSuchAlgorithmException, NoSuchProviderException,
			InvalidKeyException
	{
		byte[] dk = new byte[len];
		int totalLen = len, hLen = 32, offset = 0, loop = (len + hLen - 1) / hLen;
		byte[] macData = new byte[salt.length + 4];
		int i, j, k;

		System.arraycopy(salt, 0, macData, 0, salt.length);

		String algo = "HMAC-SHA256";
		SecretKeySpec ks = new SecretKeySpec(pwd, algo);
		Mac mac = Mac.getInstance(algo, this.providerName);

		byte[] u = null, t = new byte[hLen];

		for (k = 0; k < loop; k++) {
			for (i = 0; i < count; i++) {
				if (i == 0) {
					/* salt || Int(i) */
					macData[salt.length] = (byte) (((k + 1) >>> 24) & 0xff);
					macData[salt.length + 1] = (byte) (((k + 1) >>> 16) & 0xff);
					macData[salt.length + 2] = (byte) (((k + 1) >>> 8) & 0xff);
					macData[salt.length + 3] = (byte) (((k + 1)) & 0xff);

					/* PRF(p, salt||Int(i)) */
					mac.init(ks);
					u = mac.doFinal(macData);
				} else {
					/* PRF(p, Uc) */
					mac.init(ks);
					u = mac.doFinal(u);
				}

				/* Tl = U1 xor U2 xor ... xor Uc */
				for (j = 0; j < u.length; j++)
					t[j] ^= u[j];
			}
			if (totalLen > t.length) {
				System.arraycopy(t, 0, dk, offset, t.length);
				offset += t.length;
				totalLen -= t.length;
			} else {
				for (j = 0; j < totalLen; j++)
					dk[offset + j] = t[j];
			}
		}

		return dk;
	}

	public String encryptHttpParam(String target, JSONObject jData) throws CryptoApiException
	{
		String result = "";

		try {
			String idpName = MetadataRepository.getInstance().getIDPName();
			Credential idpCert = CredentialRepository.getCredential(idpName, MStatus.ENC_CERT);

			SSOSecretKey secKey = crypto.generateSecretKey(cryptoAlgorithm, randomAlgorithm);

			String id = SAMLUtil.createSamlId();
			DateTime issueTime = new DateTime(DateTimeZone.UTC);
			String strTime = issueTime.toString("yyyy-MM-dd'T'HH:mm:ss.SSS");

			jData.put("id", id);
			jData.put("it", strTime);

			String encData = encrypt(secKey, jData.toString());
			String encKey = encryptPublicKey(idpCert, secKey.getKeyIv());

			result = SAMLUtil.makeNLAuthnRequest(target, id, issueTime, encData, encKey);

			secKey.finalize();
		}
		catch (Exception e) {
			log.error("### EncryptHttpParam Failure", e);
			throw new CryptoApiException(MStatus.CRYPTO_ENCRYPT_PARAM, e);
		}

		return result;
	}

	public JSONObject decryptHttpParam(String ciphertext) throws CryptoApiException
	{
		JSONObject jsonData = null;

		if (Util.isEmpty(ciphertext))
			return null;

		try {
			byte[] cipherBytes = Base64.decode(ciphertext);

			InputStream samlMessage = new ByteArrayInputStream(cipherBytes);
			ParserPool parserPool = new BasicParserPool();
			Document messageDoc = parserPool.parse(samlMessage);
			Element messageElem = messageDoc.getDocumentElement();
			Unmarshaller unmarshaller = Configuration.getUnmarshallerFactory().getUnmarshaller(messageElem);

			if (unmarshaller == null) {
				throw new Exception("SAML Message Decode Failure");
			}

			AuthnRequest authnRequest = (AuthnRequest) unmarshaller.unmarshall(messageElem);
			Subject subject = authnRequest.getSubject();

			NameID nameID = subject.getNameID();

			SubjectConfirmationData subjectData = ((SubjectConfirmation) subject.getSubjectConfirmations().get(0)).getSubjectConfirmationData();
			SAMLUtil.checkAndMarshall(subjectData);
			KeyInfo keyInfo = (KeyInfo) subjectData.getUnknownXMLObjects().get(0);

			KeyValue keyValue_0 = (KeyValue) keyInfo.getKeyValues().get(0);
			XSString xsString_0 = (XSString) keyValue_0.getUnknownXMLObject();
			String encData = xsString_0.getValue();

			KeyValue keyValue_1 = (KeyValue) keyInfo.getKeyValues().get(1);
			XSString xsString_1 = (XSString) keyValue_1.getUnknownXMLObject();
			String encKey = xsString_1.getValue();

			byte[] decKey = decryptPrivateKey(encKey);
			SSOSecretKey secKey = new SSOSecretKey("SEED", decKey);
			byte[] byteData = decrypt(secKey, encData);
			String strData = new String(byteData, "UTF-8");

			Util.zeroize(decKey);
			secKey.finalize();

			// Verify
			JSONParser parser = new JSONParser();
			jsonData = (JSONObject) parser.parse(strData);

			String snd = (String) jsonData.get("xfr");
			String rcv = (String) jsonData.get("xto");
			String id = (String) jsonData.get("id");
			String it = (String) jsonData.get("it");

			DateTimeFormatter format = DateTimeFormat.forPattern("yyyy-MM-dd'T'HH:mm:ss.SSS").withZoneUTC();
			DateTime dt = format.parseDateTime(it);

			if (!snd.equals(nameID.getValue())) {
				throw new Exception("SAML Message Server Name Invalid");
			}

			if (!rcv.equals(SSOConfig.getInstance().getServerName())) {
				throw new Exception("SAML Message Recieve Server Name Invalid");
			}

			if (!id.equals(authnRequest.getID())) {
				throw new Exception("SAML Message ID Invalid");
			}

			if (!dt.equals(authnRequest.getIssueInstant())) {
				throw new Exception("SAML Message Issue Time Failure");
			}

			DateTime dateTime = new DateTime(DateTimeZone.UTC).minusMinutes(SSOConfig.getInstance().getRequestTimeout());
			if (dateTime.compareTo(authnRequest.getIssueInstant()) > 0) {
				throw new Exception("SAML Message Timeout");
			}

			if (!SSOCryptoApi.getInstance().verifySignature(authnRequest)) {
				throw new Exception("SAML Message Verify Signature Failure");
			}
		}
		catch (Exception e) {
			e.printStackTrace();
			log.error("### DecryptHttpParam Failure : " + e.getMessage());
			throw new CryptoApiException(MStatus.CRYPTO_DECRYPT_PARAM, e);
		}

		return jsonData;
	}

	public void generateSignedXML(SignableXMLObject xmlObject) throws CryptoApiException
	{
		try {
			Signature signature = new SignatureBuilder().buildObject();
			// signature.setSigningCredential(this.signCert);
			signature.setSignatureAlgorithm("http://www.w3.org/2007/05/xmldsig-more#sha256-rsa-MGF1");
			signature.setCanonicalizationAlgorithm(SignatureConstants.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);

			KeyInfoGenerator kiGenerator = SecurityHelper.getKeyInfoGenerator(this.signCert, null, null);
			KeyInfo keyInfo = kiGenerator.generate(this.signCert);
			signature.setKeyInfo(keyInfo);

			xmlObject.setSignature(signature);

			SAMLUtil.checkAndMarshall(xmlObject);

			Document sigDoc = signature.getDOM().getOwnerDocument();
			Node digestMethod = sigDoc.getElementsByTagName("ds:DigestMethod").item(0);
			NamedNodeMap dmAttr = digestMethod.getAttributes();
			Node dmAlgo = dmAttr.getNamedItem("Algorithm");
			dmAlgo.setTextContent(MessageDigestAlgorithm.ALGO_ID_DIGEST_SHA256);

			// Set AuthnRequest Digest Value
			String orgStr = Util.domToStr(sigDoc, false);
			orgStr = orgStr.substring(orgStr.indexOf("?>") + 2);
			String porgStr = orgStr.substring(0, orgStr.indexOf("<ds:Signature"));
			orgStr = porgStr + orgStr.substring(orgStr.indexOf("</ds:Signature>") + "</ds:Signature>".length());

			Canonicalizer canon = Canonicalizer.getInstance(SignatureConstants.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);
			byte orgBytes[] = canon.canonicalize(orgStr.getBytes("UTF-8"));

			Node digestValue = sigDoc.getElementsByTagName("ds:DigestValue").item(0);
			digestValue.setTextContent(Base64.encode(crypto.digest(orgBytes, hashAlgorithm)));

			// Set SignedInfo Signature Value
			Node siNode = sigDoc.getElementsByTagName("ds:SignedInfo").item(0);
			StringWriter sw = new StringWriter();
			Transformer serializer = TransformerFactory.newInstance().newTransformer();
			serializer.transform(new DOMSource(siNode), new StreamResult(sw));

			String siStr = sw.toString();
			siStr = siStr.substring(siStr.indexOf("?>") + 2);

			byte siBytes[] = canon.canonicalize(siStr.getBytes("UTF-8"));
			byte certBytes[] = getPrivateKey(MStatus.SIGN_CERT);

			Node signatureValue = sigDoc.getElementsByTagName("ds:SignatureValue").item(0);
			signatureValue.setTextContent(Base64.encode(crypto.signature(certBytes, siBytes, signAlgorithm)));

			Util.zeroize(certBytes);
		}
		catch (Exception e) {
			log.error(e.getMessage());
			throw new CryptoApiException(MStatus.ERR_GEN_SIGN_XML, e);
		}
	}

	public boolean verifySignature(SignableXMLObject xmlObject) throws SSOException
	{
		boolean isVerified = true;
		String serverName;

		if (xmlObject instanceof Assertion) {
			serverName = ((Assertion) xmlObject).getIssuer().getValue();
		}
		else if (xmlObject instanceof AuthnRequest) {
			serverName = ((AuthnRequest) xmlObject).getIssuer().getValue();
		}
		else {
			log.error("### Not SignableXMLObject");
			return false;
		}

		BasicX509Credential metaSignCert = (BasicX509Credential) CredentialRepository.getCredential(serverName, MStatus.SIGN_CERT);

		if (!checkSignCredential(metaSignCert, xmlObject)) {
			log.error("### Sign Credential Different");
			return false;
		}

		try {
			// original hash
			String orgStr = Util.domToStr(xmlObject.getDOM().getOwnerDocument(), false);
			orgStr = orgStr.substring(orgStr.indexOf("?>") + 2);
			String porgStr = orgStr.substring(0, orgStr.indexOf("<ds:Signature"));
			orgStr = porgStr + orgStr.substring(orgStr.indexOf("</ds:Signature>") + "</ds:Signature>".length());

			Canonicalizer canon = Canonicalizer.getInstance(SignatureConstants.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);
			byte orgBytes[] = canon.canonicalize(orgStr.getBytes("UTF-8"));

			String calcDigestValue = encode64(crypto.digest(orgBytes, hashAlgorithm));

			Signature signature = xmlObject.getSignature();
			Document sigDoc = signature.getDOM().getOwnerDocument();
			Node xmlDigestValue = sigDoc.getElementsByTagName("ds:DigestValue").item(0);

			if (xmlDigestValue == null || Util.isEmpty(xmlDigestValue.getTextContent())) {
				isVerified = false;
				log.error("### xmlObject DigestValue Empty");
			}
			else if (!xmlDigestValue.getTextContent().equals(calcDigestValue)) {
				isVerified = false;
				log.error("### Digest Value different");
				log.error("### xmlObject digest value : " + xmlDigestValue.getTextContent());
				log.error("### calculate digest value : " + calcDigestValue);
			}
			else {
				// verify sign
				Node siNode = sigDoc.getElementsByTagName("ds:SignedInfo").item(0);
				StringWriter sw = new StringWriter();
				Transformer serializer = TransformerFactory.newInstance().newTransformer();
				serializer.transform(new DOMSource(siNode), new StreamResult(sw));

				String siStr = sw.toString();
				siStr = siStr.substring(siStr.indexOf("?>") + 2);

				byte siBytes[] = canon.canonicalize(siStr.getBytes("UTF-8"));

				String signatureValue = sigDoc.getElementsByTagName("ds:SignatureValue").item(0).getTextContent();

				if (Util.isEmpty(signatureValue)) {
					isVerified = false;
					log.error("### xmlObject signatureValue Empty");
				}

				String certStr = getCertStr(metaSignCert);

				crypto.verify(decode64(certStr), decode64(signatureValue), siBytes, signAlgorithm);
			}
		}
		catch (Exception e) {
			isVerified = false;
			log.error("### verifySignature() Exception : " + e.getMessage());
			e.printStackTrace();
		}

		return isVerified;
	}

	public void verifyJWT(String signature, byte[] input, String algorithm, String signPublicKey) throws CryptoApiException
	{
		try {
			byte[] signcert = decode64(signPublicKey);
			X509Certificate signX509Cert = X509Certificate.getInstance(signcert);

			crypto.verify(signX509Cert.getEncoded(), decode64(signature), input, algorithm);
		}
		catch (Exception e) {
			log.error("### verifyJWT Exception : " + e.toString());
			throw new CryptoApiException(MStatus.CRYPTO_ENCRYPT_PARAM, e);
		}
	}

	public Assertion getDecryptAssertion(EncryptedAssertion encryptedAssertion) throws SSOException
	{
		Assertion assertion;

		EncryptedKey encryptedKey = encryptedAssertion.getEncryptedData().getKeyInfo().getEncryptedKeys().get(0);
		CipherValue encKey = encryptedKey.getCipherData().getCipherValue();
		CipherValue cipherValue = encryptedAssertion.getEncryptedData().getCipherData().getCipherValue();

		byte[] decKey = null;
		SSOSecretKey secKey = null;

		try {
			decKey = decryptPrivateKey(encKey.getValue());
			String algorithm = getCryptoAlgorithm(encryptedAssertion);
			secKey = new SSOSecretKey(algorithm, decKey);

			byte[] byteAssertion = decrypt(secKey, cipherValue.getValue());

			Util.zeroize(decKey);
			secKey.finalize();

			Util.setAuditInfo(SSOConfig.getInstance().getServerName(), "AW", "0", "전송정보 복호화 후 암호키 파기, 0 으로 덮어쓰기");

			BasicParserPool parser = new BasicParserPool();
			parser.setNamespaceAware(true);
			Document assertionDoc = parser.parse(new ByteArrayInputStream(byteAssertion));
			Unmarshaller unmarshaller = Configuration.getUnmarshallerFactory().getUnmarshaller(assertionDoc.getDocumentElement());
			assertion = (Assertion) unmarshaller.unmarshall(assertionDoc.getDocumentElement());
		}
		catch (Exception e) {
			Util.zeroize(decKey);
			secKey.finalize();

			throw new SSOException(e);
		}

		return assertion;
	}

	private String getCryptoAlgorithm(EncryptedAssertion encryptedAssertion) throws SSOException
	{
		String algorithm = encryptedAssertion.getEncryptedData().getEncryptionMethod().getAlgorithm();

		if (!algorithm.equals(cryptoAlgorithm)) {
			throw new SSOException("Invalid Decrypt Algorithm");
		}

		return algorithm;
	}

	protected boolean checkSignCredential(BasicX509Credential credential, SignableXMLObject xmlObject)
	{
		String metaCert = getCertStr(credential);
		String xmlCert = xmlObject.getSignature().getKeyInfo().getX509Datas().get(0).getX509Certificates().get(0).getValue();

		if (!metaCert.equals(xmlCert)) {
			StringBuffer modifyStr = new StringBuffer();
			String[] arrStr = xmlCert.toString().split("\n");

			for (int i = 0; i < arrStr.length; i++) {
				modifyStr.append(arrStr[i]);
			}

			if (!(metaCert).equals(modifyStr.toString())) {
				return false;
			}
		}

		return true;
	}

	public static String getCertStr(Credential credential)
	{
		try {
			return encode64(((BasicX509Credential) credential).getEntityCertificate().getEncoded());
		}
		catch (Exception e) {
			log.error("### getCertStr() Exception");
			e.printStackTrace();
			return null;
		}
	}

	public String encryptJsonObject(JSONObject jData) throws CryptoApiException
	{
		String result = "";

		try {
			SSOConfig config = SSOConfig.getInstance();

			DateTime issueTime = new DateTime(DateTimeZone.UTC);
			String strTime = issueTime.toString("yyyy-MM-dd'T'HH:mm:ss.SSS");

			String idpName = MetadataRepository.getInstance().getIDPName();

			jData.put("xtm", strTime);
			jData.put("xfr", config.getServerName());
			jData.put("xto", idpName);

			Credential idpCredential = CredentialRepository.getCredential(idpName, MStatus.ENC_CERT);
			byte[] idpcertkey = ((BasicX509Credential) idpCredential).getEntityCertificate().getEncoded();
			byte[] signkey = ((BasicX509Credential) this.signCert).getEntityCertificate().getEncoded();
			byte[] privatekey = getPrivateKey(MStatus.SIGN_CERT);

			byte[] byteData = crypto.generateSignedEnvelopedData(idpcertkey, signkey, privatekey, jData.toString().getBytes("UTF-8"));

			String encData = encode64(byteData);
			Util.zeroize(privatekey);

			JSONObject jEData = new JSONObject();
			jEData.put("xtp", "jsn");
			jEData.put("xid", (String) jData.get("xid"));
			jEData.put("xtm", strTime);
			jEData.put("xfr", config.getServerName());
			jEData.put("xto", idpName);
			jEData.put("xed", encData);

			result = encode64(jEData.toString().getBytes("UTF-8"));
		}
		catch (Exception e) {
			log.error("### encryptJsonObject Failure : " + e.toString());
			throw new CryptoApiException(MStatus.CRYPTO_ENCRYPT_PARAM, e);
		}

		return result;
	}

	public JSONObject decryptJsonObject(String ciphertext) throws CryptoApiException
	{
		try {
			String jsonStr = new String(decode64(ciphertext), "UTF-8");

			JSONParser parser = new JSONParser();
			JSONObject jsonEncData = (JSONObject) parser.parse(jsonStr);

			String xid = (String) jsonEncData.get("xid");
			String xtm = (String) jsonEncData.get("xtm");
			String idpName = (String) jsonEncData.get("xfr");
			String spName = (String) jsonEncData.get("xto");
			String xed = (String) jsonEncData.get("xed");

			// Verify
			if (!spName.equals(SSOConfig.getInstance().getServerName())) {
				throw new Exception("Transfer Agent Name Invalid");
			}

			if (!idpName.equals(MetadataRepository.getInstance().getIDPName())) {
				throw new Exception("Transfer Server Name Invalid");
			}

			DateTimeFormatter format = DateTimeFormat.forPattern("yyyy-MM-dd'T'HH:mm:ss.SSS").withZone(DateTimeZone.UTC);
			DateTime dt = format.parseDateTime(xtm);

			DateTime dateTime = new DateTime(DateTimeZone.UTC).minusMinutes(SSOConfig.getInstance().getRequestTimeout());
			if (dateTime.compareTo(dt) > 0) {
				throw new Exception("Transfer Data Timeout");
			}

			byte[] enckey = ((BasicX509Credential) this.encCert).getEntityCertificate().getEncoded();
			byte[] privatekey = getPrivateKey(MStatus.ENC_CERT);

			byte[] byteData = crypto.processSignedEnvelopedData(enckey, privatekey, decode64(xed));

			String decData = new String(byteData, "UTF-8");
			Util.zeroize(privatekey);

			JSONObject jsonData = (JSONObject) parser.parse(decData);

			String did = (String) jsonData.get("xid");
			String dtm = (String) jsonData.get("xtm");
			String dfr = (String) jsonData.get("xfr");
			String dto = (String) jsonData.get("xto");

			// Verify
			if (!xid.equals(did)) {
				throw new Exception("Transfer Data ID Mismatch");
			}

			if (!xtm.equals(dtm)) {
				throw new Exception("Transfer Data Issue Time Mismatch");
			}

			if (!spName.equals(dto)) {
				throw new Exception("Transfer Agent Name Mismatch");
			}

			if (!idpName.equals(dfr)) {
				throw new Exception("Transfer Server Name Mismatch");
			}

			return jsonData;
		}
		catch (ParseException e) {
			e.printStackTrace();
			log.error("### Data Parse Failure - " + e.getMessage());
			throw new CryptoApiException(MStatus.ERR_DATA_PARSE, e);
		}
		catch (CryptoApiException e) {
			e.printStackTrace();
			log.error("### Transfer Data Decrypt Failure - " + e.getMessage());
			throw new CryptoApiException(MStatus.CRYPTO_DECRYPT, e);
		}
		catch (Exception e) {
			e.printStackTrace();
			log.error("### Transfer Data Verify Failure - " + e.getMessage());
			throw new CryptoApiException(MStatus.ERR_DATA_VERIFY, e);
		}
	}

	public String decryptJS(String key, String input)
	{
		byte[] hashBytes = null;
		byte[] decBytes = null;
		SSOSecretKey secKey = null;

		try {
			hashBytes = crypto.digest(key.getBytes(), hashAlgorithm);
			secKey = new SSOSecretKey(cryptoAlgorithm, hashBytes);

			decBytes = crypto.decrypt(secKey.getKey().clone(), secKey.getIv().clone(), Hex.decode(input), cryptoAlgorithm, cipherAlgorithm);
			String strText = new String(decBytes);

			Util.zeroize(hashBytes);
			Util.zeroize(decBytes);
			secKey.finalize();

			return strText;
		}
		catch (Exception e) {
			Util.zeroize(hashBytes);
			Util.zeroize(decBytes);
			secKey.finalize();

			e.printStackTrace();
			return null;
		}
	}

	public static String encode64(byte[] source)
	{
		return Base64.encode(source);
	}

	public static byte[] decode64(String encodedtext) throws CryptoApiException
	{
		try {
			return Base64.decode(encodedtext);
		}
		catch (Exception e) {
			log.error("### decode64() Exception");
			e.printStackTrace();
			throw new CryptoApiException("Decoding 할 수 없는 문자열");
		}
	}

	public byte[] encryptSym(byte[] source) throws CryptoApiException
	{
		byte[] rand = crypto.getRandom(2, randomAlgorithm);
		int nRand = new Integer(rand[0]).intValue();
		nRand = (nRand < 0 ? nRand * -1 : nRand) % 100 + 1;

		CipherParameter param = new CipherParameter();
		param.create(nRand, hashAlgorithm);

		byte[] randomBytes = new byte[4];
		ByteUtil.intToBytes(randomBytes, 0, nRand);

		byte[] cipherBytes = crypto.encrypt(param.getKey(), param.getIv(), makeHashedPlainData(source), cryptoAlgorithm, cipherAlgorithm);

		byte[] buffer = new byte[randomBytes.length + cipherBytes.length];

		System.arraycopy(randomBytes, 0, buffer, 0, randomBytes.length);
		System.arraycopy(cipherBytes, 0, buffer, randomBytes.length, cipherBytes.length);

		param.finalize();

		return buffer;
	}

	public byte[] decryptSym(String ciphertext) throws CryptoApiException
	{
		byte[] tmp = decode64(ciphertext);

		byte[] randomBytes = new byte[4];
		byte[] cipherBytes = new byte[tmp.length - 4];
		System.arraycopy(tmp, 0, randomBytes, 0, randomBytes.length);
		System.arraycopy(tmp, randomBytes.length, cipherBytes, 0, cipherBytes.length);

		int random = ByteUtil.bytesToInt(randomBytes, 0);

		CipherParameter param = new CipherParameter();
		param.create(random, hashAlgorithm);

		byte[] plainBytes = crypto.decrypt(param.getKey(), param.getIv(), cipherBytes, cryptoAlgorithm, cipherAlgorithm);
		byte[] result = extractHash(plainBytes);

		param.finalize();

		return result;
	}

	public byte[] encryptSym(byte[] source, String algorithm) throws CryptoApiException
	{
		byte[] rand = crypto.getRandom(2, randomAlgorithm);
		int nRand = new Integer(rand[0]).intValue();
		nRand = (nRand < 0 ? nRand * -1 : nRand) % 100 + 1;

		CipherParameter param = new CipherParameter();
		param.create(nRand, algorithm);

		byte[] randomBytes = new byte[4];
		ByteUtil.intToBytes(randomBytes, 0, nRand);

		byte[] cipherBytes = crypto.encrypt(param.getKey(), param.getIv(), makeHashedPlainData(source), cryptoAlgorithm, cipherAlgorithm);

		byte[] buffer = new byte[randomBytes.length + cipherBytes.length];

		System.arraycopy(randomBytes, 0, buffer, 0, randomBytes.length);
		System.arraycopy(cipherBytes, 0, buffer, randomBytes.length, cipherBytes.length);

		param.finalize();

		return buffer;
	}

	public byte[] decryptSym(String ciphertext, String algorithm) throws CryptoApiException
	{
		byte[] tmp = decode64(ciphertext);

		byte[] randomBytes = new byte[4];
		byte[] cipherBytes = new byte[tmp.length - 4];
		System.arraycopy(tmp, 0, randomBytes, 0, randomBytes.length);
		System.arraycopy(tmp, randomBytes.length, cipherBytes, 0, cipherBytes.length);

		int random = ByteUtil.bytesToInt(randomBytes, 0);

		CipherParameter param = new CipherParameter();
		param.create(random, algorithm);

		byte[] plainBytes = crypto.decrypt(param.getKey(), param.getIv(), cipherBytes, cryptoAlgorithm, cipherAlgorithm);
		byte[] result = extractHash(plainBytes);

		param.finalize();

		return result;
	}

	private class CipherParameter
	{
		private final byte[] MPS_SYMMETRICAL_KEY = {
				83, 48, 108, 78, 86,  69, 77, 118, 81,  85, 120,  77, 86, 48, 108, 97,
				76, 48,  74, 66, 82,  86, 78,  74, 77, 122,  77, 118, 81, 86,  78, 78,
				83, 48, 108, 79, 82, 121, 57,  71, 84,  70, 108,  73, 84, 48,  53, 72,
				76, 48, 104, 66, 84, 108, 78,  73, 81, 107,  86,  73, 81, 86,  66, 81,
				87, 81,  61, 61};

		public int keySize = 16;
		public int blockSize = 16;

		private byte[] key = null;
		private byte[] iv = null;

		public CipherParameter()
		{
		}

		public void setKeySize(int val)
		{
			keySize = val;
		}

		public void setBlockSize(int val)
		{
			blockSize = val;
		}

		public void create(int random, String algorithm) throws CryptoApiException
		{
			byte[] rlt = new byte[keySize + blockSize];
			byte[] tmp = MPS_SYMMETRICAL_KEY;

			for (int i = 0; i < random; i++) {
				tmp = crypto.digest(tmp, algorithm);
			}

			if (tmp.length < keySize + blockSize) {
				System.arraycopy(tmp, 0, rlt, 0, tmp.length);
				System.arraycopy(tmp, 0, rlt, tmp.length, keySize + blockSize - tmp.length);
			}
			else {
				System.arraycopy(tmp, 0, rlt, 0, rlt.length);
			}

			key = new byte[keySize];
			iv = new byte[blockSize];

			System.arraycopy(rlt, 0, key, 0, keySize);
			System.arraycopy(rlt, keySize, iv, 0, blockSize);

			Util.zeroize(tmp);
			Util.zeroize(rlt);
		}

		public byte[] getKey()
		{
			return key;
		}

		public byte[] getIv()
		{
			return iv;
		}

		public void finalize()
		{
			Util.zeroize(key);
			Util.zeroize(iv);
		}

		public String toString()
		{
			if (key == null || iv == null) {
				return "CipherParameter [key=, iv=]";
			}

			return "CipherParameter [key=" + encode64(key) + ", iv=" + encode64(iv) + "]";
		}
	}

	public void destroy()
	{
		try {
			crypto.clearKey();
		}
		catch (Exception e) {
			e.printStackTrace();
		}
	}
}