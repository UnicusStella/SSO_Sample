package com.dreamsecurity.sso.server.crypto;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.StringWriter;
import java.net.URL;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Properties;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.naming.NamingException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;
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
import com.dreamsecurity.jcaos.cms.SignedData;
import com.dreamsecurity.jcaos.cms.SignerInfo;
import com.dreamsecurity.jcaos.ivs.IVSReqMsgGenerator;
import com.dreamsecurity.jcaos.ivs.IVSResMsg;
import com.dreamsecurity.jcaos.ocsp.BasicOCSPResponse;
import com.dreamsecurity.jcaos.ocsp.CertID;
import com.dreamsecurity.jcaos.ocsp.OCSPRequest;
import com.dreamsecurity.jcaos.ocsp.OCSPRequestGenerator;
import com.dreamsecurity.jcaos.ocsp.OCSPResponse;
import com.dreamsecurity.jcaos.ocsp.Request;
import com.dreamsecurity.jcaos.ocsp.SingleResponse;
import com.dreamsecurity.jcaos.pkcs.PKCS8PrivateKeyInfo;
import com.dreamsecurity.jcaos.protocol.IVSP;
import com.dreamsecurity.jcaos.protocol.LDAP;
import com.dreamsecurity.jcaos.protocol.OCSP;
import com.dreamsecurity.jcaos.protocol.URLParser;
import com.dreamsecurity.jcaos.util.FileUtil;
import com.dreamsecurity.jcaos.util.encoders.Hex;
import com.dreamsecurity.jcaos.x509.X509CertVerifier;
import com.dreamsecurity.jcaos.x509.X509Certificate;
import com.dreamsecurity.jcaos.x509.X509InformationAccess;
import com.dreamsecurity.kcmv.jce.provider.MagicJCryptoProvider;
import com.dreamsecurity.sso.lib.dss.s2.core.Assertion;
import com.dreamsecurity.sso.lib.dss.s2.core.AuthnRequest;
import com.dreamsecurity.sso.lib.dss.s2.core.EncryptedAssertion;
import com.dreamsecurity.sso.lib.dss.s2.core.NameID;
import com.dreamsecurity.sso.lib.dss.s2.core.Subject;
import com.dreamsecurity.sso.lib.dss.s2.core.SubjectConfirmation;
import com.dreamsecurity.sso.lib.dss.s2.core.SubjectConfirmationData;
import com.dreamsecurity.sso.lib.dss.s2.metadata.EncryptionMethod;
import com.dreamsecurity.sso.lib.dsx.Configuration;
import com.dreamsecurity.sso.lib.dsx.encryption.CipherData;
import com.dreamsecurity.sso.lib.dsx.encryption.EncryptedData;
import com.dreamsecurity.sso.lib.dsx.encryption.EncryptedKey;
import com.dreamsecurity.sso.lib.dsx.encryption.EncryptionConstants;
import com.dreamsecurity.sso.lib.dsx.io.MarshallingException;
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
import com.dreamsecurity.sso.lib.dsx.signature.Signer;
import com.dreamsecurity.sso.lib.dsx.signature.impl.SignatureBuilder;
import com.dreamsecurity.sso.lib.jsn.JSONObject;
import com.dreamsecurity.sso.lib.jsn.parser.JSONParser;
import com.dreamsecurity.sso.lib.jsn.parser.ParseException;
import com.dreamsecurity.sso.lib.jtm.DateTime;
import com.dreamsecurity.sso.lib.jtm.DateTimeZone;
import com.dreamsecurity.sso.lib.jtm.format.DateTimeFormat;
import com.dreamsecurity.sso.lib.jtm.format.DateTimeFormatter;
import com.dreamsecurity.sso.lib.slf.Logger;
import com.dreamsecurity.sso.lib.slf.LoggerFactory;
import com.dreamsecurity.sso.lib.xsc.algorithms.MessageDigestAlgorithm;
import com.dreamsecurity.sso.lib.xsc.c14n.Canonicalizer;
import com.dreamsecurity.sso.lib.xsc.utils.Base64;
import com.dreamsecurity.sso.server.common.MStatus;
import com.dreamsecurity.sso.server.config.SSOConfig;
import com.dreamsecurity.sso.server.exception.SSOException;
import com.dreamsecurity.sso.server.metadata.CredentialRepository;
import com.dreamsecurity.sso.server.metadata.MetadataRepository;
import com.dreamsecurity.sso.server.provider.CommonProvider;
import com.dreamsecurity.sso.server.session.SessionManager;
import com.dreamsecurity.sso.server.token.SSOToken;
import com.dreamsecurity.sso.server.util.ByteUtil;
import com.dreamsecurity.sso.server.util.SAMLUtil;
import com.dreamsecurity.sso.server.util.Util;

public class SSOCryptoApi
{
	private static Logger log = LoggerFactory.getLogger(SSOCryptoApi.class);

	private static SSOCryptoApi instance = null;
	private static CryptoApi crypto = null;

	private X509Certificate x509Root = null;
	private Credential encCert = null;
	private Credential signCert = null;

	private String providerName = null;

	boolean verifyCert = false;
	int[] verifyCertMethod = null;

	private String randomAlgorithm = "SHA256DRBG";
	private String cryptoAlgorithm = "SEED";
	private String cipherAlgorithm = "SEED/CBC/PKCS5Padding";
	private String rsaAlgorithm = "RSA/NONE/OAEPWithSHA256andMGF1Padding";
	private String signAlgorithm = "SHA256withRSA/PSS";
	private String hashAlgorithm = "SHA256";
	private String hmacAlgorithm = "HMAC-SHA256";
	private String keypairAlgorithm = "RSA";

	private static final byte[] CERT_KEY = {68, 114, 101, 97, 109, 115, 115, 111, 49, 48, 48, 52, 33, 64};
	private static final byte[] KEY_0 = {36};
	private static final byte[] KEY_1 = {33};
	private static final byte[] KEY_2 = {64};

	public static final int VERIFY_IVS = 1;
	public static final int VERIFY_CRL = 2;
	public static final int VERIFY_OCSP = 4;

	private SSOCryptoApi() throws CryptoApiException
	{
		crypto = CryptoApiFactory.getCryptoApi();
		providerName = crypto.getProviderName();

		loadCert();

		SSOConfig config = SSOConfig.getInstance();
		verifyCert = config.getCertVerify();

		//log.debug("### verifyCert : {}", verifyCert);

		if (verifyCert) {
			List<Object> verifyCertType = config.getCertVerifyType();
			verifyCertMethod = new int[verifyCertType.size()];

			for (int i = 0; i < verifyCertType.size(); i++) {
				String method = (String) verifyCertType.get(i);

				if (method.equalsIgnoreCase("IVS")) {
					verifyCertMethod[i] = VERIFY_IVS;
				}
				else if (method.equalsIgnoreCase("CRL")) {
					verifyCertMethod[i] = VERIFY_CRL;
				}
				else if (method.equalsIgnoreCase("OCSP")) {
					verifyCertMethod[i] = VERIFY_OCSP;
				}
			}
		}
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

			// Verify Root Cert
			//String rootcertpath = SSOConfig.getInstance().getHomePathFile("cert/ROOT.der");
			//this.x509Root = X509Certificate.getInstance(FileUtil.read(rootcertpath));
		}
		catch (Exception e) {
			log.error(e.toString());
			throw new CryptoApiException(MStatus.CRYPTO_LOAD_CERT, e);
		}
	}

	public int startSsoIntegrity()
	{
		int result = 0;
		String errorFile = "";

		SSOConfig config = SSOConfig.getInstance();

		if (config.getAuthStatus() == 1) {
			log.info("### Magic SSO Self Test failed.");
			Util.setAuditInfo(config.getServerName(), "AD", "1", config.getServerName() + ", 시동 시 테스트, 암호모듈 오류 상태");
			return -1;
		}

		try {
			errorFile = checkJarIntegrity();
			if (!Util.isEmpty(errorFile))
				throw new Exception("### " + errorFile + " Integrity Failure");

			errorFile = checkFileIntegrity();
			if (!Util.isEmpty(errorFile))
				throw new Exception("### " + errorFile + " Integrity Failure");

			result = 0;
			config.setAuthStatus(0);
			log.info("### Magic SSO Self Test ... OK");
			Util.setAuditInfo(config.getServerName(), "AD", "0", config.getServerName() + ", 시동 시 테스트");
		}
		catch (Exception e) {
			result = -1;
			config.setAuthStatus(2);
			log.error("### Magic SSO Self Test failed.");
			log.error(e.toString());
			Util.setAuditInfo(config.getServerName(), "AD", "1", config.getServerName() + ", 시동 시 테스트, " + errorFile);
		}

		return result;
	}

	public int cryptoIntegrity(String adminId, String detail)
	{
		int status = -1;
		SSOConfig config = SSOConfig.getInstance();

		try {
			if (!MagicJCryptoProvider.selfTest(true)) {
				config.setAuthStatus(1);
				log.error("### MagicJCrypto Self Test failed.");
				Util.setAuditInfo(adminId, "AC", "1", config.getServerName() + ", " + detail + ", Self Test");
				return -1;
			}
			else {
				String path = com.dreamsecurity.sso.idp.crypto.api.MJCryptoApi.class
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
					return -1;
				}

				String fileStr = new String(hmacBytes);
				String arrStr[] = fileStr.split("\n");
				String fileHmac = "";
				if (arrStr.length != 2) {
					config.setAuthStatus(1);
					log.error("### " + path + ".hmac invalid value.");
					log.error("### MagicJCrypto Self Test failed.");
					Util.setAuditInfo(adminId, "AC", "1", config.getServerName() + ", " + detail + ", HMAC Test(2)");
					return -1;
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
					return -1;
				}

				byte[] calcHmacBytes = crypto.hmacByDEK(fileByte, hmacAlgorithm);
				String calcHmac = new String(Hex.encode(calcHmacBytes));

				if (!fileHmac.equals(calcHmac)) {
					status = -1;
					config.setAuthStatus(1);
					log.error("### " + cryptopath + " integrity failed.");
					log.error("### MagicJCrypto Self Test failed.");
					Util.setAuditInfo(adminId, "AC", "1", config.getServerName() + ", " + detail + ", HMAC Test(4)");
				}
				else {
					status = 0;
					config.setAuthStatus(0);
					log.info("### MagicJCrypto Self Test ... OK");
					Util.setAuditInfo(adminId, "AC", "0", config.getServerName() + ", " + detail);
				}
			}
		}
		catch (Exception e) {
			status = -1;
			config.setAuthStatus(1);
			log.error(e.toString());
			log.error("### MagicJCrypto Self Test failed.");
			Util.setAuditInfo(adminId, "AC", "1", config.getServerName() + ", " + detail + ", Exception: " + e.getMessage());
		}

		return status;
	}

	public int ssoIntegrity(String adminId, String detail)
	{
		int result = -1;
		String errorFile = "";

		SSOConfig config = SSOConfig.getInstance();

		if (config.getAuthStatus() == 1) {
			log.info("### Magic SSO Self Test failed.");
			Util.setAuditInfo(adminId, "AD", "1", config.getServerName() + ", " + detail + ", 암호모듈 오류 상태");
			return result;
		}

		try {
			errorFile = checkJarIntegrity();
			if (!Util.isEmpty(errorFile))
				throw new Exception("### " + errorFile + " integrity failed.");

			errorFile = checkFileIntegrity();
			if (!Util.isEmpty(errorFile))
				throw new Exception("### " + errorFile + " integrity failed.");

			result = 0;
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

		return result;
	}

	private String checkJarIntegrity()
	{
		String path = com.dreamsecurity.sso.idp.crypto.api.MJCryptoApi.class
							.getProtectionDomain().getCodeSource().getLocation().getPath();

		// WAR 배포 환경에서 경로가 잘못 나오는 경우 사용
		//String path = SSOConfig.getInstance().getRootPath() + "/WEB-INF/lib/" + SSOConfig.getJarVersion() + ".jar";

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

	public int startSsoProcess()
	{
		SSOConfig config = SSOConfig.getInstance();

		if (config.getAuthStatus() == 1) {
			log.info("### Magic SSO Process ... Failed");
			Util.setAuditInfo(config.getServerName(), "BB", "1", config.getServerName() + ", 시동 시 테스트, 암호모듈 오류 상태");
			return -1;
		}

		if (config.getAuthStatus() == 2) {
			log.info("### Magic SSO Process ... Failed");
			Util.setAuditInfo(config.getServerName(), "BB", "1", config.getServerName() + ", 시동 시 테스트, SSO모듈 오류 상태");
			return -1;
		}

		config.setAuthStatus(0);
		log.info("### Magic SSO Process ... OK");
		Util.setAuditInfo(config.getServerName(), "BB", "0", config.getServerName() + ", 시동 시 테스트");
		return 0;

		/***
		try {
			String OS = System.getProperty("os.name").toLowerCase();

			if (OS.indexOf("win") >= 0) {
				config.setAuthStatus(0);
				log.info("### Magic SSO Process ... OK");
				Util.setAuditInfo(config.getServerName(), "BB", "0", config.getServerName() + ", 시동 시 테스트");
				return 0;
			}
			else {
				Process ps = new ProcessBuilder("/bin/sh", "-c", "ps -ef | grep java | grep dreamsso.conf | grep -v grep").start();
				BufferedReader stdOut = new BufferedReader(new InputStreamReader(ps.getInputStream()));

				String readline;
				while ((readline = stdOut.readLine()) != null) {
					int idx = readline.indexOf("dreamsso.conf=");
					if (idx >= 0) {
						String encData = readline.substring(idx + "dreamsso.conf=".length(), idx + "dreamsso.conf=".length() + 44);

						if (isProcessCode(encData)) {
							config.setAuthStatus(0);
							log.info("### Magic SSO Process ... OK");
							Util.setAuditInfo(config.getServerName(), "BB", "0", config.getServerName() + ", 시동 시 테스트");
							return 0;
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

		return -1;
		***/
	}

	public int ssoProcess(String adminId, String detail)
	{
		SSOConfig config = SSOConfig.getInstance();

		if (config.getAuthStatus() == 1) {
			log.info("### Magic SSO Process ... Failed");
			Util.setAuditInfo(adminId, "BB", "1", config.getServerName() + ", " + detail + ", 암호모듈 오류 상태");
			return -1;
		}

		if (config.getAuthStatus() == 2) {
			log.info("### Magic SSO Process ... Failed");
			Util.setAuditInfo(adminId, "BB", "1", config.getServerName() + ", " + detail + ", SSO모듈 오류 상태");
			return -1;
		}

		config.setAuthStatus(0);
		log.info("### Magic SSO Process ... OK");
		Util.setAuditInfo(adminId, "BB", "0", config.getServerName() + ", " + detail);
		return 0;

		/***
		try {
			String OS = System.getProperty("os.name").toLowerCase();

			if (OS.indexOf("win") >= 0) {
				config.setAuthStatus(0);
				log.info("### Magic SSO Process ... OK");
				Util.setAuditInfo(adminId, "BB", "0", config.getServerName() + ", " + detail);
				return 0;
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
							return 0;
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

		return -1;
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

	public String createRandom(int size) throws CryptoApiException
	{
		byte[] rand = crypto.getRandom(size, randomAlgorithm);
		return new String(Hex.encode(rand));
	}

	public SSOSecretKey generateSecretKey() throws Exception
	{
		return crypto.generateSecretKey(cryptoAlgorithm, randomAlgorithm);
	}

	public String encryptPublicKey(Credential credential, String input) throws Exception
	{
		byte[] certBytes = ((BasicX509Credential) credential).getEntityCertificate().getEncoded();
		byte[] inputBytes = this.makeHashedPlainData(input.getBytes());

		String result = Base64.encode(crypto.encryptPublicKey(certBytes, inputBytes, rsaAlgorithm));
		return result;
	}

	public String encryptPublicKey(Credential credential, byte[] input) throws Exception
	{
		byte[] certBytes = ((BasicX509Credential) credential).getEntityCertificate().getEncoded();
		byte[] inputBytes = this.makeHashedPlainData(input);

		String result = Base64.encode(crypto.encryptPublicKey(certBytes, inputBytes, rsaAlgorithm));
		return result;
	}

	public String encryptPublicKey(Credential credential, String input, String algorithm) throws Exception
	{
		byte[] certBytes = ((BasicX509Credential) credential).getEntityCertificate().getEncoded();

		String result = Base64.encode(crypto.encryptPublicKey(certBytes, input.getBytes(), algorithm));
		return result;
	}

	public String encryptPrivateKey(int cert, byte[] input, String algorithm) throws SSOException
	{
		byte[] certBytes = null;

		try {
			certBytes = getPrivateKey(cert);

			String result = Base64.encode(crypto.encryptPrivateKey(certBytes, input, algorithm));

			Util.zeroize(certBytes);
			return result;
		}
		catch (Exception e) {
			Util.zeroize(certBytes);

			e.printStackTrace();
			throw new SSOException("encryptPrivateKey() error");
		}
	}

	public byte[] decryptPrivateKey(String input) throws SSOException
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
		catch (Exception e) {
			Util.zeroize(certBytes);
			Util.zeroize(decBytes);

			e.printStackTrace();
			throw new SSOException("decryptPrivateKey() error");
		}
	}

	public String signature(PrivateKey privateKey, byte[] input, String algorithm) throws SSOException
	{
		try {
			return Base64.encode(crypto.signature(privateKey, input, algorithm));
		}
		catch (Exception e) {
			e.printStackTrace();
			throw new SSOException("signature() error");
		}
	}

	public void verify(PublicKey publicKey, String signature, byte[] input, String algorithm) throws SSOException
	{
		try {
			byte[] signBytes = decode64(signature);

			crypto.verify(publicKey, signBytes, input, algorithm);

			return;
		}
		catch (Exception e) {
			e.printStackTrace();
			throw new SSOException("verify() error");
		}
	}

	public String signJWT(byte[] input, String algorithm) throws CryptoApiException
	{
		try {
			byte certBytes[] = getPrivateKey(MStatus.SIGN_CERT);
			PKCS8PrivateKeyInfo cert = PKCS8PrivateKeyInfo.getInstance(certBytes);
			PrivateKey priKey = cert.getPrivateKey();

			return signature(priKey, input, algorithm);
		}
		catch (Exception e) {
			log.error("### signJWT Failure : " + e.toString());
			throw new CryptoApiException(MStatus.CRYPTO_SIGNATURE, e);
		}
	}

	public void verifyJWT(String signature, byte[] input, String algorithm) throws CryptoApiException
	{
		try {
			PublicKey publicKey = ((BasicX509Credential) this.signCert).getPublicKey();

			verify(publicKey, signature, input, algorithm);
		}
		catch (Exception e) {
			log.error("### verifyJWT Failure : " + e.toString());
			throw new CryptoApiException(MStatus.CRYPTO_VERIFY, e);
		}
	}

	public String encrypt(SSOSecretKey secKey, String input) throws SSOException
	{
		String result = "";

		try {
			byte[] inputBytes = makeHashedPlainData(input.getBytes("UTF-8"));
			byte[] encTextBytes = crypto.encrypt(secKey.getKey().clone(), secKey.getIv().clone(), inputBytes, cryptoAlgorithm, cipherAlgorithm);

			result = Base64.encode(encTextBytes);
		}
		catch (Exception e) {
			log.error("### SSOCryptoApi.encrypt() Exception: {}", e.toString());
			throw new SSOException(MStatus.CRYPTO_ENCRYPT, e);
		}

		return result;
	}

	public String encrypt(byte[] key, byte[] iv, String input, String algorithm, String cipherAlgorithm) throws SSOException
	{
		String result = "";

		try {
			byte[] encBytes = crypto.encrypt(key.clone(), iv.clone(), input.getBytes("UTF-8"), algorithm, cipherAlgorithm);

			result = Base64.encode(encBytes);
		}
		catch (Exception e) {
			log.error("### SSOCryptoApi.encrypt() Exception: {}", e.toString());
			throw new SSOException(MStatus.CRYPTO_ENCRYPT, e);
		}

		return result;
	}

	public byte[] decrypt(SSOSecretKey secKey, String input) throws SSOException
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

			log.error("### SSOCryptoApi.decrypt() Exception: {}", e.toString());
			throw new SSOException(MStatus.CRYPTO_DECRYPT, e);
		}
	}

	public byte[] decrypt(byte[] key, String input, String algorithm, String cipherAlgorithm) throws SSOException
	{
		try {
			byte[] encBytes = decode64(input);

			return crypto.decrypt(key.clone(), encBytes, algorithm, cipherAlgorithm);
		}
		catch (Exception e) {
			log.error("### SSOCryptoApi.decrypt() Exception: {}", e.toString());
			throw new SSOException(MStatus.CRYPTO_DECRYPT, e);
		}
	}

	public byte[] decrypt(byte[] key, byte[] iv, String input, String algorithm, String cipherAlgorithm) throws SSOException
	{
		try {
			byte[] encBytes = decode64(input);

			return crypto.decrypt(key.clone(), iv.clone(), encBytes, algorithm, cipherAlgorithm);
		}
		catch (Exception e) {
			log.error("### SSOCryptoApi.decrypt() Exception: {}", e.toString());
			throw new SSOException(MStatus.CRYPTO_DECRYPT, e);
		}
	}

	public byte[] hash(byte[] input, String algorithm) throws CryptoApiException
	{
		return crypto.digest(input, algorithm);
	}

	public String hash(String input) throws CryptoApiException
	{
		byte[] hashBytes = crypto.digest(input.getBytes(), hashAlgorithm);
		return Base64.encode(hashBytes);
	}

	public String hmac(byte[] input) throws CryptoApiException
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

	public void generateServerCert(String id) throws CryptoApiException
	{
		try {
			SSOConfig config = SSOConfig.getInstance();
			String certPath = config.getHomePath() + "/cert";

			X509Certificate rootCert = X509Certificate.getInstance(FileUtil.read(certPath + "/CA/ROOT.der"));

			byte[] priKeyByte = loadPrivateKey(certPath + "/CA/ROOT.key", new String(CERT_KEY));
			PKCS8PrivateKeyInfo priKeyInfo = PKCS8PrivateKeyInfo.getInstance(priKeyByte);
			PrivateKey rootPivate = priKeyInfo.getPrivateKey();

			KeyPair serverPair = crypto.genKeyPair(keypairAlgorithm, 2048, "");

			byte[] tmpKey = Util.concatBytes(KEY_0, id.getBytes());
			byte[] encKey = Util.concatBytes(tmpKey, KEY_1);
			byte[] sigKey = Util.concatBytes(tmpKey, KEY_2);

			X509Certificate serverCert = crypto.generatePublic(serverPair, rootCert, rootPivate, id + "_Sig", "S", 10);
			byte[] encPrivateKey = crypto.generatePrivate(serverPair.getPrivate(), sigKey);

			String file = certPath + "/CA/" + id;
			String ufile = certPath + "/" + id;

			FileOutputStream output_der = new FileOutputStream(new File(file + "_Sig.der"));
			output_der.write(serverCert.getEncoded());
			output_der.close();

			FileOutputStream output_uder = new FileOutputStream(new File(ufile + "_Sig.der"));
			output_uder.write(serverCert.getEncoded());
			output_uder.close();

			FileOutputStream output_key = new FileOutputStream(new File(file + "_Sig.key"));
			output_key.write(encPrivateKey);
			output_key.close();

			KeyPair serverPair2 = crypto.genKeyPair(keypairAlgorithm, 2048, "");

			X509Certificate serverCert2 = crypto.generatePublic(serverPair2, rootCert, rootPivate, id + "_Enc", "E", 10);
			byte[] encPrivateKey2 = crypto.generatePrivate(serverPair2.getPrivate(), encKey);

			FileOutputStream output_der2 = new FileOutputStream(new File(file + "_Enc.der"));
			output_der2.write(serverCert2.getEncoded());
			output_der2.close();

			FileOutputStream output_uder2 = new FileOutputStream(new File(ufile + "_Enc.der"));
			output_uder2.write(serverCert2.getEncoded());
			output_uder2.close();

			FileOutputStream output_key2 = new FileOutputStream(new File(file + "_Enc.key"));
			output_key2.write(encPrivateKey2);
			output_key2.close();
		}
		catch (Exception e) {
			log.error("### generateServerCert Exception: {}", e.toString());
			throw new CryptoApiException(MStatus.CRYPTO_GEN_CERT, e);
		}
	}

	public String encryptHttpParam(String spName, String target, JSONObject jData) throws CryptoApiException
	{
		String result = "";

		try {
			Credential spCert = CredentialRepository.getCredential(spName, MStatus.ENC_CERT);

			SSOSecretKey secKey = crypto.generateSecretKey(cryptoAlgorithm, randomAlgorithm);

			String id = SAMLUtil.createSamlId("IDP-");
			DateTime issueTime = new DateTime(DateTimeZone.UTC);
			String strTime = issueTime.toString("yyyy-MM-dd'T'HH:mm:ss.SSS");

			jData.put("id", id);
			jData.put("it", strTime);

			String encData = encrypt(secKey, jData.toString());
			String encKey = encryptPublicKey(spCert, secKey.getKeyIv());

			// 암호키 분배
			Util.setAuditInfo(Util.getDateFormat("yyyyMMdd"), Util.getDateFormat("HHmmss"),
					SSOConfig.getInstance().getServerName(), "AV", "0", spName);

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

			SSOCryptoApi cryptoApi = SSOCryptoApi.getInstance();

			byte[] decKey = cryptoApi.decryptPrivateKey(encKey);
			SSOSecretKey secKey = new SSOSecretKey("SEED", decKey);
			byte[] byteData = cryptoApi.decrypt(secKey, encData);
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
				throw new Exception("SAML Message Send Server Name Invalid");
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

			boolean dupNLAuthn = SessionManager.getInstance().addNLAuthnRequest(snd + id, dt);
			if (dupNLAuthn) {
				throw new Exception("SAML Message Duplicate");
			}

			if (!SSOCryptoApi.getInstance().verifySignature(authnRequest)) {
				throw new Exception("SAML Message Verify Signature Failure");
			}
		}
		catch (Exception e) {
			e.printStackTrace();
			log.error("### DecryptHttpParam Failure - {}", e.getMessage());
			throw new CryptoApiException(MStatus.CRYPTO_DECRYPT_PARAM, e);
		}

		return jsonData;
	}

	public String encryptJsonObject(JSONObject jData, String spName) throws CryptoApiException
	{
		String result = "";

		try {
			SSOConfig config = SSOConfig.getInstance();

			DateTime issueTime = new DateTime(DateTimeZone.UTC);
			String strTime = issueTime.toString("yyyy-MM-dd'T'HH:mm:ss.SSS");

			jData.put("xtm", strTime);
			jData.put("xfr", config.getServerName());
			jData.put("xto", spName);

			Credential spCredential = CredentialRepository.getCredential(spName, MStatus.ENC_CERT);
			byte[] spEncCert = ((BasicX509Credential) spCredential).getEntityCertificate().getEncoded();

			byte[] signCertByte = ((BasicX509Credential) this.signCert).getEntityCertificate().getEncoded();
			byte[] privatekey = getPrivateKey(MStatus.SIGN_CERT);

			byte[] byteData = crypto.generateSignedEnvelopedData(spEncCert, signCertByte, privatekey, jData.toString().getBytes("UTF-8"));

			String encData = encode64(byteData);
			Util.zeroize(privatekey);

			JSONObject jEData = new JSONObject();
			jEData.put("xid", (String) jData.get("xid"));
			jEData.put("xtm", strTime);
			jEData.put("xfr", config.getServerName());
			jEData.put("xto", spName);
			jEData.put("xed", encData);

			result = encode64(jEData.toString().getBytes("UTF-8"));
		}
		catch (Exception e) {
			log.error("### EncryptJsonObject Failure : " + e.toString());
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
			String spName = (String) jsonEncData.get("xfr");
			String idpName = (String) jsonEncData.get("xto");
			String xed = (String) jsonEncData.get("xed");

			// Verify
			if (!idpName.equals(SSOConfig.getInstance().getServerName())) {
				throw new Exception("Transfer Server Name Invalid");
			}

			DateTimeFormatter format = DateTimeFormat.forPattern("yyyy-MM-dd'T'HH:mm:ss.SSS").withZone(DateTimeZone.UTC);
			DateTime dt = format.parseDateTime(xtm);

			DateTime dateTime = new DateTime(DateTimeZone.UTC).minusMinutes(SSOConfig.getInstance().getRequestTimeout());
			if (dateTime.compareTo(dt) > 0) {
				throw new Exception("Transfer Data Timeout");
			}

			Credential encCredential = CredentialRepository.getCredential(idpName, MStatus.ENC_CERT);
			byte[] encCert = ((BasicX509Credential) encCredential).getEntityCertificate().getEncoded();

			byte[] decCert = getPrivateKey(MStatus.ENC_CERT);

			byte[] byteData = crypto.processSignedEnvelopedData(encCert, decCert, decode64(xed));

			String decData = new String(byteData, "UTF-8");
			Util.zeroize(decCert);

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

			if (!spName.equals(dfr)) {
				throw new Exception("Transfer Agent Name Mismatch");
			}

			if (!idpName.equals(dto)) {
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
			log.error("SSOCryptoApi.generateSignedXML() Exception: {}", e.getMessage());
			throw new CryptoApiException(MStatus.ERR_GEN_SIGN_XML, e);
		}
	}

	public void generateStdSignedXML(SignableXMLObject xmlObject) throws CryptoApiException
	{
		try {
			byte certBytes[] = getPrivateKey(MStatus.SIGN_CERT);
			PKCS8PrivateKeyInfo cert = PKCS8PrivateKeyInfo.getInstance(certBytes);

			BasicX509Credential signPrivate = new BasicX509Credential();
			signPrivate.setPrivateKey(cert.getPrivateKey());

			KeyInfoGenerator kiGenerator = SecurityHelper.getKeyInfoGenerator(this.signCert, null, null);
			KeyInfo keyInfo = kiGenerator.generate(this.signCert);

			Signature signature = new SignatureBuilder().buildObject("http://www.w3.org/2000/09/xmldsig#", "Signature", "dsig");
			signature.setSigningCredential(signPrivate);
			signature.setSignatureAlgorithm(SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA256);
			signature.setCanonicalizationAlgorithm(SignatureConstants.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);
			signature.setKeyInfo(keyInfo);

			xmlObject.setSignature(signature);
			SAMLUtil.checkAndMarshall(xmlObject);

			Document sigDoc = signature.getDOM().getOwnerDocument();
			Node digestMethod = sigDoc.getElementsByTagName("ds:DigestMethod").item(0);
			NamedNodeMap dmAttr = digestMethod.getAttributes();
			Node dmAlgo = dmAttr.getNamedItem("Algorithm");
			dmAlgo.setTextContent(MessageDigestAlgorithm.ALGO_ID_DIGEST_SHA256);

			Signer.signObject(signature);
			SAMLUtil.checkAndMarshall(xmlObject);
		}
		catch (Exception e) {
			log.error("SSOCryptoApi.generateStdSignedXML() Exception: {}", e.getMessage());
			e.printStackTrace();
			throw new CryptoApiException(MStatus.ERR_GEN_SIGN_XML, e);
		}
	}

	public boolean verifySignature(SignableXMLObject xmlObject)
	{
		boolean isVerified = true;
		String serverName;

		if (xmlObject instanceof AuthnRequest) {
			serverName = ((AuthnRequest) xmlObject).getIssuer().getValue();
		}
		 else if (xmlObject instanceof Assertion) {
			serverName = ((Assertion) xmlObject).getIssuer().getValue();
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

			// xmlObject hashAlgorithm read ??
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
				log.error("### xmlObject digest value : {}", xmlDigestValue.getTextContent());
				log.error("### calculate digest value : {}", calcDigestValue);
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
			log.error("### verifySignature() Exception: {}", e.getMessage());
			e.printStackTrace();
		}

		return isVerified;
	}

	public String procSignedData(String input, Map<String,Object> output) throws SSOException
	{
		try {
			SignedData signedData = crypto.processSignedData(decode64(input));

			ArrayList<?> signerInfos = signedData.getSignerInfos();
			SignerInfo signerInfo = (SignerInfo) signerInfos.get(0);

			X509Certificate userCert = signedData.getSignerCert(signerInfo.getSid());

			if (userCert == null) {
				throw new CryptoApiException(MStatus.CRYPTO_GEN_SIGNED, "Invalid SignedData: get cert failure");
			}

			// 인증서 검증
			verifyCert(userCert);

			if (output != null) {
				output.put("timestamp", signerInfo.getSigningTime());
				output.put("certificate", new String(Base64.encode(userCert.getEncoded())));
				output.put("message", new String(signedData.getContent()));
				output.put("dn", new String(userCert.getSubjectDN().getName()));
			}

			return encode64(signedData.getContent());
		}
		catch (Exception e) {
			log.error("### procSignedData() Exception: {}", e.getMessage());
			e.printStackTrace();
			throw new SSOException(e);
		}
	}

	public EncryptedAssertion getEncryptedAssertion(String userIp, String spName, Assertion assertion) throws SSOException
	{
		EncryptedAssertion encryptedAssertion = (EncryptedAssertion) SAMLUtil.buildXMLObject(EncryptedAssertion.DEFAULT_ELEMENT_NAME);

		try {
			// 암호키 생성
			SSOSecretKey secKey = crypto.generateSecretKey(cryptoAlgorithm, randomAlgorithm);

			Util.setAuditInfo(Util.getDateFormat("yyyyMMdd"), Util.getDateFormat("HHmmss"),
					SSOConfig.getInstance().getServerName(), "AM", "0", userIp + ", 전송정보 암복호화키, SEED/CBC");

			SAMLUtil.checkAndMarshall(assertion);
			String plainAsst = Util.domToStr(assertion.getDOM().getOwnerDocument(), false);
			String encAsst = encrypt(secKey, plainAsst);

			Credential spCert = CredentialRepository.getCredential(spName, MStatus.ENC_CERT);
			String encKey = encryptPublicKey(spCert, secKey.getKeyIv());

			secKey.finalize();

			Util.setAuditInfo(Util.getDateFormat("yyyyMMdd"), Util.getDateFormat("HHmmss"),
					SSOConfig.getInstance().getServerName(), "AW", "0", userIp + ", 에이전트로 암호키 분배 후 파기, 0 으로 덮어쓰기");

			EncryptedData encryptedData = (EncryptedData) SAMLUtil.buildXMLObject(EncryptedData.DEFAULT_ELEMENT_NAME);

			EncryptionMethod encMethod = (EncryptionMethod) SAMLUtil.buildXMLObject(EncryptionMethod.DEFAULT_ELEMENT_NAME);
			encMethod.setAlgorithm(cryptoAlgorithm);

			KeyInfo keyInfo = (KeyInfo) SAMLUtil.buildXMLObject(KeyInfo.DEFAULT_ELEMENT_NAME);
			EncryptedKey encryptedKey = (EncryptedKey) SAMLUtil.buildXMLObject(EncryptedKey.DEFAULT_ELEMENT_NAME);
			EncryptionMethod keyEncMethod = (EncryptionMethod) SAMLUtil.buildXMLObject(EncryptionMethod.DEFAULT_ELEMENT_NAME);
			keyEncMethod.setAlgorithm(EncryptionConstants.ALGO_ID_KEYTRANSPORT_RSAOAEP);
			encryptedKey.setEncryptionMethod(keyEncMethod);
			CipherData cipherData = SAMLUtil.getCipherData(encKey);
			encryptedKey.setCipherData(cipherData);
			keyInfo.getEncryptedKeys().add(encryptedKey);

			cipherData = SAMLUtil.getCipherData(encAsst);

			encryptedData.setEncryptionMethod(encMethod);
			encryptedData.setKeyInfo(keyInfo);
			encryptedData.setCipherData(cipherData);

			encryptedAssertion.setEncryptedData(encryptedData);
		}
		catch (CryptoApiException e) {
			log.error("encryption failed", e);
			throw new SSOException(e);
		}
		catch (MarshallingException e) {
			log.error("encryption failed", e);
			throw new SSOException(e);
		}
		catch (Exception e) {
			log.error("encryption failed", e);
			throw new SSOException(e);
		}

		return encryptedAssertion;
	}

	protected boolean checkSignCredential(BasicX509Credential credential, SignableXMLObject xmlObject)
	{
		String metaCert = getCertStr(credential);
		String xmlCert = xmlObject.getSignature().getKeyInfo().getX509Datas().get(0).getX509Certificates().get(0).getValue();

		if (Util.isEmpty(metaCert) || Util.isEmpty(xmlCert)) {
			return false;
		}

		if (!metaCert.replace("\n", "").equals(xmlCert.replace("\n", ""))) {
			return false;
		}

		return true;
	}

	public static String getCertStr(Credential credential)
	{
		try {
			return encode64(((BasicX509Credential) credential).getEntityCertificate().getEncoded());
		}
		catch (Exception e) {
			log.error("### getCertStr() Exception: {}", e.toString());
			return null;
		}
	}

	public int encryptToken(HttpSession session, String uid, String uip, String spName, StringBuilder token)
	{
		try {
			// 암호키 생성
			SSOSecretKey secKey = crypto.generateSecretKey(cryptoAlgorithm, randomAlgorithm);

			Util.setAuditInfo(Util.getDateFormat("yyyyMMdd"), Util.getDateFormat("HHmmss"),
					SSOConfig.getInstance().getServerName(), "AM", "0", uip + ", 인증토큰 암복호화키, SEED/CBC");

			// 암호 연산
			String encToken = encrypt(secKey, token.toString());

			Util.setAuditInfo(Util.getDateFormat("yyyyMMdd"), Util.getDateFormat("HHmmss"),
					SSOConfig.getInstance().getServerName(), "AX", "0", uip + ", 인증토큰 암호화, SEED/CBC");

			// 인증토큰(평문) 파기
			Util.zeroize(token);

			Util.setAuditInfo(Util.getDateFormat("yyyyMMdd"), Util.getDateFormat("HHmmss"),
					SSOConfig.getInstance().getServerName(), "AZ", "0", uip + ", 인증토큰 파기, 0 으로 덮어쓰기");

			String idpName = MetadataRepository.getInstance().getIDPName();
			Credential idpCert = CredentialRepository.getCredential(idpName, MStatus.ENC_CERT);
			String encKey = encryptPublicKey(idpCert, secKey.getKeyIv());

			session.setAttribute(CommonProvider.SESSION_SSO_ID, uid);
			session.setAttribute(CommonProvider.SESSION_TOKEN_EK, encKey);
			session.setAttribute(CommonProvider.SESSION_TOKEN, encToken);

			// 암호키 파기
			secKey.finalize();

			Util.setAuditInfo(Util.getDateFormat("yyyyMMdd"), Util.getDateFormat("HHmmss"),
					SSOConfig.getInstance().getServerName(), "AW", "0", uip + ", 인증토큰 암호화 후 파기, 0 으로 덮어쓰기");

			// AuthCode Map
			String authCode = createRandom(32);
			SessionManager sm = SessionManager.getInstance();
			sm.addAuthcodeMap(authCode, (String) uid, spName, "BR", uip, encToken + "." + encKey);

			session.setAttribute(CommonProvider.SESSION_AUTHCODE, authCode);
		}
		catch (CryptoApiException e) {
			if (e.getCode() == MStatus.CRYPTO_GEN_SECRETKEY) {
				Util.setAuditInfo(Util.getDateFormat("yyyyMMdd"), Util.getDateFormat("HHmmss"),
						uid, "AM", "1", uip + ", SEED, " + SSOConfig.getInstance().getServerName());
			}
			else if (e.getCode() == MStatus.CRYPTO_ENCRYPT) {
				Util.setAuditInfo(Util.getDateFormat("yyyyMMdd"), Util.getDateFormat("HHmmss"),
						uid, "AX", "1", uip + ", SEED, " + SSOConfig.getInstance().getServerName());
			}

			e.printStackTrace();
			return -1;
		}
		catch (Exception e) {
			e.printStackTrace();
			return -1;
		}

		return 0;
	}

	public int encryptToken(HttpServletRequest request, String uid, String uip, String spName, StringBuilder token)
	{
		try {
			// 암호키 생성
			SSOSecretKey secKey = crypto.generateSecretKey(cryptoAlgorithm, randomAlgorithm);

			Util.setAuditInfo(Util.getDateFormat("yyyyMMdd"), Util.getDateFormat("HHmmss"),
					SSOConfig.getInstance().getServerName(), "AM", "0", uip + ", 인증토큰 암복호화키, SEED/CBC");

			// 암호 연산
			String encToken = encrypt(secKey, token.toString());

			Util.setAuditInfo(Util.getDateFormat("yyyyMMdd"), Util.getDateFormat("HHmmss"),
					SSOConfig.getInstance().getServerName(), "AX", "0", uip + ", 인증토큰 암호화, SEED/CBC");

			// 인증토큰(평문) 파기
			Util.zeroize(token);

			Util.setAuditInfo(Util.getDateFormat("yyyyMMdd"), Util.getDateFormat("HHmmss"),
					SSOConfig.getInstance().getServerName(), "AZ", "0", uip + ", 인증토큰 파기, 0 으로 덮어쓰기");

			String idpName = MetadataRepository.getInstance().getIDPName();
			Credential idpCert = CredentialRepository.getCredential(idpName, MStatus.ENC_CERT);
			String encKey = encryptPublicKey(idpCert, secKey.getKeyIv());

			// 암호키 파기
			secKey.finalize();

			Util.setAuditInfo(Util.getDateFormat("yyyyMMdd"), Util.getDateFormat("HHmmss"),
					SSOConfig.getInstance().getServerName(), "AW", "0", uip + ", 인증토큰 암호화 후 파기, 0 으로 덮어쓰기");

			// AuthCode Map
			String authCode = createRandom(32);
			SessionManager sm = SessionManager.getInstance();
			sm.addAuthcodeMap(authCode, (String) uid, spName, "MB", uip, encToken + "." + encKey);

			request.setAttribute(CommonProvider.SESSION_AUTHCODE, authCode);
		}
		catch (CryptoApiException e) {
			if (e.getCode() == MStatus.CRYPTO_GEN_SECRETKEY) {
				Util.setAuditInfo(Util.getDateFormat("yyyyMMdd"), Util.getDateFormat("HHmmss"),
						uid, "AM", "1", uip + ", SEED, " + SSOConfig.getInstance().getServerName());
			}
			else if (e.getCode() == MStatus.CRYPTO_ENCRYPT) {
				Util.setAuditInfo(Util.getDateFormat("yyyyMMdd"), Util.getDateFormat("HHmmss"),
						uid, "AX", "1", uip + ", SEED, " + SSOConfig.getInstance().getServerName());
			}

			e.printStackTrace();
			return -1;
		}
		catch (Exception e) {
			e.printStackTrace();
			return -1;
		}

		return 0;
	}

	public synchronized SSOToken decryptToken(String encToken, String encKey)
	{
		//log.debug("### decryptToken() start");
		byte[] decKey = null;
		byte[] byteToken = null;
		String strToken = null;
		StringBuilder sbToken = null;
		SSOToken token = null;
		SSOSecretKey secKey = null;

		try {
			// 대칭키 복호화
			decKey = decryptPrivateKey(encKey);
			secKey = new SSOSecretKey(cryptoAlgorithm, decKey);

			// 인증토큰 복호화
			byteToken = decrypt(secKey, encToken);
			strToken = new String(byteToken);
			sbToken = new StringBuilder(strToken);
			token = new SSOToken(sbToken);

			Util.zeroize(decKey);
			Util.zeroize(byteToken);
			Util.zeroize(strToken);
			secKey.finalize();

			//log.debug("### decryptToken() end");
			return token;
		}
		catch (Exception e) {
			secKey.finalize();
			Util.zeroize(decKey);
			Util.zeroize(byteToken);

			try {
				Util.zeroize(strToken);
			}
			catch (Exception _e) {
			}

			e.printStackTrace();
			return null;
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

	public void verifyCert(X509Certificate userCert) throws SSOException
	{
		SSOException ex = null;

		if (verifyCert) {
			for (int i = 0; i < verifyCertMethod.length; i++) {
				switch (verifyCertMethod[i]) {
				case VERIFY_IVS:
					try {
						verifyCertIVS(userCert);
						return;
					}
					catch (SSOException e) {
						ex = (ex == null) ? e : new SSOException(e.getMessage(), ex);
						continue;
					}
				case VERIFY_CRL:
					try {
						verifyCertCRL(userCert);
						return;
					}
					catch (SSOException e) {
						ex = (ex == null) ? e : new SSOException(e.getMessage(), ex);
						continue;
					}

				case VERIFY_OCSP:
					try {
						verifyCertOCSP(userCert);
						return;
					}
					catch (SSOException e) {
						ex = (ex == null) ? e : new SSOException(e.getMessage(), ex);
						continue;
					}
				}
			}

			// 검증이 모두 실패했을 때는 마지막 exception을 던진다.
			throw new SSOException(MStatus.CRYPTO_VERIFY_CERT, "인증서 검증에 실패하였습니다.", ex);
		}
	}

	public void verifyCertIVS(X509Certificate userCert) throws SSOException
	{
		try {
			X509Certificate serverCert = X509Certificate.getInstance(this.encCert);

			IVSReqMsgGenerator ivsReqMsg = new IVSReqMsgGenerator(serverCert);
			byte[] reqMsg = ivsReqMsg.generate(userCert);

			IVSP ivsp = new IVSP();
			ivsp.connect("ivs.gpki.go.kr", 8080);

			IVSResMsg ivsResMsg = ivsp.sendAndRecv(reqMsg);

			X509Certificate svrSignCert = downloadCert("ldap://cen.dir.go.kr:389/cn=IVS1310386001,ou=GPKI,o=Government of Korea,c=KR",
					"signcertificate");

			int code = ivsResMsg.process(ivsReqMsg.getNonce(), svrSignCert);

			if (code != 0) {
				throw new SSOException(MStatus.CRYPTO_VERIFY_IVS, "verifyFailed[" + code + "] = " + ivsResMsg.getDescreption());
			}
		}
		catch (Exception e) {
			throw new SSOException(MStatus.CRYPTO_VERIFY_IVS, e);
		}
	}

	public void verifyCertCRL(X509Certificate userCert) throws SSOException
	{
		FileInputStream ca_info = null;

		try {
			log.debug("ca_info : " + SSOConfig.getInstance().getHomePath("config/ca_env_info"));

			ca_info = new FileInputStream(SSOConfig.getInstance().getHomePath("config/ca_env_info"));

			Properties prop = new Properties();
			prop.load(ca_info);

			X509CertVerifier certVerifier = new X509CertVerifier(prop, "./");

			// 신뢰하는 최상위 인증서 목록 지정
			ArrayList trustAnchors = new ArrayList();
			X509Certificate npkiRootCert = this.x509Root;
			trustAnchors.add(npkiRootCert);
			certVerifier.setTrustedAnchors(trustAnchors);

			// 허용하는 인증서 정책 목록 지정
			certVerifier.setVerifyRange(X509CertVerifier.RANGE_FULL_PATH);

			// 인증서 폐지 여부 확인 방법 지정
			certVerifier.setRevocationCheckMethod(X509CertVerifier.REVOCATION_CHECK_BY_ARL | X509CertVerifier.REVOCATION_CHECK_BY_CRL);

			// 검증하는 인증서 종류 지정
			certVerifier.setCertType("");

			// 인증서 검증
			certVerifier.verify(userCert);
		}
		catch (Exception e) {
			log.error(e.getMessage());

			try {
				ca_info.close();
			}
			catch (Exception ee) {
			}

			throw new SSOException(MStatus.CRYPTO_VERIFY_CRL, e);
		}
		finally {
			try {
				ca_info.close();
			}
			catch (Exception e) {
				e.printStackTrace();
			}
		}
	}

	public void verifyCertOCSP(X509Certificate userCert) throws SSOException
	{
		try {
			OCSPRequestGenerator ocspRequestGenerator = new OCSPRequestGenerator();

			ocspRequestGenerator.addRequestCert(userCert);
			OCSPRequest ocspRequest = ocspRequestGenerator.generate();

			String ocspUrl = "";
			X509InformationAccess aia = userCert.getAuthorityInformationAccess();

			if (aia == null) {
				log.error("### X509InformationAccess is null");
				throw new SSOException(MStatus.CRYPTO_VERIFY_OCSP, "X509InformationAccess is null.");
			}

			ocspUrl = aia.getOcsp();

			if (ocspUrl == null) {
				throw new SSOException(MStatus.CRYPTO_VERIFY_OCSP, "The ocsp information does not exist.");
			}

			OCSP ocsp = new OCSP();
			ocsp.connect(new URL(ocspUrl));
			OCSPResponse ocspResponse = ocsp.sendAndRecv(ocspRequest);
			ocsp.close();
			ocspResponse.verify();

			if (ocspResponse.getResponseStatus() != 0) {
				throw new SSOException(MStatus.CRYPTO_VERIFY_OCSP, "FAIL - ocspResponse Status : " + ocspResponse.getResponseStatus());
			}

			byte[] reqNonce = ocspRequest.getNonce();
			byte[] resNonce = ((BasicOCSPResponse) ocspResponse.getResponse()).getNonce();

			if (!ByteUtil.equals(reqNonce, resNonce)) {
				throw new SSOException(MStatus.CRYPTO_VERIFY_OCSP, "Nonce is different.");
			}

			ArrayList request = ocspRequest.getRequestList();
			ArrayList responses = ((BasicOCSPResponse) ocspResponse.getResponse()).getResponses();

			for (int i = 0; i < responses.size(); i++) {
				SingleResponse singleResponse = (SingleResponse) responses.get(i);
				CertID certID = singleResponse.getCertID();

				if (!((Request) request.get(i)).getReqCert().equals(certID)) {
					throw new SSOException(MStatus.CRYPTO_VERIFY_OCSP, "The response is not for the request.");
				}

				int n_status = singleResponse.getCertStat().getStatus();

				if (n_status == 0) {
					break;
				}

				if (i == (responses.size() - 1)) {
					if (n_status == 1) {
						throw new SSOException(MStatus.CRYPTO_VERIFY_OCSP, "status : revoked (revocationTime = "
								+ singleResponse.getCertStat().getRevokedInfo().getRevocationTime() + ", reason = "
								+ singleResponse.getCertStat().getRevokedInfo().getRevocationReason() + ")");
					}
					if (n_status == 2) {
						throw new SSOException(MStatus.CRYPTO_VERIFY_OCSP, "reason : unknown");
					}
				}
			}
		}
		catch (Exception e) {
			throw new SSOException(MStatus.CRYPTO_VERIFY_OCSP, e);
		}
	}

	static X509Certificate downloadCert(String url, String attribute) throws NamingException, IOException
	{
		URLParser urlParser = new URLParser(url);

		LDAP ldap = new LDAP();
		ldap.connect(urlParser.getIP(), urlParser.getPort());
		ldap.search(urlParser.getURI(), attribute);
		ArrayList objs = ldap.getObject();
		ldap.close();

		return X509Certificate.getInstance((byte[]) objs.get(0));
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
}