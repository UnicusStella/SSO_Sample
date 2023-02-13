package com.dreamsecurity.sso.server.config;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.Console;
import java.io.File;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;
import java.util.Scanner;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import netscape.ldap.LDAPAttribute;
import netscape.ldap.LDAPAttributeSet;
import netscape.ldap.LDAPConnection;
import netscape.ldap.LDAPEntry;
import netscape.ldap.LDAPException;
import netscape.ldap.LDAPSearchResults;

import com.dreamsecurity.jcaos.asn1.oid.AlgorithmObjectIdentifiers;
import com.dreamsecurity.jcaos.asn1.oid.PKCS5ObjectIdentifiers;
import com.dreamsecurity.jcaos.jce.provider.JCAOSProvider;
import com.dreamsecurity.jcaos.pkcs.PKCS8PrivateKeyInfo;
import com.dreamsecurity.jcaos.util.FileUtil;
import com.dreamsecurity.jcaos.util.encoders.Hex;
import com.dreamsecurity.sso.lib.ccf.XMLConfiguration;
import com.dreamsecurity.sso.lib.dss.s2.metadata.AssertionConsumerService;
import com.dreamsecurity.sso.lib.dss.s2.metadata.EntitiesDescriptor;
import com.dreamsecurity.sso.lib.dss.s2.metadata.EntityDescriptor;
import com.dreamsecurity.sso.lib.dss.s2.metadata.IDPSSODescriptor;
import com.dreamsecurity.sso.lib.dss.s2.metadata.KeyDescriptor;
import com.dreamsecurity.sso.lib.dss.s2.metadata.SPSSODescriptor;
import com.dreamsecurity.sso.lib.dss.s2.metadata.SingleLogoutService;
import com.dreamsecurity.sso.lib.dss.s2.metadata.SingleSignOnService;
import com.dreamsecurity.sso.lib.dsx.Configuration;
import com.dreamsecurity.sso.lib.dsx.security.SecurityHelper;
import com.dreamsecurity.sso.lib.dsx.security.credential.Credential;
import com.dreamsecurity.sso.lib.dsx.security.credential.UsageType;
import com.dreamsecurity.sso.lib.dsx.security.keyinfo.KeyInfoGenerator;
import com.dreamsecurity.sso.lib.jtm.DateTime;
import com.dreamsecurity.sso.lib.jtm.DateTimeZone;
import com.dreamsecurity.sso.server.common.MStatus;
import com.dreamsecurity.sso.server.crypto.ASN1Util;
import com.dreamsecurity.sso.server.crypto.CryptoApiException;
import com.dreamsecurity.sso.server.crypto.SSOSecretKey;
import com.dreamsecurity.sso.server.metadata.CredentialRepository;
import com.dreamsecurity.sso.server.metadata.MetadataRepository;
import com.dreamsecurity.sso.server.repository.ldap.LdapQuery;
import com.dreamsecurity.sso.server.util.SAMLUtil;
import com.dreamsecurity.sso.server.util.Util;

public class InitSSO
{
	final static String providerName = "JCAOS" ;

	static {
		JCAOSProvider.installProvider();
	}

	public static SSOSecretKey generateKEKByPwd(String password, String certFile) throws CryptoApiException
	{
		try {
			byte[] cert = FileUtil.read(certFile);
			byte[] byteData = new byte[password.getBytes().length + cert.length];
			System.arraycopy(password.getBytes(), 0, byteData, 0, password.getBytes().length);
			System.arraycopy(cert, 0, byteData, password.getBytes().length, cert.length);

			MessageDigest md = MessageDigest.getInstance("SHA256", providerName);
			byte[] bytePwd = md.digest(byteData);

			MessageDigest mdp = MessageDigest.getInstance("SHA256", providerName);
			byte[] out = mdp.digest(bytePwd);

			byte[] salt = new byte[16];
			System.arraycopy(out, 0, salt, 0, salt.length);
			int iterationCount = 1024;

			// PBKDF2 start
			byte[] macValue = null;
			byte[] dk = new byte[32];

			Mac mac = Mac.getInstance("HMAC-SHA256", providerName);
			SecretKey sk = new SecretKeySpec(bytePwd, "HMAC-SHA256");

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
			System.arraycopy(dk, 0, skParam, 0, skParam.length);

			byte[] ivParam = new byte[16];
			SecureRandom rand = SecureRandom.getInstance("SHA256DRBG", providerName);
			rand.nextBytes(ivParam);

			SSOSecretKey ssoSeckey = new SSOSecretKey("SEED", skParam.clone(), ivParam.clone());

			Util.zeroize(bytePwd);
			Util.zeroize(out);
			Util.zeroize(salt);
			Util.zeroize(dk);
			Util.zeroize(skParam);
			Util.zeroize(ivParam);

			return ssoSeckey;
		}
		catch (Exception e) {
			throw new CryptoApiException(MStatus.CRYPTO_GEN_KEK, e);
		}
	}

	public static SSOSecretKey generateSecretKey() throws CryptoApiException
	{
		try {
			KeyGenerator keyGen = KeyGenerator.getInstance("SEED", providerName);
			keyGen.init(128);
			SecretKey secKey = keyGen.generateKey();

			byte[] ivParam = new byte[16];
			SecureRandom rand = SecureRandom.getInstance("SHA256DRBG", providerName);
			rand.nextBytes(ivParam);

			SSOSecretKey ssoSeckey = new SSOSecretKey(keyGen.getAlgorithm(), secKey.getEncoded().clone(), ivParam.clone());

			Util.zeroize(ivParam);

			return ssoSeckey;
		}
		catch (Exception e) {
			throw new CryptoApiException(MStatus.CRYPTO_GEN_SECRETKEY, e);
		}
	}

	public static byte[] encrypt(byte[] key, byte[] iv, byte[] input) throws CryptoApiException
	{
		try {
			SecretKey sk = new SecretKeySpec(key.clone(), "SEED");
			IvParameterSpec ips = new IvParameterSpec(iv.clone());

			Cipher cipher = Cipher.getInstance("SEED/CBC/PKCS5Padding", providerName);
			cipher.init(Cipher.ENCRYPT_MODE, sk, ips);
			byte[] result = cipher.doFinal(input);

			return result;
		}
		catch (Exception e) {
			throw new CryptoApiException(MStatus.CRYPTO_ENCRYPT_KEY, e);
		}
	}

	public static byte[] decrypt(byte[] key, byte[] iv, byte[] input) throws CryptoApiException
	{
		try {
			SecretKey sk = new SecretKeySpec(key.clone(), "SEED");
			IvParameterSpec ips = new IvParameterSpec(iv.clone());

			Cipher cipher = Cipher.getInstance("SEED/CBC/PKCS5Padding", providerName);
			cipher.init(Cipher.DECRYPT_MODE, sk, ips);
			byte[] result = cipher.doFinal(input);

			return result;
		}
		catch (Exception e) {
			throw new CryptoApiException(MStatus.CRYPTO_DECRYPT_KEY, e);
		}
	}

	public static String hmac(byte[] input, byte[] key) throws CryptoApiException
	{
		try {
			SecretKey macKey = new SecretKeySpec(key, "HMAC-SHA256");

			Mac mac = Mac.getInstance("HMAC-SHA256", providerName);
			mac.init(macKey);
			mac.update(input);
			byte[] bytes = mac.doFinal();
			String result = new String(Hex.encode(bytes));

			return result;
		}
		catch (Exception e) {
			throw new CryptoApiException(MStatus.CRYPTO_HMAC, e);
		}
	}

	public static void setIntegrityJar(String homepath, byte[] key)
	{
		BufferedWriter bw = null;

		try {
			String cryptopath = com.dreamsecurity.kcmv.jce.provider.MagicJCryptoProvider.class
					.getProtectionDomain().getCodeSource().getLocation().getPath() + ".hmac";

			String ssopath = com.dreamsecurity.sso.idp.crypto.api.MJCryptoApi.class
					.getProtectionDomain().getCodeSource().getLocation().getPath();

			if (!Util.isEmpty(ssopath) && ssopath.length() >= 4 && !ssopath.substring(ssopath.length() - 4).equalsIgnoreCase(".jar")) {
				ssopath = homepath + "/config/" + SSOConfig.getJarVersion() + ".jar";
			}

			String hmacPath = homepath + "/config/" + SSOConfig.getJarVersion() + ".jar.hmac";

			// crypto
			byte[] cryptofileByte = FileUtil.read(cryptopath);
			if (cryptofileByte == null || cryptofileByte.length < 0)
				throw new Exception(cryptopath + " file is not exist.");

			String cryptojarHmac = hmac(cryptofileByte, key.clone());

			// sso
			byte[] fileByte = FileUtil.read(ssopath);
			if (fileByte == null || fileByte.length < 0)
				throw new Exception(ssopath + " file is not exist.");

			String jarHmac = hmac(fileByte, key.clone());

			bw = new BufferedWriter(new FileWriter(hmacPath));
			bw.write(cryptojarHmac + "\n" + jarHmac + "\n");
			bw.flush();
		}
		catch (Exception e) {
			e.printStackTrace();
			outPrint("\nsetIntegrityJar() Failure\n");
			if (bw != null) try { bw.close(); } catch (IOException ie) {}
		}
		finally {
			Util.zeroize(key);
			if (bw != null) try { bw.close(); } catch (IOException ie) {}
		}
	}

	public static int setIntegrityFile(String ssopath, String homepath, byte[] key)
	{
		BufferedWriter bw = null;

		try {
			StringBuilder out = new StringBuilder();

			ArrayList<String> pathList = getVerifyPathList(homepath);

			for (int i = 0; i < pathList.size(); i++) {
				if (out.length() != 0) { out.append("\n"); }
				out.append("[" + pathList.get(i) + "]\n");

				ArrayList<String> fileList = getVerifyFileList(homepath, pathList.get(i));

				for (int j = 0; j < fileList.size(); j++) {
					String file = fileList.get(j);
					int index = file.indexOf(";");
					if (index > -1) {
						file = file.substring(0, index);
					}

					String fullpathfile = "";
					int idxsso = pathList.get(i).indexOf("/sso");
					if (idxsso == 0) {
						fullpathfile = ssopath + pathList.get(i).substring(4) + "/" + file;
					}
					else {
						fullpathfile = homepath + pathList.get(i) + "/" + file;
					}

					byte[] fileByte = FileUtil.read(fullpathfile);
					if (fileByte == null || fileByte.length < 0) {
						throw new Exception(fileList.get(j) + " file is not exist.");
					}

					String hmac = hmac(fileByte, key.clone());

					out.append(file + ";" + hmac + "\n");
				}
			}

			String outFile = homepath + "/config/integrity.cfg";
			bw = new BufferedWriter(new FileWriter(outFile));
			bw.write(out.toString());
			bw.flush();
			bw.close();

			String allhmac = hmac(out.toString().getBytes(), key.clone());

			outFile = homepath + "/config/integrity.cfg.hmac";
			bw = new BufferedWriter(new FileWriter(outFile));
			bw.write(allhmac + "\n");
			bw.flush();
			bw.close();
		}
		catch (Exception e) {
			e.printStackTrace();
			outPrint("\nsetIntegrityFile() Failure\n");
			if (bw != null) try { bw.close(); } catch (IOException ie) {}
			return 0;
		}
		finally {
			Util.zeroize(key);
			if (bw != null) try { bw.close(); } catch (IOException ie) {}
		}

		return 1;
	}

	public static ArrayList<String> getVerifyPathList(String homepath)
	{
		BufferedReader br = null;
		ArrayList<String> pathList = new ArrayList<String>();

		try {
			String inFile = homepath + "/config/integrity.cfg";

			br = new BufferedReader(new FileReader(inFile));
			String line;

			while ((line = br.readLine()) != null) {
				line = line.trim();
				int index1 = line.indexOf("[");
				int index2 = line.indexOf("]");
				if (index1 == 0 && index2 > 0)
					pathList.add(line.substring(index1 + 1, index2));
            }

			Collections.sort(pathList, new Comparator<String>() {
				public int compare(String o1, String o2) {
					return o1.compareTo(o2);
				}
			});
		}
		catch (Exception e) {
			e.printStackTrace();
		}
		finally {
			if (br != null) try { br.close(); } catch (IOException e) {}
		}

		return pathList;
	}

	public static ArrayList<String> getVerifyFileList(String homepath, String subdir)
	{
		BufferedReader br = null;
		ArrayList<String> fileList = new ArrayList<String>();

		try {
			String inFile = homepath + "/config/integrity.cfg";

			br = new BufferedReader(new FileReader(inFile));
			boolean bPath = false;
			String line;

			while ((line = br.readLine()) != null) {
				line = line.trim();
				if (Util.isEmpty(line)) continue;
				int index1 = line.indexOf("[");
				int index2 = line.indexOf("]");
				if (index1 == 0 && index2 > 0) {
					if (subdir.equals(line.substring(index1 + 1, index2)))
						bPath = true;
					else
						if (bPath) break;
				}
				else {
					if (bPath)
						fileList.add(line);
				}
            }

			Collections.sort(fileList, new Comparator<String>() {
				public int compare(String o1, String o2) {
					return o1.compareTo(o2);
				}
			});
		}
		catch (Exception e) {
			e.printStackTrace();
		}
		finally {
			if (br != null) try { br.close(); } catch (IOException e) {}
		}

		return fileList;
	}

	public static void verifyKeyPair(String privateFile, String privatePwd) throws Exception
	{
		try {
			byte[] priKeyByte = loadPrivateKey(privateFile, privatePwd);
			PKCS8PrivateKeyInfo priKeyInfo = PKCS8PrivateKeyInfo.getInstance(priKeyByte);

			String publicFile = privateFile.replace(".key", ".der");
			com.dreamsecurity.jcaos.x509.X509Certificate pubKeyInfo = com.dreamsecurity.jcaos.x509.X509Certificate.getInstance(FileUtil.read(publicFile));

			Cipher cipher = Cipher.getInstance("RSA/NONE/OAEPWithSHA256andMGF1Padding", providerName);
			cipher.init(Cipher.ENCRYPT_MODE, pubKeyInfo.getPublicKey());
			byte[] cipherText = cipher.doFinal("dreamsecurity".getBytes());

			cipher.init(Cipher.DECRYPT_MODE, priKeyInfo.getPrivateKey());
			byte[] plainText = cipher.doFinal(cipherText);
			String decText = new String(plainText);

			if (!"dreamsecurity".equals(decText)) {
				throw new Exception("Mismatched Key Pair.");
			}
		}
		catch (Exception e) {
			e.printStackTrace();
			outPrint("\n>>> Mismatched Key Pair.\n");
			throw new Exception("Mismatched Key Pair.");
		}
	}

	private static byte[] loadPrivateKey(String path, String pwd) throws CryptoApiException
	{
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

			Cipher cipher = Cipher.getInstance(szAlgorithm, providerName);
			cipher.init(Cipher.DECRYPT_MODE, sKeySpec, ivParamSepc);
			result = cipher.doFinal(encryptedData);

			return result;
		}
		catch (Exception e) {
			throw new CryptoApiException(MStatus.ERR_LOAD_PRIVATEKEY, e);
		}
	}

	private static byte[] pbkdf2(byte[] pwd, byte[] salt, int count, int len) throws NoSuchAlgorithmException, NoSuchProviderException,
			InvalidKeyException
	{
		byte[] dk = new byte[len];
		int totalLen = len, hLen = 32, offset = 0, loop = (len + hLen - 1) / hLen;
		byte[] macData = new byte[salt.length + 4];
		int i, j, k;

		System.arraycopy(salt, 0, macData, 0, salt.length);

		String algo = "HMAC-SHA256";
		SecretKeySpec ks = new SecretKeySpec(pwd, algo);
		Mac mac = Mac.getInstance(algo, providerName);

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

	public static void setInitializeDB(String dbDriver, String dburl, String dbusr, String dbpwd, SSOSecretKey DEK, String adminIP) throws Exception
	{
		Class.forName(dbDriver);
		Connection conn = DriverManager.getConnection(dburl, dbusr, dbpwd);

		StringBuffer query01 = new StringBuffer();
		query01.append("DELETE FROM SSO_AUPY ");

		PreparedStatement pstmt = conn.prepareStatement(query01.toString());
		pstmt.executeUpdate();
		pstmt.close();

		byte[] encWarnLimit = encrypt(DEK.getKey(), DEK.getIv(), "90".getBytes());
		byte[] encVerifyCycle = encrypt(DEK.getKey(), DEK.getIv(), "H".getBytes());
		byte[] encVerifyPoint = encrypt(DEK.getKey(), DEK.getIv(), "8".getBytes());

		StringBuffer query02 = new StringBuffer();
		query02.append("INSERT INTO SSO_AUPY(CODE, WARN_LIMIT, VERIFY_CYCLE, VERIFY_POINT) ")
			.append("VALUES('AUPY0001', ?, ?, ?) ");

		pstmt = conn.prepareStatement(query02.toString());
        pstmt.setString(1, new String(Hex.encode(encWarnLimit)));
        pstmt.setString(2, new String(Hex.encode(encVerifyCycle)));
        pstmt.setString(3, new String(Hex.encode(encVerifyPoint)));
		pstmt.executeUpdate();
		pstmt.close();

		StringBuffer query03 = new StringBuffer();
		query03.append("DELETE FROM SSO_MSVR ");

		pstmt = conn.prepareStatement(query03.toString());
		pstmt.executeUpdate();
		pstmt.close();

		StringBuffer query04 = new StringBuffer();
		query04.append("INSERT INTO SSO_MSVR(CODE) ")
			.append("VALUES('MSVR0001') ");

		pstmt = conn.prepareStatement(query04.toString());
		pstmt.executeUpdate();
		pstmt.close();

		StringBuffer query05 = new StringBuffer();
		query05.append("DELETE FROM SSO_MSND ");

		pstmt = conn.prepareStatement(query05.toString());
		pstmt.executeUpdate();
		pstmt.close();

		StringBuffer sbBody1 = new StringBuffer();
		sbBody1.append("$1 $2 아이디가 비밀번호 연속 오류로\n")
			.append("인증 기능 비활성화 상태로 변경되었습니다.\n")
			.append("확인 바랍니다.");

		byte[] encSubject = encrypt(DEK.getKey(), DEK.getIv(), "[SSO] 인증 기능 비활성화 알림".getBytes("UTF-8"));
		byte[] encBody = encrypt(DEK.getKey(), DEK.getIv(), sbBody1.toString().getBytes("UTF-8"));

		StringBuffer query06 = new StringBuffer();
		query06.append("INSERT INTO SSO_MSND(CODE, SUBJECT, BODY) ")
			.append("VALUES(?, ?, ?) ");

		pstmt = conn.prepareStatement(query06.toString());
		pstmt.setString(1, "MSND0000");
		pstmt.setString(2, new String(Hex.encode(encSubject)));
		pstmt.setString(3, new String(Hex.encode(encBody)));
		pstmt.executeUpdate();

		StringBuffer sbBody2 = new StringBuffer();
		sbBody2.append("SSO 무결성 검증 오류가 발생하였습니다.\n")
			.append("시스템 점검 바랍니다.");

		encSubject = encrypt(DEK.getKey(), DEK.getIv(), "[SSO] 무결성 검증 오류 발생".getBytes("UTF-8"));
		encBody = encrypt(DEK.getKey(), DEK.getIv(), sbBody2.toString().getBytes("UTF-8"));

		pstmt.setString(1, "MSND0001");
		pstmt.setString(2, new String(Hex.encode(encSubject)));
		pstmt.setString(3, new String(Hex.encode(encBody)));
		pstmt.executeUpdate();

		StringBuffer sbBody3 = new StringBuffer();
		sbBody3.append("SSO 암호모듈 자가시험 오류가 발생하였습니다.\n")
			.append("시스템 점검 바랍니다.");

		encSubject = encrypt(DEK.getKey(), DEK.getIv(), "[SSO] 암호모듈 자가시험 오류 발생".getBytes("UTF-8"));
		encBody = encrypt(DEK.getKey(), DEK.getIv(), sbBody3.toString().getBytes("UTF-8"));

		pstmt.setString(1, "MSND0002");
		pstmt.setString(2, new String(Hex.encode(encSubject)));
		pstmt.setString(3, new String(Hex.encode(encBody)));
		pstmt.executeUpdate();

		StringBuffer sbBody6 = new StringBuffer();
		sbBody6.append("SSO 프로세스 검증 오류가 발생하였습니다.\n")
			.append("시스템 점검 바랍니다.");

		encSubject = encrypt(DEK.getKey(), DEK.getIv(), "[SSO] 프로세스 검증 오류 발생".getBytes("UTF-8"));
		encBody = encrypt(DEK.getKey(), DEK.getIv(), sbBody6.toString().getBytes("UTF-8"));

		pstmt.setString(1, "MSND0005");
		pstmt.setString(2, new String(Hex.encode(encSubject)));
		pstmt.setString(3, new String(Hex.encode(encBody)));
		pstmt.executeUpdate();

		StringBuffer sbBody4 = new StringBuffer();
		sbBody4.append("SSO 감사정보 저장용량이 임계치를 초과하였습니다.\n")
			.append("시스템 점검 바랍니다.");

		encSubject = encrypt(DEK.getKey(), DEK.getIv(), "[SSO] 감사정보 저장용량 임계치 초과".getBytes("UTF-8"));
		encBody = encrypt(DEK.getKey(), DEK.getIv(), sbBody4.toString().getBytes("UTF-8"));

		pstmt.setString(1, "MSND0003");
		pstmt.setString(2, new String(Hex.encode(encSubject)));
		pstmt.setString(3, new String(Hex.encode(encBody)));
		pstmt.executeUpdate();

		StringBuffer sbBody5 = new StringBuffer();
		sbBody5.append("SSO 감사정보 저장소가 포화 상태입니다.\n")
			.append("시스템 점검 바랍니다.");

		encSubject = encrypt(DEK.getKey(), DEK.getIv(), "[SSO] 감사정보 저장소 포화상태 알림".getBytes("UTF-8"));
		encBody = encrypt(DEK.getKey(), DEK.getIv(), sbBody5.toString().getBytes("UTF-8"));

		pstmt.setString(1, "MSND0004");
		pstmt.setString(2, new String(Hex.encode(encSubject)));
		pstmt.setString(3, new String(Hex.encode(encBody)));
		pstmt.executeUpdate();
		pstmt.close();

		StringBuffer query07 = new StringBuffer();
		query07.append("DELETE FROM SSO_URPY ");

		pstmt = conn.prepareStatement(query07.toString());
		pstmt.executeUpdate();
		pstmt.close();

		byte[] encPwMismatchAllow = encrypt(DEK.getKey(), DEK.getIv(), "5".getBytes());
		byte[] encPwChangeWarn = encrypt(DEK.getKey(), DEK.getIv(), "7".getBytes());
		byte[] encPwValidate = encrypt(DEK.getKey(), DEK.getIv(), "90".getBytes());
		byte[] encSessionTime = encrypt(DEK.getKey(), DEK.getIv(), "10".getBytes());
		byte[] encPollingTime = encrypt(DEK.getKey(), DEK.getIv(), "30".getBytes());

		StringBuffer query08 = new StringBuffer();
		query08.append("INSERT INTO SSO_URPY(URPY_CODE, NAME, PW_MISMATCH_ALLOW, PW_CHANGE_WARN, PW_VALIDATE, SESSION_TIME, POLLING_TIME) ")
			.append("VALUES('URPY0001', '사용자보안정책', ?, ?, ?, ?, ?) ");

		pstmt = conn.prepareStatement(query08.toString());
        pstmt.setString(1, new String(Hex.encode(encPwMismatchAllow)));
        pstmt.setString(2, new String(Hex.encode(encPwChangeWarn)));
        pstmt.setString(3, new String(Hex.encode(encPwValidate)));
        pstmt.setString(4, new String(Hex.encode(encSessionTime)));
        pstmt.setString(5, new String(Hex.encode(encPollingTime)));
		pstmt.executeUpdate();
		pstmt.close();

		StringBuffer query09 = new StringBuffer();
		query09.append("DELETE FROM SSO_ADPY ");

		pstmt = conn.prepareStatement(query09.toString());
		pstmt.executeUpdate();
		pstmt.close();

		encPwMismatchAllow = encrypt(DEK.getKey(), DEK.getIv(), "5".getBytes());
		encSessionTime = encrypt(DEK.getKey(), DEK.getIv(), "10".getBytes());
		byte[] encLockTime = encrypt(DEK.getKey(), DEK.getIv(), "5".getBytes());
		byte[] encIpMaxCount = encrypt(DEK.getKey(), DEK.getIv(), "2".getBytes());

		StringBuffer query10 = new StringBuffer();
		query10.append("INSERT INTO SSO_ADPY(ADPY_CODE, NAME, PW_MISMATCH_ALLOW, SESSION_TIME, LOCK_TIME, IP_MAX_COUNT) ")
			.append("VALUES('ADPY0001', '관리자보안정책', ?, ?, ?, ?) ");

		pstmt = conn.prepareStatement(query10.toString());
        pstmt.setString(1, new String(Hex.encode(encPwMismatchAllow)));
        pstmt.setString(2, new String(Hex.encode(encSessionTime)));
        pstmt.setString(3, new String(Hex.encode(encLockTime)));
        pstmt.setString(4, new String(Hex.encode(encIpMaxCount)));
		pstmt.executeUpdate();
		pstmt.close();

		StringBuffer query11 = new StringBuffer();
		query11.append("DELETE FROM SSO_ADIP ");

		pstmt = conn.prepareStatement(query11.toString());
		pstmt.executeUpdate();
		pstmt.close();

		byte[] encIp = encrypt(DEK.getKey(), DEK.getIv(), adminIP.getBytes());

		StringBuffer query12 = new StringBuffer();
		query12.append("INSERT INTO SSO_ADIP(IP) ")
			.append("VALUES(?) ");

		pstmt = conn.prepareStatement(query12.toString());
        pstmt.setString(1, new String(Hex.encode(encIp)));
		pstmt.executeUpdate();
		pstmt.close();

		StringBuffer query13 = new StringBuffer();
		query13.append("DELETE FROM SSO_ADMN ");

		pstmt = conn.prepareStatement(query13.toString());
		pstmt.executeUpdate();
		pstmt.close();

		StringBuffer query14 = new StringBuffer();
		query14.append("INSERT INTO SSO_ADMN(ID, NAME, PASSWORD, PW_UPDATE_TIME, STATUS, ADMN_TYPE, ADPY_CODE, FIRST_YN) ")
			.append("VALUES('ssoadmin', '관리자', 'ff1f1f9b5ef6534d070d0c7345c8b4b121dd01e73cb94dee1780e798d79cc9be', TO_DATE('20220802123456','YYYYMMDDHH24MISS'), 'C', 'S', 'ADPY0001', 'Y') ");

		pstmt = conn.prepareStatement(query14.toString());
		pstmt.executeUpdate();
		pstmt.close();

		StringBuffer query15 = new StringBuffer();
		query15.append("DELETE FROM SSO_USER WHERE ID = 'sso' ");

		pstmt = conn.prepareStatement(query15.toString());
		pstmt.executeUpdate();
		pstmt.close();

		StringBuffer query16 = new StringBuffer();
		query16.append("INSERT INTO SSO_USER(ID, NAME, PASSWORD, PW_UPDATE_TIME, STATUS, URPY_CODE) ")
			.append("VALUES('sso', '홍길동', 'e77ef187bff54bd057b1957fb2967fd845030fe1a9a419f4216b2a5b53b6c174', TO_DATE('20220801100000','YYYYMMDDHH24MISS'), 'C', 'URPY0001') ");

		pstmt = conn.prepareStatement(query16.toString());
		pstmt.executeUpdate();
		pstmt.close();

		StringBuffer query17 = new StringBuffer();
		query17.append("DELETE FROM SSO_SCOPES ");

		pstmt = conn.prepareStatement(query17.toString());
		pstmt.executeUpdate();
		pstmt.close();

		StringBuffer query18 = new StringBuffer();
		query18.append("INSERT INTO SSO_SCOPES(SCOPE) VALUES(?)");

		pstmt = conn.prepareStatement(query18.toString());
        pstmt.setString(1, "openid");
		pstmt.executeUpdate();

        pstmt.setString(1, "profile");
		pstmt.executeUpdate();

        pstmt.setString(1, "email");
		pstmt.executeUpdate();

        pstmt.setString(1, "address");
		pstmt.executeUpdate();
		pstmt.close();

		StringBuffer query19 = new StringBuffer();
		query19.append("DELETE FROM SSO_CLIENT ");

		pstmt = conn.prepareStatement(query19.toString());
		pstmt.executeUpdate();
		pstmt.close();

		StringBuffer query20 = new StringBuffer();
		query20.append("DELETE FROM SSO_CLIENT_REDIRECT ");

		pstmt = conn.prepareStatement(query20.toString());
		pstmt.executeUpdate();
		pstmt.close();

		StringBuffer query21 = new StringBuffer();
		query21.append("DELETE FROM SSO_CLIENT_SCOPE ");

		pstmt = conn.prepareStatement(query21.toString());
		pstmt.executeUpdate();
		pstmt.close();

		if (!conn.getAutoCommit())
			conn.commit();

		conn.close();
	}

	// Cubrid
	public static void setInitializeDB_cubrid(String dbDriver, String dburl, String dbusr, String dbpwd, SSOSecretKey DEK, String adminIP) throws Exception
	{
		Class.forName(dbDriver);
		Connection conn = DriverManager.getConnection(dburl, dbusr, dbpwd);

		StringBuffer query01 = new StringBuffer();
		query01.append("DELETE FROM SSO_AUPY ");

		PreparedStatement pstmt = conn.prepareStatement(query01.toString());
		pstmt.executeUpdate();
		pstmt.close();

		byte[] encWarnLimit = encrypt(DEK.getKey(), DEK.getIv(), "90".getBytes());
		byte[] encVerifyCycle = encrypt(DEK.getKey(), DEK.getIv(), "H".getBytes());
		byte[] encVerifyPoint = encrypt(DEK.getKey(), DEK.getIv(), "8".getBytes());

		StringBuffer query02 = new StringBuffer();
		query02.append("INSERT INTO SSO_AUPY(CODE, WARN_LIMIT, VERIFY_CYCLE, VERIFY_POINT) ")
			.append("VALUES('AUPY0001', ?, ?, ?) ");

		pstmt = conn.prepareStatement(query02.toString());
        pstmt.setString(1, new String(Hex.encode(encWarnLimit)));
        pstmt.setString(2, new String(Hex.encode(encVerifyCycle)));
        pstmt.setString(3, new String(Hex.encode(encVerifyPoint)));
		pstmt.executeUpdate();
		pstmt.close();

		StringBuffer query03 = new StringBuffer();
		query03.append("DELETE FROM SSO_MSVR ");

		pstmt = conn.prepareStatement(query03.toString());
		pstmt.executeUpdate();
		pstmt.close();

		StringBuffer query04 = new StringBuffer();
		query04.append("INSERT INTO SSO_MSVR(CODE) ")
			.append("VALUES('MSVR0001') ");

		pstmt = conn.prepareStatement(query04.toString());
		pstmt.executeUpdate();
		pstmt.close();

		StringBuffer query05 = new StringBuffer();
		query05.append("DELETE FROM SSO_MSND ");

		pstmt = conn.prepareStatement(query05.toString());
		pstmt.executeUpdate();
		pstmt.close();

		StringBuffer sbBody1 = new StringBuffer();
		sbBody1.append("$1 $2 아이디가 비밀번호 연속 오류로\n")
			.append("인증 기능 비활성화 상태로 변경되었습니다.\n")
			.append("확인 바랍니다.");

		byte[] encSubject = encrypt(DEK.getKey(), DEK.getIv(), "[SSO] 인증 기능 비활성화 알림".getBytes("UTF-8"));
		byte[] encBody = encrypt(DEK.getKey(), DEK.getIv(), sbBody1.toString().getBytes("UTF-8"));

		StringBuffer query06 = new StringBuffer();
		query06.append("INSERT INTO SSO_MSND(CODE, SUBJECT, BODY) ")
			.append("VALUES(?, ?, ?) ");

		pstmt = conn.prepareStatement(query06.toString());
		pstmt.setString(1, "MSND0000");
		pstmt.setString(2, new String(Hex.encode(encSubject)));
		pstmt.setString(3, new String(Hex.encode(encBody)));
		pstmt.executeUpdate();

		StringBuffer sbBody2 = new StringBuffer();
		sbBody2.append("SSO 무결성 검증 오류가 발생하였습니다.\n")
			.append("시스템 점검 바랍니다.");

		encSubject = encrypt(DEK.getKey(), DEK.getIv(), "[SSO] 무결성 검증 오류 발생".getBytes("UTF-8"));
		encBody = encrypt(DEK.getKey(), DEK.getIv(), sbBody2.toString().getBytes("UTF-8"));

		pstmt.setString(1, "MSND0001");
		pstmt.setString(2, new String(Hex.encode(encSubject)));
		pstmt.setString(3, new String(Hex.encode(encBody)));
		pstmt.executeUpdate();

		StringBuffer sbBody3 = new StringBuffer();
		sbBody3.append("SSO 암호모듈 자가시험 오류가 발생하였습니다.\n")
			.append("시스템 점검 바랍니다.");

		encSubject = encrypt(DEK.getKey(), DEK.getIv(), "[SSO] 암호모듈 자가시험 오류 발생".getBytes("UTF-8"));
		encBody = encrypt(DEK.getKey(), DEK.getIv(), sbBody3.toString().getBytes("UTF-8"));

		pstmt.setString(1, "MSND0002");
		pstmt.setString(2, new String(Hex.encode(encSubject)));
		pstmt.setString(3, new String(Hex.encode(encBody)));
		pstmt.executeUpdate();

		StringBuffer sbBody6 = new StringBuffer();
		sbBody6.append("SSO 프로세스 검증 오류가 발생하였습니다.\n")
			.append("시스템 점검 바랍니다.");

		encSubject = encrypt(DEK.getKey(), DEK.getIv(), "[SSO] 프로세스 검증 오류 발생".getBytes("UTF-8"));
		encBody = encrypt(DEK.getKey(), DEK.getIv(), sbBody6.toString().getBytes("UTF-8"));

		pstmt.setString(1, "MSND0005");
		pstmt.setString(2, new String(Hex.encode(encSubject)));
		pstmt.setString(3, new String(Hex.encode(encBody)));
		pstmt.executeUpdate();

		StringBuffer sbBody4 = new StringBuffer();
		sbBody4.append("SSO 감사정보 저장용량이 임계치를 초과하였습니다.\n")
			.append("시스템 점검 바랍니다.");

		encSubject = encrypt(DEK.getKey(), DEK.getIv(), "[SSO] 감사정보 저장용량 임계치 초과".getBytes("UTF-8"));
		encBody = encrypt(DEK.getKey(), DEK.getIv(), sbBody4.toString().getBytes("UTF-8"));

		pstmt.setString(1, "MSND0003");
		pstmt.setString(2, new String(Hex.encode(encSubject)));
		pstmt.setString(3, new String(Hex.encode(encBody)));
		pstmt.executeUpdate();

		StringBuffer sbBody5 = new StringBuffer();
		sbBody5.append("SSO 감사정보 저장소가 포화 상태입니다.\n")
			.append("시스템 점검 바랍니다.");

		encSubject = encrypt(DEK.getKey(), DEK.getIv(), "[SSO] 감사정보 저장소 포화상태 알림".getBytes("UTF-8"));
		encBody = encrypt(DEK.getKey(), DEK.getIv(), sbBody5.toString().getBytes("UTF-8"));

		pstmt.setString(1, "MSND0004");
		pstmt.setString(2, new String(Hex.encode(encSubject)));
		pstmt.setString(3, new String(Hex.encode(encBody)));
		pstmt.executeUpdate();
		pstmt.close();

		StringBuffer query07 = new StringBuffer();
		query07.append("DELETE FROM SSO_URPY ");

		pstmt = conn.prepareStatement(query07.toString());
		pstmt.executeUpdate();
		pstmt.close();

		byte[] encPwMismatchAllow = encrypt(DEK.getKey(), DEK.getIv(), "5".getBytes());
		byte[] encPwChangeWarn = encrypt(DEK.getKey(), DEK.getIv(), "7".getBytes());
		byte[] encPwValidate = encrypt(DEK.getKey(), DEK.getIv(), "90".getBytes());
		byte[] encSessionTime = encrypt(DEK.getKey(), DEK.getIv(), "10".getBytes());
		byte[] encPollingTime = encrypt(DEK.getKey(), DEK.getIv(), "30".getBytes());

		StringBuffer query08 = new StringBuffer();
		query08.append("INSERT INTO SSO_URPY(URPY_CODE, NAME, PW_MISMATCH_ALLOW, PW_CHANGE_WARN, PW_VALIDATE, SESSION_TIME, POLLING_TIME) ")
			.append("VALUES('URPY0001', '사용자보안정책', ?, ?, ?, ?, ?) ");

		pstmt = conn.prepareStatement(query08.toString());
        pstmt.setString(1, new String(Hex.encode(encPwMismatchAllow)));
        pstmt.setString(2, new String(Hex.encode(encPwChangeWarn)));
        pstmt.setString(3, new String(Hex.encode(encPwValidate)));
        pstmt.setString(4, new String(Hex.encode(encSessionTime)));
        pstmt.setString(5, new String(Hex.encode(encPollingTime)));
		pstmt.executeUpdate();
		pstmt.close();

		StringBuffer query09 = new StringBuffer();
		query09.append("DELETE FROM SSO_ADPY ");

		pstmt = conn.prepareStatement(query09.toString());
		pstmt.executeUpdate();
		pstmt.close();

		encPwMismatchAllow = encrypt(DEK.getKey(), DEK.getIv(), "5".getBytes());
		encSessionTime = encrypt(DEK.getKey(), DEK.getIv(), "10".getBytes());
		byte[] encLockTime = encrypt(DEK.getKey(), DEK.getIv(), "5".getBytes());
		byte[] encIpMaxCount = encrypt(DEK.getKey(), DEK.getIv(), "2".getBytes());

		StringBuffer query10 = new StringBuffer();
		query10.append("INSERT INTO SSO_ADPY(ADPY_CODE, NAME, PW_MISMATCH_ALLOW, SESSION_TIME, LOCK_TIME, IP_MAX_COUNT) ")
			.append("VALUES('ADPY0001', '관리자보안정책', ?, ?, ?, ?) ");

		pstmt = conn.prepareStatement(query10.toString());
        pstmt.setString(1, new String(Hex.encode(encPwMismatchAllow)));
        pstmt.setString(2, new String(Hex.encode(encSessionTime)));
        pstmt.setString(3, new String(Hex.encode(encLockTime)));
        pstmt.setString(4, new String(Hex.encode(encIpMaxCount)));
		pstmt.executeUpdate();
		pstmt.close();

		StringBuffer query11 = new StringBuffer();
		query11.append("DELETE FROM SSO_ADIP ");

		pstmt = conn.prepareStatement(query11.toString());
		pstmt.executeUpdate();
		pstmt.close();

		byte[] encIp = encrypt(DEK.getKey(), DEK.getIv(), adminIP.getBytes());

		StringBuffer query12 = new StringBuffer();
		query12.append("INSERT INTO SSO_ADIP(IP) ")
			.append("VALUES(?) ");

		pstmt = conn.prepareStatement(query12.toString());
        pstmt.setString(1, new String(Hex.encode(encIp)));
		pstmt.executeUpdate();
		pstmt.close();

		StringBuffer query13 = new StringBuffer();
		query13.append("DELETE FROM SSO_ADMN ");

		pstmt = conn.prepareStatement(query13.toString());
		pstmt.executeUpdate();
		pstmt.close();

		StringBuffer query14 = new StringBuffer();
		query14.append("INSERT INTO SSO_ADMN(ID, NAME, PASSWORD, PW_UPDATE_TIME, STATUS, ADMN_TYPE, ADPY_CODE, FIRST_YN) ")
			.append("VALUES('ssoadmin', '관리자', 'ff1f1f9b5ef6534d070d0c7345c8b4b121dd01e73cb94dee1780e798d79cc9be', TO_DATETIME('20220802123456','YYYYMMDDHH24MISS'), 'C', 'S', 'ADPY0001', 'Y') ");

		pstmt = conn.prepareStatement(query14.toString());
		pstmt.executeUpdate();
		pstmt.close();

		StringBuffer query15 = new StringBuffer();
		query15.append("DELETE FROM SSO_USER WHERE ID = 'sso' ");

		pstmt = conn.prepareStatement(query15.toString());
		pstmt.executeUpdate();
		pstmt.close();

		StringBuffer query16 = new StringBuffer();
		query16.append("INSERT INTO SSO_USER(ID, NAME, PASSWORD, PW_UPDATE_TIME, STATUS, URPY_CODE) ")
			.append("VALUES('sso', '홍길동', 'e77ef187bff54bd057b1957fb2967fd845030fe1a9a419f4216b2a5b53b6c174', TO_DATETIME('20220801100000','YYYYMMDDHH24MISS'), 'C', 'URPY0001') ");

		pstmt = conn.prepareStatement(query16.toString());
		pstmt.executeUpdate();
		pstmt.close();

		StringBuffer query17 = new StringBuffer();
		query17.append("DELETE FROM SSO_SCOPES ");

		pstmt = conn.prepareStatement(query17.toString());
		pstmt.executeUpdate();
		pstmt.close();

		StringBuffer query18 = new StringBuffer();
		query18.append("INSERT INTO SSO_SCOPES(SCOPE) VALUES(?)");

		pstmt = conn.prepareStatement(query18.toString());
        pstmt.setString(1, "openid");
		pstmt.executeUpdate();

        pstmt.setString(1, "profile");
		pstmt.executeUpdate();

        pstmt.setString(1, "email");
		pstmt.executeUpdate();

        pstmt.setString(1, "address");
		pstmt.executeUpdate();
		pstmt.close();

		StringBuffer query19 = new StringBuffer();
		query19.append("DELETE FROM SSO_CLIENT ");

		pstmt = conn.prepareStatement(query19.toString());
		pstmt.executeUpdate();
		pstmt.close();

		StringBuffer query20 = new StringBuffer();
		query20.append("DELETE FROM SSO_CLIENT_REDIRECT ");

		pstmt = conn.prepareStatement(query20.toString());
		pstmt.executeUpdate();
		pstmt.close();

		StringBuffer query21 = new StringBuffer();
		query21.append("DELETE FROM SSO_CLIENT_SCOPE ");

		pstmt = conn.prepareStatement(query21.toString());
		pstmt.executeUpdate();
		pstmt.close();

		if (!conn.getAutoCommit())
			conn.commit();

		conn.close();
	}

	// PostgreSQL
	public static void setInitializeDB_postgresql(String dbDriver, String dburl, String dbusr, String dbpwd, SSOSecretKey DEK, String adminIP) throws Exception
	{
		Class.forName(dbDriver);
		Connection conn = DriverManager.getConnection(dburl, dbusr, dbpwd);

		StringBuffer query01 = new StringBuffer();
		query01.append("DELETE FROM SSO_AUPY ");

		PreparedStatement pstmt = conn.prepareStatement(query01.toString());
		pstmt.executeUpdate();
		pstmt.close();

		byte[] encWarnLimit = encrypt(DEK.getKey(), DEK.getIv(), "90".getBytes());
		byte[] encVerifyCycle = encrypt(DEK.getKey(), DEK.getIv(), "H".getBytes());
		byte[] encVerifyPoint = encrypt(DEK.getKey(), DEK.getIv(), "8".getBytes());

		StringBuffer query02 = new StringBuffer();
		query02.append("INSERT INTO SSO_AUPY(CODE, WARN_LIMIT, VERIFY_CYCLE, VERIFY_POINT) ")
			.append("VALUES('AUPY0001', ?, ?, ?) ");

		pstmt = conn.prepareStatement(query02.toString());
        pstmt.setString(1, new String(Hex.encode(encWarnLimit)));
        pstmt.setString(2, new String(Hex.encode(encVerifyCycle)));
        pstmt.setString(3, new String(Hex.encode(encVerifyPoint)));
		pstmt.executeUpdate();
		pstmt.close();

		StringBuffer query03 = new StringBuffer();
		query03.append("DELETE FROM SSO_MSVR ");

		pstmt = conn.prepareStatement(query03.toString());
		pstmt.executeUpdate();
		pstmt.close();

		StringBuffer query04 = new StringBuffer();
		query04.append("INSERT INTO SSO_MSVR(CODE) ")
			.append("VALUES('MSVR0001') ");

		pstmt = conn.prepareStatement(query04.toString());
		pstmt.executeUpdate();
		pstmt.close();

		StringBuffer query05 = new StringBuffer();
		query05.append("DELETE FROM SSO_MSND ");

		pstmt = conn.prepareStatement(query05.toString());
		pstmt.executeUpdate();
		pstmt.close();

		StringBuffer sbBody1 = new StringBuffer();
		sbBody1.append("$1 $2 아이디가 비밀번호 연속 오류로\n")
			.append("인증 기능 비활성화 상태로 변경되었습니다.\n")
			.append("확인 바랍니다.");

		byte[] encSubject = encrypt(DEK.getKey(), DEK.getIv(), "[SSO] 인증 기능 비활성화 알림".getBytes("UTF-8"));
		byte[] encBody = encrypt(DEK.getKey(), DEK.getIv(), sbBody1.toString().getBytes("UTF-8"));

		StringBuffer query06 = new StringBuffer();
		query06.append("INSERT INTO SSO_MSND(CODE, SUBJECT, BODY) ")
			.append("VALUES(?, ?, ?) ");

		pstmt = conn.prepareStatement(query06.toString());
		pstmt.setString(1, "MSND0000");
		pstmt.setString(2, new String(Hex.encode(encSubject)));
		pstmt.setString(3, new String(Hex.encode(encBody)));
		pstmt.executeUpdate();

		StringBuffer sbBody2 = new StringBuffer();
		sbBody2.append("SSO 무결성 검증 오류가 발생하였습니다.\n")
			.append("시스템 점검 바랍니다.");

		encSubject = encrypt(DEK.getKey(), DEK.getIv(), "[SSO] 무결성 검증 오류 발생".getBytes("UTF-8"));
		encBody = encrypt(DEK.getKey(), DEK.getIv(), sbBody2.toString().getBytes("UTF-8"));

		pstmt.setString(1, "MSND0001");
		pstmt.setString(2, new String(Hex.encode(encSubject)));
		pstmt.setString(3, new String(Hex.encode(encBody)));
		pstmt.executeUpdate();

		StringBuffer sbBody3 = new StringBuffer();
		sbBody3.append("SSO 암호모듈 자가시험 오류가 발생하였습니다.\n")
			.append("시스템 점검 바랍니다.");

		encSubject = encrypt(DEK.getKey(), DEK.getIv(), "[SSO] 암호모듈 자가시험 오류 발생".getBytes("UTF-8"));
		encBody = encrypt(DEK.getKey(), DEK.getIv(), sbBody3.toString().getBytes("UTF-8"));

		pstmt.setString(1, "MSND0002");
		pstmt.setString(2, new String(Hex.encode(encSubject)));
		pstmt.setString(3, new String(Hex.encode(encBody)));
		pstmt.executeUpdate();

		StringBuffer sbBody6 = new StringBuffer();
		sbBody6.append("SSO 프로세스 검증 오류가 발생하였습니다.\n")
			.append("시스템 점검 바랍니다.");

		encSubject = encrypt(DEK.getKey(), DEK.getIv(), "[SSO] 프로세스 검증 오류 발생".getBytes("UTF-8"));
		encBody = encrypt(DEK.getKey(), DEK.getIv(), sbBody6.toString().getBytes("UTF-8"));

		pstmt.setString(1, "MSND0005");
		pstmt.setString(2, new String(Hex.encode(encSubject)));
		pstmt.setString(3, new String(Hex.encode(encBody)));
		pstmt.executeUpdate();

		StringBuffer sbBody4 = new StringBuffer();
		sbBody4.append("SSO 감사정보 저장용량이 임계치를 초과하였습니다.\n")
			.append("시스템 점검 바랍니다.");

		encSubject = encrypt(DEK.getKey(), DEK.getIv(), "[SSO] 감사정보 저장용량 임계치 초과".getBytes("UTF-8"));
		encBody = encrypt(DEK.getKey(), DEK.getIv(), sbBody4.toString().getBytes("UTF-8"));

		pstmt.setString(1, "MSND0003");
		pstmt.setString(2, new String(Hex.encode(encSubject)));
		pstmt.setString(3, new String(Hex.encode(encBody)));
		pstmt.executeUpdate();

		StringBuffer sbBody5 = new StringBuffer();
		sbBody5.append("SSO 감사정보 저장소가 포화 상태입니다.\n")
			.append("시스템 점검 바랍니다.");

		encSubject = encrypt(DEK.getKey(), DEK.getIv(), "[SSO] 감사정보 저장소 포화상태 알림".getBytes("UTF-8"));
		encBody = encrypt(DEK.getKey(), DEK.getIv(), sbBody5.toString().getBytes("UTF-8"));

		pstmt.setString(1, "MSND0004");
		pstmt.setString(2, new String(Hex.encode(encSubject)));
		pstmt.setString(3, new String(Hex.encode(encBody)));
		pstmt.executeUpdate();
		pstmt.close();

		StringBuffer query07 = new StringBuffer();
		query07.append("DELETE FROM SSO_URPY ");

		pstmt = conn.prepareStatement(query07.toString());
		pstmt.executeUpdate();
		pstmt.close();

		byte[] encPwMismatchAllow = encrypt(DEK.getKey(), DEK.getIv(), "5".getBytes());
		byte[] encPwChangeWarn = encrypt(DEK.getKey(), DEK.getIv(), "7".getBytes());
		byte[] encPwValidate = encrypt(DEK.getKey(), DEK.getIv(), "90".getBytes());
		byte[] encSessionTime = encrypt(DEK.getKey(), DEK.getIv(), "10".getBytes());
		byte[] encPollingTime = encrypt(DEK.getKey(), DEK.getIv(), "30".getBytes());

		StringBuffer query08 = new StringBuffer();
		query08.append("INSERT INTO SSO_URPY(URPY_CODE, NAME, PW_MISMATCH_ALLOW, PW_CHANGE_WARN, PW_VALIDATE, SESSION_TIME, POLLING_TIME) ")
			.append("VALUES('URPY0001', '사용자보안정책', ?, ?, ?, ?, ?) ");

		pstmt = conn.prepareStatement(query08.toString());
        pstmt.setString(1, new String(Hex.encode(encPwMismatchAllow)));
        pstmt.setString(2, new String(Hex.encode(encPwChangeWarn)));
        pstmt.setString(3, new String(Hex.encode(encPwValidate)));
        pstmt.setString(4, new String(Hex.encode(encSessionTime)));
        pstmt.setString(5, new String(Hex.encode(encPollingTime)));
		pstmt.executeUpdate();
		pstmt.close();

		StringBuffer query09 = new StringBuffer();
		query09.append("DELETE FROM SSO_ADPY ");

		pstmt = conn.prepareStatement(query09.toString());
		pstmt.executeUpdate();
		pstmt.close();

		encPwMismatchAllow = encrypt(DEK.getKey(), DEK.getIv(), "5".getBytes());
		encSessionTime = encrypt(DEK.getKey(), DEK.getIv(), "10".getBytes());
		byte[] encLockTime = encrypt(DEK.getKey(), DEK.getIv(), "5".getBytes());
		byte[] encIpMaxCount = encrypt(DEK.getKey(), DEK.getIv(), "2".getBytes());

		StringBuffer query10 = new StringBuffer();
		query10.append("INSERT INTO SSO_ADPY(ADPY_CODE, NAME, PW_MISMATCH_ALLOW, SESSION_TIME, LOCK_TIME, IP_MAX_COUNT) ")
			.append("VALUES('ADPY0001', '관리자보안정책', ?, ?, ?, ?) ");

		pstmt = conn.prepareStatement(query10.toString());
        pstmt.setString(1, new String(Hex.encode(encPwMismatchAllow)));
        pstmt.setString(2, new String(Hex.encode(encSessionTime)));
        pstmt.setString(3, new String(Hex.encode(encLockTime)));
        pstmt.setString(4, new String(Hex.encode(encIpMaxCount)));
		pstmt.executeUpdate();
		pstmt.close();

		StringBuffer query11 = new StringBuffer();
		query11.append("DELETE FROM SSO_ADIP ");

		pstmt = conn.prepareStatement(query11.toString());
		pstmt.executeUpdate();
		pstmt.close();

		byte[] encIp = encrypt(DEK.getKey(), DEK.getIv(), adminIP.getBytes());

		StringBuffer query12 = new StringBuffer();
		query12.append("INSERT INTO SSO_ADIP(IP) ")
			.append("VALUES(?) ");

		pstmt = conn.prepareStatement(query12.toString());
        pstmt.setString(1, new String(Hex.encode(encIp)));
		pstmt.executeUpdate();
		pstmt.close();

		StringBuffer query13 = new StringBuffer();
		query13.append("DELETE FROM SSO_ADMN ");

		pstmt = conn.prepareStatement(query13.toString());
		pstmt.executeUpdate();
		pstmt.close();

		StringBuffer query14 = new StringBuffer();
		query14.append("INSERT INTO SSO_ADMN(ID, NAME, PASSWORD, PW_UPDATE_TIME, STATUS, ADMN_TYPE, ADPY_CODE, FIRST_YN) ")
			.append("VALUES('ssoadmin', '관리자', 'ff1f1f9b5ef6534d070d0c7345c8b4b121dd01e73cb94dee1780e798d79cc9be', TO_TIMESTAMP('20220802123456','YYYYMMDDHH24MISS'), 'C', 'S', 'ADPY0001', 'Y') ");

		pstmt = conn.prepareStatement(query14.toString());
		pstmt.executeUpdate();
		pstmt.close();

		StringBuffer query15 = new StringBuffer();
		query15.append("DELETE FROM SSO_USER WHERE ID = 'sso' ");

		pstmt = conn.prepareStatement(query15.toString());
		pstmt.executeUpdate();
		pstmt.close();

		StringBuffer query16 = new StringBuffer();
		query16.append("INSERT INTO SSO_USER(ID, NAME, PASSWORD, PW_UPDATE_TIME, STATUS, URPY_CODE) ")
			.append("VALUES('sso', '홍길동', 'e77ef187bff54bd057b1957fb2967fd845030fe1a9a419f4216b2a5b53b6c174', TO_TIMESTAMP('20220801100000','YYYYMMDDHH24MISS'), 'C', 'URPY0001') ");

		pstmt = conn.prepareStatement(query16.toString());
		pstmt.executeUpdate();
		pstmt.close();

		StringBuffer query17 = new StringBuffer();
		query17.append("DELETE FROM SSO_SCOPES ");

		pstmt = conn.prepareStatement(query17.toString());
		pstmt.executeUpdate();
		pstmt.close();

		StringBuffer query18 = new StringBuffer();
		query18.append("INSERT INTO SSO_SCOPES(SCOPE) VALUES(?)");

		pstmt = conn.prepareStatement(query18.toString());
        pstmt.setString(1, "openid");
		pstmt.executeUpdate();

        pstmt.setString(1, "profile");
		pstmt.executeUpdate();

        pstmt.setString(1, "email");
		pstmt.executeUpdate();

        pstmt.setString(1, "address");
		pstmt.executeUpdate();
		pstmt.close();

		StringBuffer query19 = new StringBuffer();
		query19.append("DELETE FROM SSO_CLIENT ");

		pstmt = conn.prepareStatement(query19.toString());
		pstmt.executeUpdate();
		pstmt.close();

		StringBuffer query20 = new StringBuffer();
		query20.append("DELETE FROM SSO_CLIENT_REDIRECT ");

		pstmt = conn.prepareStatement(query20.toString());
		pstmt.executeUpdate();
		pstmt.close();

		StringBuffer query21 = new StringBuffer();
		query21.append("DELETE FROM SSO_CLIENT_SCOPE ");

		pstmt = conn.prepareStatement(query21.toString());
		pstmt.executeUpdate();
		pstmt.close();

		if (!conn.getAutoCommit())
			conn.commit();

		conn.close();
	}

	// MySQL
	public static void setInitializeDB_mysql(String dbDriver, String dburl, String dbusr, String dbpwd, SSOSecretKey DEK, String adminIP) throws Exception
	{
		Class.forName(dbDriver);
		Connection conn = DriverManager.getConnection(dburl, dbusr, dbpwd);

		StringBuffer query01 = new StringBuffer();
		query01.append("DELETE FROM SSO_AUPY ");

		PreparedStatement pstmt = conn.prepareStatement(query01.toString());
		pstmt.executeUpdate();
		pstmt.close();

		byte[] encWarnLimit = encrypt(DEK.getKey(), DEK.getIv(), "90".getBytes());
		byte[] encVerifyCycle = encrypt(DEK.getKey(), DEK.getIv(), "H".getBytes());
		byte[] encVerifyPoint = encrypt(DEK.getKey(), DEK.getIv(), "8".getBytes());

		StringBuffer query02 = new StringBuffer();
		query02.append("INSERT INTO SSO_AUPY(CODE, WARN_LIMIT, VERIFY_CYCLE, VERIFY_POINT) ")
			.append("VALUES('AUPY0001', ?, ?, ?) ");

		pstmt = conn.prepareStatement(query02.toString());
        pstmt.setString(1, new String(Hex.encode(encWarnLimit)));
        pstmt.setString(2, new String(Hex.encode(encVerifyCycle)));
        pstmt.setString(3, new String(Hex.encode(encVerifyPoint)));
		pstmt.executeUpdate();
		pstmt.close();

		StringBuffer query03 = new StringBuffer();
		query03.append("DELETE FROM SSO_MSVR ");

		pstmt = conn.prepareStatement(query03.toString());
		pstmt.executeUpdate();
		pstmt.close();

		StringBuffer query04 = new StringBuffer();
		query04.append("INSERT INTO SSO_MSVR(CODE) ")
			.append("VALUES('MSVR0001') ");

		pstmt = conn.prepareStatement(query04.toString());
		pstmt.executeUpdate();
		pstmt.close();

		StringBuffer query05 = new StringBuffer();
		query05.append("DELETE FROM SSO_MSND ");

		pstmt = conn.prepareStatement(query05.toString());
		pstmt.executeUpdate();
		pstmt.close();

		StringBuffer sbBody1 = new StringBuffer();
		sbBody1.append("$1 $2 아이디가 비밀번호 연속 오류로\n")
			.append("인증 기능 비활성화 상태로 변경되었습니다.\n")
			.append("확인 바랍니다.");

		byte[] encSubject = encrypt(DEK.getKey(), DEK.getIv(), "[SSO] 인증 기능 비활성화 알림".getBytes("UTF-8"));
		byte[] encBody = encrypt(DEK.getKey(), DEK.getIv(), sbBody1.toString().getBytes("UTF-8"));

		StringBuffer query06 = new StringBuffer();
		query06.append("INSERT INTO SSO_MSND(CODE, SUBJECT, BODY) ")
			.append("VALUES(?, ?, ?) ");

		pstmt = conn.prepareStatement(query06.toString());
		pstmt.setString(1, "MSND0000");
		pstmt.setString(2, new String(Hex.encode(encSubject)));
		pstmt.setString(3, new String(Hex.encode(encBody)));
		pstmt.executeUpdate();

		StringBuffer sbBody2 = new StringBuffer();
		sbBody2.append("SSO 무결성 검증 오류가 발생하였습니다.\n")
			.append("시스템 점검 바랍니다.");

		encSubject = encrypt(DEK.getKey(), DEK.getIv(), "[SSO] 무결성 검증 오류 발생".getBytes("UTF-8"));
		encBody = encrypt(DEK.getKey(), DEK.getIv(), sbBody2.toString().getBytes("UTF-8"));

		pstmt.setString(1, "MSND0001");
		pstmt.setString(2, new String(Hex.encode(encSubject)));
		pstmt.setString(3, new String(Hex.encode(encBody)));
		pstmt.executeUpdate();

		StringBuffer sbBody3 = new StringBuffer();
		sbBody3.append("SSO 암호모듈 자가시험 오류가 발생하였습니다.\n")
			.append("시스템 점검 바랍니다.");

		encSubject = encrypt(DEK.getKey(), DEK.getIv(), "[SSO] 암호모듈 자가시험 오류 발생".getBytes("UTF-8"));
		encBody = encrypt(DEK.getKey(), DEK.getIv(), sbBody3.toString().getBytes("UTF-8"));

		pstmt.setString(1, "MSND0002");
		pstmt.setString(2, new String(Hex.encode(encSubject)));
		pstmt.setString(3, new String(Hex.encode(encBody)));
		pstmt.executeUpdate();

		StringBuffer sbBody6 = new StringBuffer();
		sbBody6.append("SSO 프로세스 검증 오류가 발생하였습니다.\n")
			.append("시스템 점검 바랍니다.");

		encSubject = encrypt(DEK.getKey(), DEK.getIv(), "[SSO] 프로세스 검증 오류 발생".getBytes("UTF-8"));
		encBody = encrypt(DEK.getKey(), DEK.getIv(), sbBody6.toString().getBytes("UTF-8"));

		pstmt.setString(1, "MSND0005");
		pstmt.setString(2, new String(Hex.encode(encSubject)));
		pstmt.setString(3, new String(Hex.encode(encBody)));
		pstmt.executeUpdate();

		StringBuffer sbBody4 = new StringBuffer();
		sbBody4.append("SSO 감사정보 저장용량이 임계치를 초과하였습니다.\n")
			.append("시스템 점검 바랍니다.");

		encSubject = encrypt(DEK.getKey(), DEK.getIv(), "[SSO] 감사정보 저장용량 임계치 초과".getBytes("UTF-8"));
		encBody = encrypt(DEK.getKey(), DEK.getIv(), sbBody4.toString().getBytes("UTF-8"));

		pstmt.setString(1, "MSND0003");
		pstmt.setString(2, new String(Hex.encode(encSubject)));
		pstmt.setString(3, new String(Hex.encode(encBody)));
		pstmt.executeUpdate();

		StringBuffer sbBody5 = new StringBuffer();
		sbBody5.append("SSO 감사정보 저장소가 포화 상태입니다.\n")
			.append("시스템 점검 바랍니다.");

		encSubject = encrypt(DEK.getKey(), DEK.getIv(), "[SSO] 감사정보 저장소 포화상태 알림".getBytes("UTF-8"));
		encBody = encrypt(DEK.getKey(), DEK.getIv(), sbBody5.toString().getBytes("UTF-8"));

		pstmt.setString(1, "MSND0004");
		pstmt.setString(2, new String(Hex.encode(encSubject)));
		pstmt.setString(3, new String(Hex.encode(encBody)));
		pstmt.executeUpdate();
		pstmt.close();

		StringBuffer query07 = new StringBuffer();
		query07.append("DELETE FROM SSO_URPY ");

		pstmt = conn.prepareStatement(query07.toString());
		pstmt.executeUpdate();
		pstmt.close();

		byte[] encPwMismatchAllow = encrypt(DEK.getKey(), DEK.getIv(), "5".getBytes());
		byte[] encPwChangeWarn = encrypt(DEK.getKey(), DEK.getIv(), "7".getBytes());
		byte[] encPwValidate = encrypt(DEK.getKey(), DEK.getIv(), "90".getBytes());
		byte[] encSessionTime = encrypt(DEK.getKey(), DEK.getIv(), "10".getBytes());
		byte[] encPollingTime = encrypt(DEK.getKey(), DEK.getIv(), "30".getBytes());

		StringBuffer query08 = new StringBuffer();
		query08.append("INSERT INTO SSO_URPY(URPY_CODE, NAME, PW_MISMATCH_ALLOW, PW_CHANGE_WARN, PW_VALIDATE, SESSION_TIME, POLLING_TIME) ")
			.append("VALUES('URPY0001', '사용자보안정책', ?, ?, ?, ?, ?) ");

		pstmt = conn.prepareStatement(query08.toString());
        pstmt.setString(1, new String(Hex.encode(encPwMismatchAllow)));
        pstmt.setString(2, new String(Hex.encode(encPwChangeWarn)));
        pstmt.setString(3, new String(Hex.encode(encPwValidate)));
        pstmt.setString(4, new String(Hex.encode(encSessionTime)));
        pstmt.setString(5, new String(Hex.encode(encPollingTime)));
		pstmt.executeUpdate();
		pstmt.close();

		StringBuffer query09 = new StringBuffer();
		query09.append("DELETE FROM SSO_ADPY ");

		pstmt = conn.prepareStatement(query09.toString());
		pstmt.executeUpdate();
		pstmt.close();

		encPwMismatchAllow = encrypt(DEK.getKey(), DEK.getIv(), "5".getBytes());
		encSessionTime = encrypt(DEK.getKey(), DEK.getIv(), "10".getBytes());
		byte[] encLockTime = encrypt(DEK.getKey(), DEK.getIv(), "5".getBytes());
		byte[] encIpMaxCount = encrypt(DEK.getKey(), DEK.getIv(), "2".getBytes());

		StringBuffer query10 = new StringBuffer();
		query10.append("INSERT INTO SSO_ADPY(ADPY_CODE, NAME, PW_MISMATCH_ALLOW, SESSION_TIME, LOCK_TIME, IP_MAX_COUNT) ")
			.append("VALUES('ADPY0001', '관리자보안정책', ?, ?, ?, ?) ");

		pstmt = conn.prepareStatement(query10.toString());
        pstmt.setString(1, new String(Hex.encode(encPwMismatchAllow)));
        pstmt.setString(2, new String(Hex.encode(encSessionTime)));
        pstmt.setString(3, new String(Hex.encode(encLockTime)));
        pstmt.setString(4, new String(Hex.encode(encIpMaxCount)));
		pstmt.executeUpdate();
		pstmt.close();

		StringBuffer query11 = new StringBuffer();
		query11.append("DELETE FROM SSO_ADIP ");

		pstmt = conn.prepareStatement(query11.toString());
		pstmt.executeUpdate();
		pstmt.close();

		byte[] encIp = encrypt(DEK.getKey(), DEK.getIv(), adminIP.getBytes());

		StringBuffer query12 = new StringBuffer();
		query12.append("INSERT INTO SSO_ADIP(IP) ")
			.append("VALUES(?) ");

		pstmt = conn.prepareStatement(query12.toString());
        pstmt.setString(1, new String(Hex.encode(encIp)));
		pstmt.executeUpdate();
		pstmt.close();

		StringBuffer query13 = new StringBuffer();
		query13.append("DELETE FROM SSO_ADMN ");

		pstmt = conn.prepareStatement(query13.toString());
		pstmt.executeUpdate();
		pstmt.close();

		StringBuffer query14 = new StringBuffer();
		query14.append("INSERT INTO SSO_ADMN(ID, NAME, PASSWORD, PW_UPDATE_TIME, STATUS, ADMN_TYPE, ADPY_CODE, FIRST_YN) ")
			.append("VALUES('ssoadmin', '관리자', 'ff1f1f9b5ef6534d070d0c7345c8b4b121dd01e73cb94dee1780e798d79cc9be', STR_TO_DATE('20220802123456','%Y%m%d%H%i%s'), 'C', 'S', 'ADPY0001', 'Y') ");

		pstmt = conn.prepareStatement(query14.toString());
		pstmt.executeUpdate();
		pstmt.close();

		StringBuffer query15 = new StringBuffer();
		query15.append("DELETE FROM SSO_USER WHERE ID = 'sso' ");

		pstmt = conn.prepareStatement(query15.toString());
		pstmt.executeUpdate();
		pstmt.close();

		StringBuffer query16 = new StringBuffer();
		query16.append("INSERT INTO SSO_USER(ID, NAME, PASSWORD, PW_UPDATE_TIME, STATUS, URPY_CODE) ")
			.append("VALUES('sso', '홍길동', 'e77ef187bff54bd057b1957fb2967fd845030fe1a9a419f4216b2a5b53b6c174', STR_TO_DATE('20220801100000','%Y%m%d%H%i%s'), 'C', 'URPY0001') ");

		pstmt = conn.prepareStatement(query16.toString());
		pstmt.executeUpdate();
		pstmt.close();

		StringBuffer query17 = new StringBuffer();
		query17.append("DELETE FROM SSO_SCOPES ");

		pstmt = conn.prepareStatement(query17.toString());
		pstmt.executeUpdate();
		pstmt.close();

		StringBuffer query18 = new StringBuffer();
		query18.append("INSERT INTO SSO_SCOPES(SCOPE) VALUES(?)");

		pstmt = conn.prepareStatement(query18.toString());
        pstmt.setString(1, "openid");
		pstmt.executeUpdate();

        pstmt.setString(1, "profile");
		pstmt.executeUpdate();

        pstmt.setString(1, "email");
		pstmt.executeUpdate();

        pstmt.setString(1, "address");
		pstmt.executeUpdate();
		pstmt.close();

		StringBuffer query19 = new StringBuffer();
		query19.append("DELETE FROM SSO_CLIENT ");

		pstmt = conn.prepareStatement(query19.toString());
		pstmt.executeUpdate();
		pstmt.close();

		StringBuffer query20 = new StringBuffer();
		query20.append("DELETE FROM SSO_CLIENT_REDIRECT ");

		pstmt = conn.prepareStatement(query20.toString());
		pstmt.executeUpdate();
		pstmt.close();

		StringBuffer query21 = new StringBuffer();
		query21.append("DELETE FROM SSO_CLIENT_SCOPE ");

		pstmt = conn.prepareStatement(query21.toString());
		pstmt.executeUpdate();
		pstmt.close();

		if (!conn.getAutoCommit())
			conn.commit();

		conn.close();
	}

	// SQL Server
	public static void setInitializeDB_sqlserver(String dbDriver, String dburl, String dbusr, String dbpwd, SSOSecretKey DEK, String adminIP) throws Exception
	{
		Class.forName(dbDriver);
		Connection conn = DriverManager.getConnection(dburl, dbusr, dbpwd);

		StringBuffer query01 = new StringBuffer();
		query01.append("DELETE FROM SSO_AUPY ");

		PreparedStatement pstmt = conn.prepareStatement(query01.toString());
		pstmt.executeUpdate();
		pstmt.close();

		byte[] encWarnLimit = encrypt(DEK.getKey(), DEK.getIv(), "90".getBytes());
		byte[] encVerifyCycle = encrypt(DEK.getKey(), DEK.getIv(), "H".getBytes());
		byte[] encVerifyPoint = encrypt(DEK.getKey(), DEK.getIv(), "8".getBytes());

		StringBuffer query02 = new StringBuffer();
		query02.append("INSERT INTO SSO_AUPY(CODE, WARN_LIMIT, VERIFY_CYCLE, VERIFY_POINT) ")
			.append("VALUES('AUPY0001', ?, ?, ?) ");

		pstmt = conn.prepareStatement(query02.toString());
        pstmt.setString(1, new String(Hex.encode(encWarnLimit)));
        pstmt.setString(2, new String(Hex.encode(encVerifyCycle)));
        pstmt.setString(3, new String(Hex.encode(encVerifyPoint)));
		pstmt.executeUpdate();
		pstmt.close();

		StringBuffer query03 = new StringBuffer();
		query03.append("DELETE FROM SSO_MSVR ");

		pstmt = conn.prepareStatement(query03.toString());
		pstmt.executeUpdate();
		pstmt.close();

		StringBuffer query04 = new StringBuffer();
		query04.append("INSERT INTO SSO_MSVR(CODE) ")
			.append("VALUES('MSVR0001') ");

		pstmt = conn.prepareStatement(query04.toString());
		pstmt.executeUpdate();
		pstmt.close();

		StringBuffer query05 = new StringBuffer();
		query05.append("DELETE FROM SSO_MSND ");

		pstmt = conn.prepareStatement(query05.toString());
		pstmt.executeUpdate();
		pstmt.close();

		StringBuffer sbBody1 = new StringBuffer();
		sbBody1.append("$1 $2 아이디가 비밀번호 연속 오류로\n")
			.append("인증 기능 비활성화 상태로 변경되었습니다.\n")
			.append("확인 바랍니다.");

		byte[] encSubject = encrypt(DEK.getKey(), DEK.getIv(), "[SSO] 인증 기능 비활성화 알림".getBytes("UTF-8"));
		byte[] encBody = encrypt(DEK.getKey(), DEK.getIv(), sbBody1.toString().getBytes("UTF-8"));

		StringBuffer query06 = new StringBuffer();
		query06.append("INSERT INTO SSO_MSND(CODE, SUBJECT, BODY) ")
			.append("VALUES(?, ?, ?) ");

		pstmt = conn.prepareStatement(query06.toString());
		pstmt.setString(1, "MSND0000");
		pstmt.setString(2, new String(Hex.encode(encSubject)));
		pstmt.setString(3, new String(Hex.encode(encBody)));
		pstmt.executeUpdate();

		StringBuffer sbBody2 = new StringBuffer();
		sbBody2.append("SSO 무결성 검증 오류가 발생하였습니다.\n")
			.append("시스템 점검 바랍니다.");

		encSubject = encrypt(DEK.getKey(), DEK.getIv(), "[SSO] 무결성 검증 오류 발생".getBytes("UTF-8"));
		encBody = encrypt(DEK.getKey(), DEK.getIv(), sbBody2.toString().getBytes("UTF-8"));

		pstmt.setString(1, "MSND0001");
		pstmt.setString(2, new String(Hex.encode(encSubject)));
		pstmt.setString(3, new String(Hex.encode(encBody)));
		pstmt.executeUpdate();

		StringBuffer sbBody3 = new StringBuffer();
		sbBody3.append("SSO 암호모듈 자가시험 오류가 발생하였습니다.\n")
			.append("시스템 점검 바랍니다.");

		encSubject = encrypt(DEK.getKey(), DEK.getIv(), "[SSO] 암호모듈 자가시험 오류 발생".getBytes("UTF-8"));
		encBody = encrypt(DEK.getKey(), DEK.getIv(), sbBody3.toString().getBytes("UTF-8"));

		pstmt.setString(1, "MSND0002");
		pstmt.setString(2, new String(Hex.encode(encSubject)));
		pstmt.setString(3, new String(Hex.encode(encBody)));
		pstmt.executeUpdate();

		StringBuffer sbBody6 = new StringBuffer();
		sbBody6.append("SSO 프로세스 검증 오류가 발생하였습니다.\n")
			.append("시스템 점검 바랍니다.");

		encSubject = encrypt(DEK.getKey(), DEK.getIv(), "[SSO] 프로세스 검증 오류 발생".getBytes("UTF-8"));
		encBody = encrypt(DEK.getKey(), DEK.getIv(), sbBody6.toString().getBytes("UTF-8"));

		pstmt.setString(1, "MSND0005");
		pstmt.setString(2, new String(Hex.encode(encSubject)));
		pstmt.setString(3, new String(Hex.encode(encBody)));
		pstmt.executeUpdate();

		StringBuffer sbBody4 = new StringBuffer();
		sbBody4.append("SSO 감사정보 저장용량이 임계치를 초과하였습니다.\n")
			.append("시스템 점검 바랍니다.");

		encSubject = encrypt(DEK.getKey(), DEK.getIv(), "[SSO] 감사정보 저장용량 임계치 초과".getBytes("UTF-8"));
		encBody = encrypt(DEK.getKey(), DEK.getIv(), sbBody4.toString().getBytes("UTF-8"));

		pstmt.setString(1, "MSND0003");
		pstmt.setString(2, new String(Hex.encode(encSubject)));
		pstmt.setString(3, new String(Hex.encode(encBody)));
		pstmt.executeUpdate();

		StringBuffer sbBody5 = new StringBuffer();
		sbBody5.append("SSO 감사정보 저장소가 포화 상태입니다.\n")
			.append("시스템 점검 바랍니다.");

		encSubject = encrypt(DEK.getKey(), DEK.getIv(), "[SSO] 감사정보 저장소 포화상태 알림".getBytes("UTF-8"));
		encBody = encrypt(DEK.getKey(), DEK.getIv(), sbBody5.toString().getBytes("UTF-8"));

		pstmt.setString(1, "MSND0004");
		pstmt.setString(2, new String(Hex.encode(encSubject)));
		pstmt.setString(3, new String(Hex.encode(encBody)));
		pstmt.executeUpdate();
		pstmt.close();

		StringBuffer query07 = new StringBuffer();
		query07.append("DELETE FROM SSO_URPY ");

		pstmt = conn.prepareStatement(query07.toString());
		pstmt.executeUpdate();
		pstmt.close();

		byte[] encPwMismatchAllow = encrypt(DEK.getKey(), DEK.getIv(), "5".getBytes());
		byte[] encPwChangeWarn = encrypt(DEK.getKey(), DEK.getIv(), "7".getBytes());
		byte[] encPwValidate = encrypt(DEK.getKey(), DEK.getIv(), "90".getBytes());
		byte[] encSessionTime = encrypt(DEK.getKey(), DEK.getIv(), "10".getBytes());
		byte[] encPollingTime = encrypt(DEK.getKey(), DEK.getIv(), "30".getBytes());

		StringBuffer query08 = new StringBuffer();
		query08.append("INSERT INTO SSO_URPY(URPY_CODE, NAME, PW_MISMATCH_ALLOW, PW_CHANGE_WARN, PW_VALIDATE, SESSION_TIME, POLLING_TIME) ")
			.append("VALUES('URPY0001', '사용자보안정책', ?, ?, ?, ?, ?) ");

		pstmt = conn.prepareStatement(query08.toString());
        pstmt.setString(1, new String(Hex.encode(encPwMismatchAllow)));
        pstmt.setString(2, new String(Hex.encode(encPwChangeWarn)));
        pstmt.setString(3, new String(Hex.encode(encPwValidate)));
        pstmt.setString(4, new String(Hex.encode(encSessionTime)));
        pstmt.setString(5, new String(Hex.encode(encPollingTime)));
		pstmt.executeUpdate();
		pstmt.close();

		StringBuffer query09 = new StringBuffer();
		query09.append("DELETE FROM SSO_ADPY ");

		pstmt = conn.prepareStatement(query09.toString());
		pstmt.executeUpdate();
		pstmt.close();

		encPwMismatchAllow = encrypt(DEK.getKey(), DEK.getIv(), "5".getBytes());
		encSessionTime = encrypt(DEK.getKey(), DEK.getIv(), "10".getBytes());
		byte[] encLockTime = encrypt(DEK.getKey(), DEK.getIv(), "5".getBytes());
		byte[] encIpMaxCount = encrypt(DEK.getKey(), DEK.getIv(), "2".getBytes());

		StringBuffer query10 = new StringBuffer();
		query10.append("INSERT INTO SSO_ADPY(ADPY_CODE, NAME, PW_MISMATCH_ALLOW, SESSION_TIME, LOCK_TIME, IP_MAX_COUNT) ")
			.append("VALUES('ADPY0001', '관리자보안정책', ?, ?, ?, ?) ");

		pstmt = conn.prepareStatement(query10.toString());
        pstmt.setString(1, new String(Hex.encode(encPwMismatchAllow)));
        pstmt.setString(2, new String(Hex.encode(encSessionTime)));
        pstmt.setString(3, new String(Hex.encode(encLockTime)));
        pstmt.setString(4, new String(Hex.encode(encIpMaxCount)));
		pstmt.executeUpdate();
		pstmt.close();

		StringBuffer query11 = new StringBuffer();
		query11.append("DELETE FROM SSO_ADIP ");

		pstmt = conn.prepareStatement(query11.toString());
		pstmt.executeUpdate();
		pstmt.close();

		byte[] encIp = encrypt(DEK.getKey(), DEK.getIv(), adminIP.getBytes());

		StringBuffer query12 = new StringBuffer();
		query12.append("INSERT INTO SSO_ADIP(IP) ")
			.append("VALUES(?) ");

		pstmt = conn.prepareStatement(query12.toString());
        pstmt.setString(1, new String(Hex.encode(encIp)));
		pstmt.executeUpdate();
		pstmt.close();

		StringBuffer query13 = new StringBuffer();
		query13.append("DELETE FROM SSO_ADMN ");

		pstmt = conn.prepareStatement(query13.toString());
		pstmt.executeUpdate();
		pstmt.close();

		StringBuffer query14 = new StringBuffer();
		query14.append("INSERT INTO SSO_ADMN(ID, NAME, PASSWORD, PW_UPDATE_TIME, STATUS, ADMN_TYPE, ADPY_CODE, FIRST_YN) ")
			.append("VALUES('ssoadmin', '관리자', 'ff1f1f9b5ef6534d070d0c7345c8b4b121dd01e73cb94dee1780e798d79cc9be', convert(datetime, '2022-08-02 12:34:56', 120), 'C', 'S', 'ADPY0001', 'Y') ");

		pstmt = conn.prepareStatement(query14.toString());
		pstmt.executeUpdate();
		pstmt.close();

		StringBuffer query15 = new StringBuffer();
		query15.append("DELETE FROM SSO_USER WHERE ID = 'sso' ");

		pstmt = conn.prepareStatement(query15.toString());
		pstmt.executeUpdate();
		pstmt.close();

		StringBuffer query16 = new StringBuffer();
		query16.append("INSERT INTO SSO_USER(ID, NAME, PASSWORD, PW_UPDATE_TIME, STATUS, URPY_CODE) ")
			.append("VALUES('sso', '홍길동', 'e77ef187bff54bd057b1957fb2967fd845030fe1a9a419f4216b2a5b53b6c174', convert(datetime, '2022-08-01 10:00:00', 120), 'C', 'URPY0001') ");

		pstmt = conn.prepareStatement(query16.toString());
		pstmt.executeUpdate();
		pstmt.close();

		StringBuffer query17 = new StringBuffer();
		query17.append("DELETE FROM SSO_SCOPES ");

		pstmt = conn.prepareStatement(query17.toString());
		pstmt.executeUpdate();
		pstmt.close();

		StringBuffer query18 = new StringBuffer();
		query18.append("INSERT INTO SSO_SCOPES(SCOPE) VALUES(?)");

		pstmt = conn.prepareStatement(query18.toString());
        pstmt.setString(1, "openid");
		pstmt.executeUpdate();

        pstmt.setString(1, "profile");
		pstmt.executeUpdate();

        pstmt.setString(1, "email");
		pstmt.executeUpdate();

        pstmt.setString(1, "address");
		pstmt.executeUpdate();
		pstmt.close();

		StringBuffer query19 = new StringBuffer();
		query19.append("DELETE FROM SSO_CLIENT ");

		pstmt = conn.prepareStatement(query19.toString());
		pstmt.executeUpdate();
		pstmt.close();

		StringBuffer query20 = new StringBuffer();
		query20.append("DELETE FROM SSO_CLIENT_REDIRECT ");

		pstmt = conn.prepareStatement(query20.toString());
		pstmt.executeUpdate();
		pstmt.close();

		StringBuffer query21 = new StringBuffer();
		query21.append("DELETE FROM SSO_CLIENT_SCOPE ");

		pstmt = conn.prepareStatement(query21.toString());
		pstmt.executeUpdate();
		pstmt.close();

		if (!conn.getAutoCommit())
			conn.commit();

		conn.close();
	}

	public static void setInitializeDB_tibero(String dbDriver, String dburl, String dbusr, String dbpwd, SSOSecretKey DEK, String adminIP) throws Exception
	{
		Class.forName(dbDriver);
		Connection conn = DriverManager.getConnection(dburl, dbusr, dbpwd);

		StringBuffer query01 = new StringBuffer();
		query01.append("DELETE FROM SSO_AUPY ");

		PreparedStatement pstmt = conn.prepareStatement(query01.toString());
		pstmt.executeUpdate();
		pstmt.close();

		byte[] encWarnLimit = encrypt(DEK.getKey(), DEK.getIv(), "90".getBytes());
		byte[] encVerifyCycle = encrypt(DEK.getKey(), DEK.getIv(), "H".getBytes());
		byte[] encVerifyPoint = encrypt(DEK.getKey(), DEK.getIv(), "8".getBytes());

		StringBuffer query02 = new StringBuffer();
		query02.append("INSERT INTO SSO_AUPY(CODE, WARN_LIMIT, VERIFY_CYCLE, VERIFY_POINT) ")
			.append("VALUES('AUPY0001', ?, ?, ?) ");

		pstmt = conn.prepareStatement(query02.toString());
        pstmt.setString(1, new String(Hex.encode(encWarnLimit)));
        pstmt.setString(2, new String(Hex.encode(encVerifyCycle)));
        pstmt.setString(3, new String(Hex.encode(encVerifyPoint)));
		pstmt.executeUpdate();
		pstmt.close();

		StringBuffer query03 = new StringBuffer();
		query03.append("DELETE FROM SSO_MSVR ");

		pstmt = conn.prepareStatement(query03.toString());
		pstmt.executeUpdate();
		pstmt.close();

		StringBuffer query04 = new StringBuffer();
		query04.append("INSERT INTO SSO_MSVR(CODE) ")
			.append("VALUES('MSVR0001') ");

		pstmt = conn.prepareStatement(query04.toString());
		pstmt.executeUpdate();
		pstmt.close();

		StringBuffer query05 = new StringBuffer();
		query05.append("DELETE FROM SSO_MSND ");

		pstmt = conn.prepareStatement(query05.toString());
		pstmt.executeUpdate();
		pstmt.close();

		StringBuffer sbBody1 = new StringBuffer();
		sbBody1.append("$1 $2 아이디가 비밀번호 연속 오류로\n")
			.append("인증 기능 비활성화 상태로 변경되었습니다.\n")
			.append("확인 바랍니다.");

		byte[] encSubject = encrypt(DEK.getKey(), DEK.getIv(), "[SSO] 인증 기능 비활성화 알림".getBytes("UTF-8"));
		byte[] encBody = encrypt(DEK.getKey(), DEK.getIv(), sbBody1.toString().getBytes("UTF-8"));

		StringBuffer query06 = new StringBuffer();
		query06.append("INSERT INTO SSO_MSND(CODE, SUBJECT, BODY) ")
			.append("VALUES(?, ?, ?) ");

		pstmt = conn.prepareStatement(query06.toString());
		pstmt.setString(1, "MSND0000");
		pstmt.setString(2, new String(Hex.encode(encSubject)));
		pstmt.setString(3, new String(Hex.encode(encBody)));
		pstmt.executeUpdate();

		StringBuffer sbBody2 = new StringBuffer();
		sbBody2.append("SSO 무결성 검증 오류가 발생하였습니다.\n")
			.append("시스템 점검 바랍니다.");

		encSubject = encrypt(DEK.getKey(), DEK.getIv(), "[SSO] 무결성 검증 오류 발생".getBytes("UTF-8"));
		encBody = encrypt(DEK.getKey(), DEK.getIv(), sbBody2.toString().getBytes("UTF-8"));

		pstmt.setString(1, "MSND0001");
		pstmt.setString(2, new String(Hex.encode(encSubject)));
		pstmt.setString(3, new String(Hex.encode(encBody)));
		pstmt.executeUpdate();

		StringBuffer sbBody3 = new StringBuffer();
		sbBody3.append("SSO 암호모듈 자가시험 오류가 발생하였습니다.\n")
			.append("시스템 점검 바랍니다.");

		encSubject = encrypt(DEK.getKey(), DEK.getIv(), "[SSO] 암호모듈 자가시험 오류 발생".getBytes("UTF-8"));
		encBody = encrypt(DEK.getKey(), DEK.getIv(), sbBody3.toString().getBytes("UTF-8"));

		pstmt.setString(1, "MSND0002");
		pstmt.setString(2, new String(Hex.encode(encSubject)));
		pstmt.setString(3, new String(Hex.encode(encBody)));
		pstmt.executeUpdate();

		StringBuffer sbBody6 = new StringBuffer();
		sbBody6.append("SSO 프로세스 검증 오류가 발생하였습니다.\n")
			.append("시스템 점검 바랍니다.");

		encSubject = encrypt(DEK.getKey(), DEK.getIv(), "[SSO] 프로세스 검증 오류 발생".getBytes("UTF-8"));
		encBody = encrypt(DEK.getKey(), DEK.getIv(), sbBody6.toString().getBytes("UTF-8"));

		pstmt.setString(1, "MSND0005");
		pstmt.setString(2, new String(Hex.encode(encSubject)));
		pstmt.setString(3, new String(Hex.encode(encBody)));
		pstmt.executeUpdate();

		StringBuffer sbBody4 = new StringBuffer();
		sbBody4.append("SSO 감사정보 저장용량이 임계치를 초과하였습니다.\n")
			.append("시스템 점검 바랍니다.");

		encSubject = encrypt(DEK.getKey(), DEK.getIv(), "[SSO] 감사정보 저장용량 임계치 초과".getBytes("UTF-8"));
		encBody = encrypt(DEK.getKey(), DEK.getIv(), sbBody4.toString().getBytes("UTF-8"));

		pstmt.setString(1, "MSND0003");
		pstmt.setString(2, new String(Hex.encode(encSubject)));
		pstmt.setString(3, new String(Hex.encode(encBody)));
		pstmt.executeUpdate();

		StringBuffer sbBody5 = new StringBuffer();
		sbBody5.append("SSO 감사정보 저장소가 포화 상태입니다.\n")
			.append("시스템 점검 바랍니다.");

		encSubject = encrypt(DEK.getKey(), DEK.getIv(), "[SSO] 감사정보 저장소 포화상태 알림".getBytes("UTF-8"));
		encBody = encrypt(DEK.getKey(), DEK.getIv(), sbBody5.toString().getBytes("UTF-8"));

		pstmt.setString(1, "MSND0004");
		pstmt.setString(2, new String(Hex.encode(encSubject)));
		pstmt.setString(3, new String(Hex.encode(encBody)));
		pstmt.executeUpdate();
		pstmt.close();

		StringBuffer query07 = new StringBuffer();
		query07.append("DELETE FROM SSO_URPY ");

		pstmt = conn.prepareStatement(query07.toString());
		pstmt.executeUpdate();
		pstmt.close();

		byte[] encPwMismatchAllow = encrypt(DEK.getKey(), DEK.getIv(), "5".getBytes());
		byte[] encPwChangeWarn = encrypt(DEK.getKey(), DEK.getIv(), "7".getBytes());
		byte[] encPwValidate = encrypt(DEK.getKey(), DEK.getIv(), "90".getBytes());
		byte[] encSessionTime = encrypt(DEK.getKey(), DEK.getIv(), "10".getBytes());
		byte[] encPollingTime = encrypt(DEK.getKey(), DEK.getIv(), "30".getBytes());

		StringBuffer query08 = new StringBuffer();
		query08.append("INSERT INTO SSO_URPY(URPY_CODE, NAME, PW_MISMATCH_ALLOW, PW_CHANGE_WARN, PW_VALIDATE, SESSION_TIME, POLLING_TIME) ")
			.append("VALUES('URPY0001', '사용자보안정책', ?, ?, ?, ?, ?) ");

		pstmt = conn.prepareStatement(query08.toString());
        pstmt.setString(1, new String(Hex.encode(encPwMismatchAllow)));
        pstmt.setString(2, new String(Hex.encode(encPwChangeWarn)));
        pstmt.setString(3, new String(Hex.encode(encPwValidate)));
        pstmt.setString(4, new String(Hex.encode(encSessionTime)));
        pstmt.setString(5, new String(Hex.encode(encPollingTime)));
		pstmt.executeUpdate();
		pstmt.close();

		StringBuffer query09 = new StringBuffer();
		query09.append("DELETE FROM SSO_ADPY ");

		pstmt = conn.prepareStatement(query09.toString());
		pstmt.executeUpdate();
		pstmt.close();

		encPwMismatchAllow = encrypt(DEK.getKey(), DEK.getIv(), "5".getBytes());
		encSessionTime = encrypt(DEK.getKey(), DEK.getIv(), "10".getBytes());
		byte[] encLockTime = encrypt(DEK.getKey(), DEK.getIv(), "5".getBytes());
		byte[] encIpMaxCount = encrypt(DEK.getKey(), DEK.getIv(), "2".getBytes());

		StringBuffer query10 = new StringBuffer();
		query10.append("INSERT INTO SSO_ADPY(ADPY_CODE, NAME, PW_MISMATCH_ALLOW, SESSION_TIME, LOCK_TIME, IP_MAX_COUNT) ")
			.append("VALUES('ADPY0001', '관리자보안정책', ?, ?, ?, ?) ");

		pstmt = conn.prepareStatement(query10.toString());
        pstmt.setString(1, new String(Hex.encode(encPwMismatchAllow)));
        pstmt.setString(2, new String(Hex.encode(encSessionTime)));
        pstmt.setString(3, new String(Hex.encode(encLockTime)));
        pstmt.setString(4, new String(Hex.encode(encIpMaxCount)));
		pstmt.executeUpdate();
		pstmt.close();

		StringBuffer query11 = new StringBuffer();
		query11.append("DELETE FROM SSO_ADIP ");

		pstmt = conn.prepareStatement(query11.toString());
		pstmt.executeUpdate();
		pstmt.close();

		byte[] encIp = encrypt(DEK.getKey(), DEK.getIv(), adminIP.getBytes());

		StringBuffer query12 = new StringBuffer();
		query12.append("INSERT INTO SSO_ADIP(IP) ")
			.append("VALUES(?) ");

		pstmt = conn.prepareStatement(query12.toString());
        pstmt.setString(1, new String(Hex.encode(encIp)));
		pstmt.executeUpdate();
		pstmt.close();

		StringBuffer query13 = new StringBuffer();
		query13.append("DELETE FROM SSO_ADMN ");

		pstmt = conn.prepareStatement(query13.toString());
		pstmt.executeUpdate();
		pstmt.close();

		StringBuffer query14 = new StringBuffer();
		query14.append("INSERT INTO SSO_ADMN(ID, NAME, PASSWORD, PW_UPDATE_TIME, STATUS, ADMN_TYPE, ADPY_CODE, FIRST_YN) ")
			.append("VALUES('ssoadmin', '관리자', 'ff1f1f9b5ef6534d070d0c7345c8b4b121dd01e73cb94dee1780e798d79cc9be', TO_DATE('20220802123456','YYYYMMDDHH24MISS'), 'C', 'S', 'ADPY0001', 'Y') ");

		pstmt = conn.prepareStatement(query14.toString());
		pstmt.executeUpdate();
		pstmt.close();

		StringBuffer query15 = new StringBuffer();
		query15.append("DELETE FROM SSO_USER WHERE ID = 'sso' ");

		pstmt = conn.prepareStatement(query15.toString());
		pstmt.executeUpdate();
		pstmt.close();

		StringBuffer query16 = new StringBuffer();
		query16.append("INSERT INTO SSO_USER(ID, NAME, PASSWORD, PW_UPDATE_TIME, STATUS, URPY_CODE) ")
			.append("VALUES('sso', '홍길동', 'e77ef187bff54bd057b1957fb2967fd845030fe1a9a419f4216b2a5b53b6c174', TO_DATE('20220801100000','YYYYMMDDHH24MISS'), 'C', 'URPY0001') ");

		pstmt = conn.prepareStatement(query16.toString());
		pstmt.executeUpdate();
		pstmt.close();

		StringBuffer query17 = new StringBuffer();
		query17.append("DELETE FROM SSO_SCOPES ");

		pstmt = conn.prepareStatement(query17.toString());
		pstmt.executeUpdate();
		pstmt.close();

		StringBuffer query18 = new StringBuffer();
		query18.append("INSERT INTO SSO_SCOPES(SCOPE) VALUES(?)");

		pstmt = conn.prepareStatement(query18.toString());
        pstmt.setString(1, "openid");
		pstmt.executeUpdate();

        pstmt.setString(1, "profile");
		pstmt.executeUpdate();

        pstmt.setString(1, "email");
		pstmt.executeUpdate();

        pstmt.setString(1, "address");
		pstmt.executeUpdate();
		pstmt.close();

		StringBuffer query19 = new StringBuffer();
		query19.append("DELETE FROM SSO_CLIENT ");

		pstmt = conn.prepareStatement(query19.toString());
		pstmt.executeUpdate();
		pstmt.close();

		StringBuffer query20 = new StringBuffer();
		query20.append("DELETE FROM SSO_CLIENT_REDIRECT ");

		pstmt = conn.prepareStatement(query20.toString());
		pstmt.executeUpdate();
		pstmt.close();

		StringBuffer query21 = new StringBuffer();
		query21.append("DELETE FROM SSO_CLIENT_SCOPE ");

		pstmt = conn.prepareStatement(query21.toString());
		pstmt.executeUpdate();
		pstmt.close();

		if (!conn.getAutoCommit())
			conn.commit();

		conn.close();
	}

	public static void setInitializeLDAP(String address, int port, String authdn, String pw, String basedn,
			SSOSecretKey DEK, String adminIP) throws Exception
	{
		LDAPConnection ld = new LDAPConnection();
		ld.connect(address, port);
		ld.authenticate(3, authdn, pw);

		LDAPAttributeSet attrs = null;
		LDAPAttribute attr = null;
		LDAPEntry entry = null;

		// delete auditpolicy
		try {
			ld.delete("cn=AUPY0001,ou=auditpolicy," + basedn);
		}
		catch (LDAPException e) {
			if (e.getLDAPResultCode() != 32) {
				throw new LDAPException(e.toString());
			}
		}

		// insert auditpolicy
		byte[] encWarnLimit = encrypt(DEK.getKey(), DEK.getIv(), "90".getBytes());
		byte[] encVerifyCycle = encrypt(DEK.getKey(), DEK.getIv(), "H".getBytes());
		byte[] encVerifyPoint = encrypt(DEK.getKey(), DEK.getIv(), "8".getBytes());

		attrs = new LDAPAttributeSet();
		attr = new LDAPAttribute("objectclass", "top");
		attr.addValue("ssoAuditPolicy");
		attrs.add(attr);
		attr = new LDAPAttribute("cn", "AUPY0001");
		attrs.add(attr);
		attr = new LDAPAttribute("ssoWarnLimit", new String(Hex.encode(encWarnLimit)));
		attrs.add(attr);
		attr = new LDAPAttribute("ssoVerifyCycle", new String(Hex.encode(encVerifyCycle)));
		attrs.add(attr);
		attr = new LDAPAttribute("ssoVerifyPoint", new String(Hex.encode(encVerifyPoint)));
		attrs.add(attr);

		entry = new LDAPEntry("cn=AUPY0001,ou=auditPolicy," + basedn, attrs);
		ld.add(entry);

		// delete mailserver
		try {
			ld.delete("cn=MSVR0001,ou=mailserver," + basedn);
		}
		catch (LDAPException e) {
			if (e.getLDAPResultCode() != 32) {
				throw new LDAPException(e.toString());
			}
		}

		// insert mailserver
		attrs = new LDAPAttributeSet();
		attr = new LDAPAttribute("objectclass", "top");
		attr.addValue("ssoMailServer");
		attrs.add(attr);
		attr = new LDAPAttribute("cn", "MSVR0001");
		attrs.add(attr);

		entry = new LDAPEntry("cn=MSVR0001,ou=mailserver," + basedn, attrs);
		ld.add(entry);

		// delete mailsend
		try {
			ld.delete("cn=MSND0000,ou=mailsend," + basedn);
			ld.delete("cn=MSND0001,ou=mailsend," + basedn);
			ld.delete("cn=MSND0002,ou=mailsend," + basedn);
			ld.delete("cn=MSND0003,ou=mailsend," + basedn);
			ld.delete("cn=MSND0004,ou=mailsend," + basedn);
			ld.delete("cn=MSND0005,ou=mailsend," + basedn);
		}
		catch (LDAPException e) {
			if (e.getLDAPResultCode() != 32) {
				throw new LDAPException(e.toString());
			}
		}

		// insert mailsend
		StringBuffer sbBody1 = new StringBuffer();
		sbBody1.append("$1 $2 아이디가 비밀번호 연속 오류로\n")
			.append("인증 기능 비활성화 상태로 변경되었습니다.\n")
			.append("확인 바랍니다.");

		byte[] encSubject = encrypt(DEK.getKey(), DEK.getIv(), "[SSO] 인증 기능 비활성화 알림".getBytes("UTF-8"));
		byte[] encBody = encrypt(DEK.getKey(), DEK.getIv(), sbBody1.toString().getBytes("UTF-8"));

		attrs = new LDAPAttributeSet();
		attr = new LDAPAttribute("objectclass", "top");
		attr.addValue("ssoMailSend");
		attrs.add(attr);
		attr = new LDAPAttribute("cn", "MSND0000");
		attrs.add(attr);
		attr = new LDAPAttribute("ssoMailSubject", new String(Hex.encode(encSubject)));
		attrs.add(attr);
		attr = new LDAPAttribute("ssoMailBody", new String(Hex.encode(encBody)));
		attrs.add(attr);

		entry = new LDAPEntry("cn=MSND0000,ou=mailsend," + basedn, attrs);
		ld.add(entry);

		StringBuffer sbBody2 = new StringBuffer();
		sbBody2.append("SSO 무결성 검증 오류가 발생하였습니다.\n")
			.append("시스템 점검 바랍니다.");

		encSubject = encrypt(DEK.getKey(), DEK.getIv(), "[SSO] 무결성 검증 오류 발생".getBytes("UTF-8"));
		encBody = encrypt(DEK.getKey(), DEK.getIv(), sbBody2.toString().getBytes("UTF-8"));

		attrs = new LDAPAttributeSet();
		attr = new LDAPAttribute("objectclass", "top");
		attr.addValue("ssoMailSend");
		attrs.add(attr);
		attr = new LDAPAttribute("cn", "MSND0001");
		attrs.add(attr);
		attr = new LDAPAttribute("ssoMailSubject", new String(Hex.encode(encSubject)));
		attrs.add(attr);
		attr = new LDAPAttribute("ssoMailBody", new String(Hex.encode(encBody)));
		attrs.add(attr);

		entry = new LDAPEntry("cn=MSND0001,ou=mailsend," + basedn, attrs);
		ld.add(entry);

		StringBuffer sbBody3 = new StringBuffer();
		sbBody3.append("SSO 암호모듈 자가시험 오류가 발생하였습니다.\n")
			.append("시스템 점검 바랍니다.");

		encSubject = encrypt(DEK.getKey(), DEK.getIv(), "[SSO] 암호모듈 자가시험 오류 발생".getBytes("UTF-8"));
		encBody = encrypt(DEK.getKey(), DEK.getIv(), sbBody3.toString().getBytes("UTF-8"));

		attrs = new LDAPAttributeSet();
		attr = new LDAPAttribute("objectclass", "top");
		attr.addValue("ssoMailSend");
		attrs.add(attr);
		attr = new LDAPAttribute("cn", "MSND0002");
		attrs.add(attr);
		attr = new LDAPAttribute("ssoMailSubject", new String(Hex.encode(encSubject)));
		attrs.add(attr);
		attr = new LDAPAttribute("ssoMailBody", new String(Hex.encode(encBody)));
		attrs.add(attr);

		entry = new LDAPEntry("cn=MSND0002,ou=mailsend," + basedn, attrs);
		ld.add(entry);

		StringBuffer sbBody6 = new StringBuffer();
		sbBody6.append("SSO 프로세스 검증 오류가 발생하였습니다.\n")
			.append("시스템 점검 바랍니다.");

		encSubject = encrypt(DEK.getKey(), DEK.getIv(), "[SSO] 프로세스 검증 오류 발생".getBytes("UTF-8"));
		encBody = encrypt(DEK.getKey(), DEK.getIv(), sbBody6.toString().getBytes("UTF-8"));

		attrs = new LDAPAttributeSet();
		attr = new LDAPAttribute("objectclass", "top");
		attr.addValue("ssoMailSend");
		attrs.add(attr);
		attr = new LDAPAttribute("cn", "MSND0005");
		attrs.add(attr);
		attr = new LDAPAttribute("ssoMailSubject", new String(Hex.encode(encSubject)));
		attrs.add(attr);
		attr = new LDAPAttribute("ssoMailBody", new String(Hex.encode(encBody)));
		attrs.add(attr);

		entry = new LDAPEntry("cn=MSND0005,ou=mailsend," + basedn, attrs);
		ld.add(entry);

		StringBuffer sbBody4 = new StringBuffer();
		sbBody4.append("SSO 감사정보 저장용량이 임계치를 초과하였습니다.\n")
			.append("시스템 점검 바랍니다.");

		encSubject = encrypt(DEK.getKey(), DEK.getIv(), "[SSO] 감사정보 저장용량 임계치 초과".getBytes("UTF-8"));
		encBody = encrypt(DEK.getKey(), DEK.getIv(), sbBody4.toString().getBytes("UTF-8"));

		attrs = new LDAPAttributeSet();
		attr = new LDAPAttribute("objectclass", "top");
		attr.addValue("ssoMailSend");
		attrs.add(attr);
		attr = new LDAPAttribute("cn", "MSND0003");
		attrs.add(attr);
		attr = new LDAPAttribute("ssoMailSubject", new String(Hex.encode(encSubject)));
		attrs.add(attr);
		attr = new LDAPAttribute("ssoMailBody", new String(Hex.encode(encBody)));
		attrs.add(attr);

		entry = new LDAPEntry("cn=MSND0003,ou=mailsend," + basedn, attrs);
		ld.add(entry);

		StringBuffer sbBody5 = new StringBuffer();
		sbBody5.append("SSO 감사정보 저장소가 포화 상태입니다.\n")
			.append("시스템 점검 바랍니다.");

		encSubject = encrypt(DEK.getKey(), DEK.getIv(), "[SSO] 감사정보 저장소 포화상태 알림".getBytes("UTF-8"));
		encBody = encrypt(DEK.getKey(), DEK.getIv(), sbBody5.toString().getBytes("UTF-8"));

		attrs = new LDAPAttributeSet();
		attr = new LDAPAttribute("objectclass", "top");
		attr.addValue("ssoMailSend");
		attrs.add(attr);
		attr = new LDAPAttribute("cn", "MSND0004");
		attrs.add(attr);
		attr = new LDAPAttribute("ssoMailSubject", new String(Hex.encode(encSubject)));
		attrs.add(attr);
		attr = new LDAPAttribute("ssoMailBody", new String(Hex.encode(encBody)));
		attrs.add(attr);

		entry = new LDAPEntry("cn=MSND0004,ou=mailsend," + basedn, attrs);
		ld.add(entry);

		// delete userpolicy
		try {
			ld.delete("cn=URPY0001,ou=userpolicy," + basedn);
		}
		catch (LDAPException e) {
			if (e.getLDAPResultCode() != 32) {
				throw new LDAPException(e.toString());
			}
		}

		// insert userpolicy
		byte[] encPwMismatchAllow = encrypt(DEK.getKey(), DEK.getIv(), "5".getBytes());
		byte[] encPwChangeWarn = encrypt(DEK.getKey(), DEK.getIv(), "7".getBytes());
		byte[] encPwValidate = encrypt(DEK.getKey(), DEK.getIv(), "90".getBytes());
		byte[] encSessionTime = encrypt(DEK.getKey(), DEK.getIv(), "10".getBytes());
		byte[] encPollingTime = encrypt(DEK.getKey(), DEK.getIv(), "30".getBytes());

		attrs = new LDAPAttributeSet();
		attr = new LDAPAttribute("objectclass", "top");
		attr.addValue("ssoPolicy");
		attrs.add(attr);
		attr = new LDAPAttribute("cn", "URPY0001");
		attrs.add(attr);
		attr = new LDAPAttribute("ssoPwMismatchAllow", new String(Hex.encode(encPwMismatchAllow)));
		attrs.add(attr);
		attr = new LDAPAttribute("ssoPwChangeWarn", new String(Hex.encode(encPwChangeWarn)));
		attrs.add(attr);
		attr = new LDAPAttribute("ssoPwValidate", new String(Hex.encode(encPwValidate)));
		attrs.add(attr);
		attr = new LDAPAttribute("ssoSessionTime", new String(Hex.encode(encSessionTime)));
		attrs.add(attr);
		attr = new LDAPAttribute("ssoPollingTime", new String(Hex.encode(encPollingTime)));
		attrs.add(attr);

		entry = new LDAPEntry("cn=URPY0001,ou=userpolicy," + basedn, attrs);
		ld.add(entry);

		// delete adminpolicy
		try {
			ld.delete("cn=ADPY0001,ou=adminpolicy," + basedn);
		}
		catch (LDAPException e) {
			if (e.getLDAPResultCode() != 32) {
				throw new LDAPException(e.toString());
			}
		}

		// insert adminpolicy
		encPwMismatchAllow = encrypt(DEK.getKey(), DEK.getIv(), "5".getBytes());
		encSessionTime = encrypt(DEK.getKey(), DEK.getIv(), "10".getBytes());
		byte[] encLockTime = encrypt(DEK.getKey(), DEK.getIv(), "5".getBytes());
		byte[] encIpMaxCount = encrypt(DEK.getKey(), DEK.getIv(), "2".getBytes());

		attrs = new LDAPAttributeSet();
		attr = new LDAPAttribute("objectclass", "top");
		attr.addValue("ssoAdminPolicy");
		attrs.add(attr);
		attr = new LDAPAttribute("cn", "ADPY0001");
		attrs.add(attr);
		attr = new LDAPAttribute("ssoPwMismatchAllow", new String(Hex.encode(encPwMismatchAllow)));
		attrs.add(attr);
		attr = new LDAPAttribute("ssoSessionTime", new String(Hex.encode(encSessionTime)));
		attrs.add(attr);
		attr = new LDAPAttribute("ssoLockTime", new String(Hex.encode(encLockTime)));
		attrs.add(attr);
		attr = new LDAPAttribute("ssoIpMaxCount", new String(Hex.encode(encIpMaxCount)));
		attrs.add(attr);

		entry = new LDAPEntry("cn=ADPY0001,ou=adminpolicy," + basedn, attrs);
		ld.add(entry);

		// delete adminip
		LDAPSearchResults ldResults = ld.search("ou=adminip," + basedn, LdapQuery.SCOPE_ONE,
				"(&amp;(objectclass=ssoAdminIp)(cn=*))", new String[] {"cn"}, false);

		while (ldResults.hasMoreElements()) {
			LDAPEntry ldEntry = ldResults.next();
			ld.delete(ldEntry.getDN());
		}

		// insert adminip
		byte[] encIp = encrypt(DEK.getKey(), DEK.getIv(), adminIP.getBytes());
		String strIp = new String(Hex.encode(encIp));

		attrs = new LDAPAttributeSet();
		attr = new LDAPAttribute("objectclass", "top");
		attr.addValue("ssoAdminIp");
		attrs.add(attr);
		attr = new LDAPAttribute("cn", strIp);
		attrs.add(attr);

		entry = new LDAPEntry("cn=" + strIp + ",ou=adminip," + basedn, attrs);
		ld.add(entry);

		// delete admin
		try {
			ld.delete("cn=ssoadmin,ou=admin," + basedn);
		}
		catch (LDAPException e) {
			if (e.getLDAPResultCode() != 32) {
				throw new LDAPException(e.toString());
			}
		}

		// insert admin
		attrs = new LDAPAttributeSet();
		attr = new LDAPAttribute("objectclass", "top");
		attr.addValue("ssoAdmin");
		attrs.add(attr);
		attr = new LDAPAttribute("cn", "ssoadmin");
		attrs.add(attr);
		attr = new LDAPAttribute("ssoUserName", "관리자");
		attrs.add(attr);
		attr = new LDAPAttribute("ssoUserPassword", "ff1f1f9b5ef6534d070d0c7345c8b4b121dd01e73cb94dee1780e798d79cc9be");
		attrs.add(attr);
		attr = new LDAPAttribute("ssoPwUpdateTime", "20220802123456");
		attrs.add(attr);
		attr = new LDAPAttribute("ssoPwMismatchCount", "0");
		attrs.add(attr);
		attr = new LDAPAttribute("ssoPolicyCode", "ADPY0001");
		attrs.add(attr);
		attr = new LDAPAttribute("ssoUserStatus", "C");
		attrs.add(attr);
		attr = new LDAPAttribute("ssoUserType", "S");
		attrs.add(attr);
		attr = new LDAPAttribute("ssoFirstYn", "Y");
		attrs.add(attr);

		entry = new LDAPEntry("cn=ssoadmin,ou=admin," + basedn, attrs);
		ld.add(entry);

		// delete user
		try {
			ld.delete("cn=sso,ou=user," + basedn);
		}
		catch (LDAPException e) {
			if (e.getLDAPResultCode() != 32) {
				throw new LDAPException(e.toString());
			}
		}

		// insert user
		attrs = new LDAPAttributeSet();
		attr = new LDAPAttribute("objectclass", "top");
		attr.addValue("ssoUser");
		attrs.add(attr);
		attr = new LDAPAttribute("cn", "sso");
		attrs.add(attr);
		attr = new LDAPAttribute("ssoUserName", "홍길동");
		attrs.add(attr);
		attr = new LDAPAttribute("ssoUserPassword", "e77ef187bff54bd057b1957fb2967fd845030fe1a9a419f4216b2a5b53b6c174");
		attrs.add(attr);
		attr = new LDAPAttribute("ssoPwUpdateTime", "20220801100000");
		attrs.add(attr);
		attr = new LDAPAttribute("ssoPwMismatchCount", "0");
		attrs.add(attr);
		attr = new LDAPAttribute("ssoPolicyCode", "URPY0001");
		attrs.add(attr);
		attr = new LDAPAttribute("ssoUserStatus", "C");
		attrs.add(attr);

		entry = new LDAPEntry("cn=sso,ou=user," + basedn, attrs);
		ld.add(entry);

		ld.disconnect();
	}

	private static void setXMLProperty(XMLConfiguration config, String key, String value) throws Exception
	{
		String data = config.getString(key, "");

		if (Util.isEmpty(data)) {
			config.addProperty(key, value);
		}
		else {
			config.setProperty(key, value);
		}
	}

	private static String readPassword(String format) throws Exception
	{
		String sInput = "";

		while (true) {
			Console console = System.console();
			console.printf(format);
			console.printf("> ");
			char[] pwdChars = console.readPassword();
			sInput = new String(pwdChars);

			if (sInput.equals("")) {
				String sCancel = "";

				Scanner scanner2 = new Scanner(System.in);
				System.out.printf("\nCancel Input (Y/N) ? ");
				sCancel = scanner2.nextLine();

				if (sCancel.equalsIgnoreCase("Y")) {
					throw new Exception("Cancel Input");
				}
			}
			else {
				break;
			}
		}

		return sInput;
	}

	private static String readLine(String format, boolean required) throws Exception
	{
		String sInput = "";

		while (true) {
			Scanner scanner = new Scanner(System.in);
			System.out.printf(format);
			System.out.printf("> ");
			sInput = scanner.nextLine().trim();

			if (sInput.equals("cancel")) {
				String sCancel = "";

				Scanner scanner2 = new Scanner(System.in);
				System.out.printf("\nCancel Input (Y/N) ? ");
				sCancel = scanner2.nextLine().trim();

				if (sCancel.equalsIgnoreCase("Y"))
					throw new Exception("Cancel Input");
			}
			else if (sInput.equals("") && required) {
				continue;
			}
			else {
				break;
			}
		}

		return sInput;
	}

	private static void outPrint(String format)
	{
		System.out.printf(format);
	}

	public static void main(String[] args)
	{
		SSOSecretKey KEK = null;
		SSOSecretKey DEK = null;

		try {
			outPrint("\n");
			outPrint("==============================================\n");
			outPrint("  Product   : " + SSOConfig.getTOE() + "\n");
			outPrint("  Version   : " + SSOConfig.getDetailVersion() + "\n");
			outPrint("  Component : " + SSOConfig.getElementVersion() + "\n");
			outPrint("  Developer : Dreamsecurity Co.,Ltd.\n");
			outPrint("==============================================\n");

			outPrint("\n>>> SSO Config Initialization  (Cancel: \"cancel\" Input)\n");

			String rootpath = readLine("\nEnter WAS Container Root Full Path : ex) /home/tomcat/webapps\n", true);

			String homepath = readLine("\nEnter Magic SSO Config Home Full Path : ex) /home/dreamsso\n", true);

			String ssopath  = readLine("\nEnter Magic SSO Home Path : default) /sso\n", false);
			if (ssopath.equals("")) {
				ssopath = "/sso";
			}

			String name = readLine("\nEnter SSO Server Name : ex) TEST_IDP\n", true);

			String encCertName = name + "_Enc.key";
			String sigCertName = name + "_Sig.key";

			String encCertPwd = readPassword("\nEnter Encryption Certificate [" + encCertName + "] Password : \n");
			verifyKeyPair(homepath + "/cert/" + encCertName, encCertPwd);
			outPrint("\n>>> Encryption Certificate Key Pair OK.\n");

			String sigCertPwd = readPassword("\nEnter Signing Certificate [" + sigCertName + "] Password : \n");
			verifyKeyPair(homepath + "/cert/" + sigCertName, sigCertPwd);
			outPrint("\n>>> Signing Certificate Key Pair OK.\n");

			String dbUseYN = "Y";
			String dbDriver = "dbDriver";
			String dbUrl = "dbUrl";
			String dbName = "dbName";
			String dbPwd = "dbPwd";

			String ldapHost = "";
			String ldapPort = "";
			String ldapUser = "";
			String ldapPwd = "";
			String ldapBaseDn = "";
			int nLdapPort = 0;

			String ldapUseYN = readLine("\nUse LDAP : (Y)es / (N)o ?  default) No\n", false);
			if (ldapUseYN.equals("")) {
				ldapUseYN = "N";
			}

			if (ldapUseYN.equalsIgnoreCase("Y")) {
				ldapHost = readLine("\nEnter LDAP Connection Host : ex) abc.dev.com or 10.10.10.2\n", true);

				ldapPort = readLine("\nEnter LDAP Connection Port : default) 389\n", false);
				if (ldapPort.equals("")) {
					ldapPort = "389";
				}

				nLdapPort = Integer.parseInt(ldapPort);

				ldapUser = readLine("\nEnter LDAP Connection User Name : \n", true);
				ldapPwd = readPassword("\nEnter LDAP Connection User Password : \n");
				ldapBaseDn = readLine("\nEnter LDAP SSO Base DN : ex) ou=dreamsso,dc=my-domain,dc=com\n", true);

				dbUseYN = readLine("\nUse Database : (Y)es / (N)o ?  default) No\n", false);
				if (dbUseYN.equals("")) {
					dbUseYN = "N";
				}
			}

			if (dbUseYN.equalsIgnoreCase("Y")) {
				dbDriver = readLine("\nEnter DB Driver Class Name : default) oracle.jdbc.driver.OracleDriver\n", false);
				if (dbDriver.equals("")) {
					dbDriver = "oracle.jdbc.driver.OracleDriver";
				}

				dbUrl = readLine("\nEnter Database Connection URL : ex) jdbc:oracle:thin:@192.168.10.2:1521:ORASID\n", true);
				dbName = readLine("\nEnter Database Connection User Name : \n", true);
				dbPwd = readPassword("\nEnter Database Connection User Password : \n");
			}

			outPrint("\nToken Attribute: ID,NAME,TIMESTAMP,NOT_AFTER,LAST_LOGIN_IP,LAST_LOGIN_TIME,NOW_LOGIN_IP,NOW_LOGIN_TIME,POLLING_TIME,SESSION_TIME,PW_MISMATCH_ALLOW,PW_VALIDATE,PW_CHANGE_WARN,PW_UPDATE_DAYS,LOGIN_TYPE");
			String token = readLine("\nEnter Add Token Attribute : ex) ATTR_AAA,ATTR_BBB\n", false);
			if (token.equals("")) {
				token = "ID,NAME,TIMESTAM_,NOT_AFTER,LAST_LOGIN_IP,LAST_LOGIN_TIME,NOW_LOGIN_IP,NOW_LOGIN_TIME,POLLING_TIME,SESSION_TIME,PW_MISMATCH_ALLOW,PW_VALIDATE,PW_CHANGE_WARN,PW_UPDATE_DAYS,LOGIN_TYPE";
			}
			else {
				token = "ID,NAME,TIMESTAM_,NOT_AFTER,LAST_LOGIN_IP,LAST_LOGIN_TIME,NOW_LOGIN_IP,NOW_LOGIN_TIME,POLLING_TIME,SESSION_TIME,PW_MISMATCH_ALLOW,PW_VALIDATE,PW_CHANGE_WARN,PW_UPDATE_DAYS,LOGIN_TYPE,"
						+ token;
			}

			String xmlFile = homepath + "/config/application/idp.xml";
			XMLConfiguration config = new XMLConfiguration(xmlFile);
			config.setThrowExceptionOnMissing(false);
			String strDEK = config.getString("server.code", "");
			String strBlock = config.getString("server.block", "");

			KEK = generateKEKByPwd(name, homepath + "/cert/" + name + "_Enc.der");

			if (Util.isEmpty(strDEK)) {
				DEK = generateSecretKey();
				byte[] encDEK = encrypt(KEK.getKey(), KEK.getIv(), DEK.getKeyIv());
				strDEK = new String(Hex.encode(encDEK));
				strBlock = new String(Hex.encode(KEK.getIv()));
			}
			else {
				KEK.setIv(Hex.decode(strBlock));
				byte[] decDEK = decrypt(KEK.getKey(), KEK.getIv(), Hex.decode(strDEK));
				DEK = new SSOSecretKey("SEED", decDEK);
			}

			byte[] encSsoPath = encrypt(DEK.getKey(), DEK.getIv(), ssopath.getBytes());

			byte[] encEncCertPwd = encrypt(DEK.getKey(), DEK.getIv(), encCertPwd.getBytes());
			byte[] encSigCertPwd = encrypt(DEK.getKey(), DEK.getIv(), sigCertPwd.getBytes());

			byte[] encDbDriver = encrypt(DEK.getKey(), DEK.getIv(), dbDriver.getBytes());
			byte[] encDbUrl = encrypt(DEK.getKey(), DEK.getIv(), dbUrl.getBytes());
			byte[] encDbName = encrypt(DEK.getKey(), DEK.getIv(), dbName.getBytes());
			byte[] encDbPwd = encrypt(DEK.getKey(), DEK.getIv(), dbPwd.getBytes());

			byte[] encTAttr = encrypt(DEK.getKey(), DEK.getIv(), token.getBytes());

			config.clear();

			setXMLProperty(config, "server.name", name);
			setXMLProperty(config, "server.code", strDEK);
			setXMLProperty(config, "server.block", strBlock);

			setXMLProperty(config, "sso.homepath", new String(Hex.encode(encSsoPath)));

			setXMLProperty(config, "cert.keycode", new String(Hex.encode(encEncCertPwd)));
			setXMLProperty(config, "cert.signcode", new String(Hex.encode(encSigCertPwd)));

			setXMLProperty(config, "dbcp.driver", new String(Hex.encode(encDbDriver)));
			setXMLProperty(config, "dbcp.url", new String(Hex.encode(encDbUrl)));
			setXMLProperty(config, "dbcp.username", new String(Hex.encode(encDbName)));
			setXMLProperty(config, "dbcp.password", new String(Hex.encode(encDbPwd)));

			setXMLProperty(config, "token.attribute", new String(Hex.encode(encTAttr)));

			config.save();

			String strConfig = Util.domToStr(config.getDocument(), true, "UTF-8");
			File fileConfig = new File(xmlFile);
			BufferedWriter bw = new BufferedWriter(new OutputStreamWriter(new FileOutputStream(fileConfig.getPath()), "UTF-8"));
			bw.write(strConfig);
			bw.close();

			outPrint("\n>>> SSO Config Initialization Complete !!!\n");
			outPrint("\n>>> SSO Database Initialization  (Cancel: \"cancel\" Input)\n");

			String adminIP = readLine("\nEnter Administrator Access IP : ex) 192.168.10.5\n", true);

			if (ldapUseYN.equalsIgnoreCase("Y")) {
				setInitializeLDAP(ldapHost, nLdapPort, ldapUser, ldapPwd, ldapBaseDn, DEK, adminIP);
			}
			else {
				if (dbDriver.indexOf("cubrid") >= 0) {
					setInitializeDB_cubrid(dbDriver, dbUrl, dbName, dbPwd, DEK, adminIP);
				}
				else if (dbDriver.indexOf("postgresql") >= 0) {
					setInitializeDB_postgresql(dbDriver, dbUrl, dbName, dbPwd, DEK, adminIP);
				}
				else if (dbDriver.indexOf("mysql") >= 0) {
					setInitializeDB_mysql(dbDriver, dbUrl, dbName, dbPwd, DEK, adminIP);
				}
				else if (dbDriver.indexOf("sqlserver") >= 0) {
					setInitializeDB_sqlserver(dbDriver, dbUrl, dbName, dbPwd, DEK, adminIP);
				}
				else if (dbDriver.indexOf("tibero") >= 0) {
					setInitializeDB_tibero(dbDriver, dbUrl, dbName, dbPwd, DEK, adminIP);
				}
				else {
					setInitializeDB(dbDriver, dbUrl, dbName, dbPwd, DEK, adminIP);
				}
			}

			outPrint("\n>>> SSO Database Initialization Complete !!!\n");
			outPrint("\n>>> SSO Metadata Initialization\n");

			SSOConfig.setHomeDir(rootpath, homepath);

			MetadataRepository metaInstance = MetadataRepository.getInstance();
			IDPSSODescriptor idpDescriptor = metaInstance.getIDPDescriptor();
			List<String> spList = metaInstance.getSPNames();

			/* Save Entities */
			EntitiesDescriptor parentEntities = (EntitiesDescriptor) SAMLUtil.buildXMLObject(EntitiesDescriptor.DEFAULT_ELEMENT_NAME);
			parentEntities.setValidUntil(new DateTime(DateTimeZone.UTC).plusYears(20));
			parentEntities.setName("DREAM");

			EntityDescriptor idpEntity = (EntityDescriptor) SAMLUtil.buildXMLObject(EntityDescriptor.DEFAULT_ELEMENT_NAME);
			IDPSSODescriptor idpDesc = (IDPSSODescriptor) SAMLUtil.buildXMLObject(IDPSSODescriptor.DEFAULT_ELEMENT_NAME);

			EntitiesDescriptor spEntities = (EntitiesDescriptor) SAMLUtil.buildXMLObject(EntitiesDescriptor.DEFAULT_ELEMENT_NAME);
			/* Save Entities */

			CredentialRepository.clearCredential();

			/* IDP */
			outPrint("\nSSO Server\n");
			outPrint("    Server Name : " + name + "\n");

			String encCert = name + "_Enc.der";
			String sigCert = name + "_Sig.der";

			String idpEdit = readLine("\nSelect SSO Server : (E)dit / (N)one ? ", true);
			if (idpEdit.equalsIgnoreCase("E")) {
				outPrint("\nSSO Server Name : " + name);

				outPrint("\nSSO Server Encryption Certificate File Name : " + name + "_Enc.der");
				outPrint("\nSSO Server Signing    Certificate File Name : " + name + "_Sig.der\n");

				String requestUrl = readLine("\nEnter SSO Server Request URL : ex) "
						+ idpDescriptor.getSingleSignOnServices().get(0).getLocation() + "\n", true);
				String logoutUrl = readLine("\nEnter SSO Server Logout URL : ex) "
						+ idpDescriptor.getSingleLogoutServices().get(0).getLocation() + "\n", true);

				idpEntity.setEntityID(name);

				X509Certificate encX509Cert = Util.getCert(homepath + "/cert/" + encCert);
				Credential encCred = CredentialRepository.createCredential(name + "_E", encX509Cert);
				KeyInfoGenerator encKeyInfoGen = SecurityHelper.getKeyInfoGenerator(encCred, Configuration.getGlobalSecurityConfiguration(), null);

				KeyDescriptor encKeyDescriptor = (KeyDescriptor) SAMLUtil.buildXMLObject(KeyDescriptor.DEFAULT_ELEMENT_NAME);
				encKeyDescriptor.setUse(UsageType.ENCRYPTION);
				encKeyDescriptor.setKeyInfo(encKeyInfoGen.generate(encCred));
				idpDesc.getKeyDescriptors().add(encKeyDescriptor);

				X509Certificate sigX509Cert = SAMLUtil.getCert(homepath + "/cert/" + sigCert);
				Credential sigCred = CredentialRepository.createCredential(name + "_S", sigX509Cert);
				KeyInfoGenerator sigKeyInfoGen = SecurityHelper.getKeyInfoGenerator(sigCred, Configuration.getGlobalSecurityConfiguration(), null);

				KeyDescriptor sigKeyDescriptor = (KeyDescriptor) SAMLUtil.buildXMLObject(KeyDescriptor.DEFAULT_ELEMENT_NAME);
				sigKeyDescriptor.setUse(UsageType.SIGNING);
				sigKeyDescriptor.setKeyInfo(sigKeyInfoGen.generate(sigCred));
				idpDesc.getKeyDescriptors().add(sigKeyDescriptor);

				SingleSignOnService requestService = (SingleSignOnService) SAMLUtil.buildXMLObject(SingleSignOnService.DEFAULT_ELEMENT_NAME);
				requestService.setLocation(requestUrl);
				idpDesc.getSingleSignOnServices().add(requestService);

				SingleLogoutService logoutService = (SingleLogoutService) SAMLUtil.buildXMLObject(SingleLogoutService.DEFAULT_ELEMENT_NAME);
				logoutService.setLocation(logoutUrl);
				idpDesc.getSingleLogoutServices().add(logoutService);
			}
			else {
				idpEntity.setEntityID(name);

				X509Certificate encX509Cert = Util.getCert(homepath + "/cert/" + encCert);
				Credential encCred = CredentialRepository.createCredential(name + "_E", encX509Cert);
				KeyInfoGenerator encKeyInfoGen = SecurityHelper.getKeyInfoGenerator(encCred, Configuration.getGlobalSecurityConfiguration(), null);

				KeyDescriptor encKeyDescriptor = (KeyDescriptor) SAMLUtil.buildXMLObject(KeyDescriptor.DEFAULT_ELEMENT_NAME);
				encKeyDescriptor.setUse(UsageType.ENCRYPTION);
				encKeyDescriptor.setKeyInfo(encKeyInfoGen.generate(encCred));
				idpDesc.getKeyDescriptors().add(encKeyDescriptor);

				X509Certificate sigX509Cert = SAMLUtil.getCert(homepath + "/cert/" + sigCert);
				Credential sigCred = CredentialRepository.createCredential(name + "_S", sigX509Cert);
				KeyInfoGenerator sigKeyInfoGen = SecurityHelper.getKeyInfoGenerator(sigCred, Configuration.getGlobalSecurityConfiguration(), null);

				KeyDescriptor sigKeyDescriptor = (KeyDescriptor) SAMLUtil.buildXMLObject(KeyDescriptor.DEFAULT_ELEMENT_NAME);
				sigKeyDescriptor.setUse(UsageType.SIGNING);
				sigKeyDescriptor.setKeyInfo(sigKeyInfoGen.generate(sigCred));
				idpDesc.getKeyDescriptors().add(sigKeyDescriptor);

				SingleSignOnService requestService = (SingleSignOnService) SAMLUtil.buildXMLObject(SingleSignOnService.DEFAULT_ELEMENT_NAME);
				requestService.setLocation(idpDescriptor.getSingleSignOnServices().get(0).getLocation());
				idpDesc.getSingleSignOnServices().add(requestService);

				SingleLogoutService logoutService = (SingleLogoutService) SAMLUtil.buildXMLObject(SingleLogoutService.DEFAULT_ELEMENT_NAME);
				logoutService.setLocation(idpDescriptor.getSingleLogoutServices().get(0).getLocation());
				idpDesc.getSingleLogoutServices().add(logoutService);
			}

			idpEntity.getRoleDescriptors().add(idpDesc);
			parentEntities.getEntityDescriptors().add(idpEntity);

			/* SP */
			for (int i = 0; i < spList.size(); i++) {
				EntityDescriptor spEntity = (EntityDescriptor) SAMLUtil.buildXMLObject(EntityDescriptor.DEFAULT_ELEMENT_NAME);
				SPSSODescriptor spDesc = (SPSSODescriptor) SAMLUtil.buildXMLObject(SPSSODescriptor.DEFAULT_ELEMENT_NAME);
				spDesc.setAuthnRequestsSigned(true);
				spDesc.setWantAssertionsSigned(true);

				SPSSODescriptor spDescriptor = metaInstance.getSPDescriptor(spList.get(i));

				outPrint("\nSSO Agent\n");
				outPrint("    Agent Name : " + spList.get(i) + "\n");

				encCert = spList.get(i) + "_Enc.der";
				sigCert = spList.get(i) + "_Sig.der";

				String spEdit = readLine("\nSelect SSO Agent " + spList.get(i) + " : (E)dit / (D)elete / (N)one ? ", true);
				if (spEdit.equalsIgnoreCase("E")) {
					String spName = readLine("\nEnter SSO Agent Name : ex) TEST_SP\n", true);

					encCert = spName + "_Enc.der";
					sigCert = spName + "_Sig.der";

					outPrint("\nSSO Agent Encryption Certificate File Name : " + spName + "_Enc.der");
					outPrint("\nSSO Agent Signing    Certificate File Name : " + spName + "_Sig.der\n");

					String responseUrl = readLine("\nEnter SSO Agent " + spName + " Response URL : ex) "
							+ spDescriptor.getAssertionConsumerServices().get(0).getLocation() + "\n", true);
					String logoutUrl = readLine("\nEnter SSO Agent " + spName + " Logout URL : ex) "
							+ spDescriptor.getSingleLogoutServices().get(0).getLocation() + "\n", true);

					spEntity.setEntityID(spName);

					X509Certificate encX509Cert = SAMLUtil.getCert(homepath + "/cert/" + encCert);
					Credential encCred = CredentialRepository.createCredential(spName + "_E", encX509Cert);
					KeyInfoGenerator encKeyInfoGen = SecurityHelper
							.getKeyInfoGenerator(encCred, Configuration.getGlobalSecurityConfiguration(), null);

					KeyDescriptor encKeyDescriptor = (KeyDescriptor) SAMLUtil.buildXMLObject(KeyDescriptor.DEFAULT_ELEMENT_NAME);
					encKeyDescriptor.setUse(UsageType.ENCRYPTION);
					encKeyDescriptor.setKeyInfo(encKeyInfoGen.generate(encCred));
					spDesc.getKeyDescriptors().add(encKeyDescriptor);

					X509Certificate sigX509Cert = SAMLUtil.getCert(homepath + "/cert/" + sigCert);
					Credential sigCred = CredentialRepository.createCredential(spName + "_S", sigX509Cert);
					KeyInfoGenerator sigKeyInfoGen = SecurityHelper
							.getKeyInfoGenerator(sigCred, Configuration.getGlobalSecurityConfiguration(), null);

					KeyDescriptor sigKeyDescriptor = (KeyDescriptor) SAMLUtil.buildXMLObject(KeyDescriptor.DEFAULT_ELEMENT_NAME);
					sigKeyDescriptor.setUse(UsageType.SIGNING);
					sigKeyDescriptor.setKeyInfo(sigKeyInfoGen.generate(sigCred));
					spDesc.getKeyDescriptors().add(sigKeyDescriptor);

					AssertionConsumerService responseService =
							(AssertionConsumerService) SAMLUtil.buildXMLObject(AssertionConsumerService.DEFAULT_ELEMENT_NAME);
					responseService.setIsDefault(true);
					responseService.setLocation(responseUrl);
					spDesc.getAssertionConsumerServices().add(responseService);

					SingleLogoutService logoutService = (SingleLogoutService) SAMLUtil.buildXMLObject(SingleLogoutService.DEFAULT_ELEMENT_NAME);
					logoutService.setLocation(logoutUrl);
					spDesc.getSingleLogoutServices().add(logoutService);

					int index = 1;
					while (true) {
						String addURL = readLine("\nSelect SSO Agent " + spName + " URL : (A)dd / (N)one ? ", true);
						if (addURL.equalsIgnoreCase("A")) {
							String addResponseUrl = readLine("\nEnter SSO Agent Add Response URL : ex) https://sp.dev.com:8443/sso/Response.jsp\n", true);
							String addLogoutUrl = readLine("\nEnter SSO Agent Add Logout URL : ex) https://sp.dev.com:8443/sso/Logout.jsp\n", true);

							if (index == 1)
								spDesc.getAssertionConsumerServices().get(0).setIndex(0);
								
							AssertionConsumerService addResponseService =
									(AssertionConsumerService) SAMLUtil.buildXMLObject(AssertionConsumerService.DEFAULT_ELEMENT_NAME);
							addResponseService.setIndex(index);
							addResponseService.setLocation(addResponseUrl);
							spDesc.getAssertionConsumerServices().add(addResponseService);

							SingleLogoutService addLogoutService = (SingleLogoutService) SAMLUtil.buildXMLObject(SingleLogoutService.DEFAULT_ELEMENT_NAME);
							addLogoutService.setLocation(addLogoutUrl);
							spDesc.getSingleLogoutServices().add(addLogoutService);
						}
						else {
							break;
						}
					}
				}
				else if (spEdit.equalsIgnoreCase("D")) {
					String addURL = readLine("\nConfirm Delete SSO Agent " + spList.get(i) + " (Y/N) ? ", true);
					if (addURL.equalsIgnoreCase("Y")) {
						continue;
					}
					else {
						i--;
						continue;
					}
				}
				else {
					spEntity.setEntityID(spList.get(i));

					X509Certificate encX509Cert = SAMLUtil.getCert(homepath + "/cert/" + encCert);
					Credential encCred = CredentialRepository.createCredential(spList.get(i) + "_E", encX509Cert);
					KeyInfoGenerator encKeyInfoGen =
							SecurityHelper.getKeyInfoGenerator(encCred, Configuration.getGlobalSecurityConfiguration(), null);

					KeyDescriptor encKeyDescriptor = (KeyDescriptor) SAMLUtil.buildXMLObject(KeyDescriptor.DEFAULT_ELEMENT_NAME);
					encKeyDescriptor.setUse(UsageType.ENCRYPTION);
					encKeyDescriptor.setKeyInfo(encKeyInfoGen.generate(encCred));
					spDesc.getKeyDescriptors().add(encKeyDescriptor);

					X509Certificate sigX509Cert = SAMLUtil.getCert(homepath + "/cert/" + sigCert);
					Credential sigCred = CredentialRepository.createCredential(spList.get(i) + "_S", sigX509Cert);
					KeyInfoGenerator sigKeyInfoGen =
							SecurityHelper.getKeyInfoGenerator(sigCred, Configuration.getGlobalSecurityConfiguration(), null);

					KeyDescriptor sigKeyDescriptor = (KeyDescriptor) SAMLUtil.buildXMLObject(KeyDescriptor.DEFAULT_ELEMENT_NAME);
					sigKeyDescriptor.setUse(UsageType.SIGNING);
					sigKeyDescriptor.setKeyInfo(sigKeyInfoGen.generate(sigCred));
					spDesc.getKeyDescriptors().add(sigKeyDescriptor);

					for (int j = 0; j < spDescriptor.getAssertionConsumerServices().size(); j++) {
						AssertionConsumerService responseService =
								(AssertionConsumerService) SAMLUtil.buildXMLObject(AssertionConsumerService.DEFAULT_ELEMENT_NAME);
						if (j == 0)  responseService.setIsDefault(true);
						if (spDescriptor.getAssertionConsumerServices().size() > 1)  responseService.setIndex(j);
						responseService.setLocation(spDescriptor.getAssertionConsumerServices().get(j).getLocation());
						spDesc.getAssertionConsumerServices().add(responseService);

						SingleLogoutService logoutService = (SingleLogoutService) SAMLUtil.buildXMLObject(SingleLogoutService.DEFAULT_ELEMENT_NAME);
						logoutService.setLocation(spDescriptor.getSingleLogoutServices().get(j).getLocation());
						spDesc.getSingleLogoutServices().add(logoutService);
					}
				}

				spEntity.getRoleDescriptors().add(spDesc);
				spEntities.getEntityDescriptors().add(spEntity);
			}

			while (true) {
				String addSP = readLine("\nSelect SSO Agent : (A)dd / (N)one ? ", true);
				if (addSP.equalsIgnoreCase("A")) {
					EntityDescriptor spEntity = (EntityDescriptor) SAMLUtil.buildXMLObject(EntityDescriptor.DEFAULT_ELEMENT_NAME);
					SPSSODescriptor spDesc = (SPSSODescriptor) SAMLUtil.buildXMLObject(SPSSODescriptor.DEFAULT_ELEMENT_NAME);
					spDesc.setAuthnRequestsSigned(true);
					spDesc.setWantAssertionsSigned(true);

					String spName = readLine("\nEnter SSO Agent Name : ex) TEST_SP\n", true);

					encCert = spName + "_Enc.der";
					sigCert = spName + "_Sig.der";

					outPrint("\nSSO Agent Encryption Certificate File Name : " + spName + "_Enc.der");
					outPrint("\nSSO Agent Signing    Certificate File Name : " + spName + "_Sig.der\n");

					String responseUrl = readLine("\nEnter SSO Agent Response URL : ex) https://sp.dev.com:8443/sso/Response.jsp\n", true);
					String logoutUrl = readLine("\nEnter SSO Agent Logout URL : ex) https://sp.dev.com:8443/sso/Logout.jsp\n", true);

					spEntity.setEntityID(spName);

					X509Certificate encX509Cert = SAMLUtil.getCert(homepath + "/cert/" + encCert);
					Credential encCred = CredentialRepository.createCredential(spName + "_E", encX509Cert);
					KeyInfoGenerator encKeyInfoGen = SecurityHelper
							.getKeyInfoGenerator(encCred, Configuration.getGlobalSecurityConfiguration(), null);

					KeyDescriptor encKeyDescriptor = (KeyDescriptor) SAMLUtil.buildXMLObject(KeyDescriptor.DEFAULT_ELEMENT_NAME);
					encKeyDescriptor.setUse(UsageType.ENCRYPTION);
					encKeyDescriptor.setKeyInfo(encKeyInfoGen.generate(encCred));
					spDesc.getKeyDescriptors().add(encKeyDescriptor);

					X509Certificate sigX509Cert = SAMLUtil.getCert(homepath + "/cert/" + sigCert);
					Credential sigCred = CredentialRepository.createCredential(spName + "_S", sigX509Cert);
					KeyInfoGenerator sigKeyInfoGen = SecurityHelper
							.getKeyInfoGenerator(sigCred, Configuration.getGlobalSecurityConfiguration(), null);

					KeyDescriptor sigKeyDescriptor = (KeyDescriptor) SAMLUtil.buildXMLObject(KeyDescriptor.DEFAULT_ELEMENT_NAME);
					sigKeyDescriptor.setUse(UsageType.SIGNING);
					sigKeyDescriptor.setKeyInfo(sigKeyInfoGen.generate(sigCred));
					spDesc.getKeyDescriptors().add(sigKeyDescriptor);

					AssertionConsumerService responseService = (AssertionConsumerService) SAMLUtil
							.buildXMLObject(AssertionConsumerService.DEFAULT_ELEMENT_NAME);
					responseService.setIsDefault(true);
					responseService.setLocation(responseUrl);
					spDesc.getAssertionConsumerServices().add(responseService);

					SingleLogoutService logoutService = (SingleLogoutService) SAMLUtil.buildXMLObject(SingleLogoutService.DEFAULT_ELEMENT_NAME);
					logoutService.setLocation(logoutUrl);
					spDesc.getSingleLogoutServices().add(logoutService);

					int index = 1;
					while (true) {
						String addURL = readLine("\nSelect SSO Agent URL : (A)dd / (N)one ? ", true);
						if (addURL.equalsIgnoreCase("A")) {
							String addResponseUrl = readLine("\nEnter SSO Agent Add Response URL : ex) https://sp.dev.com:8443/sso/Response.jsp\n", true);
							String addLogoutUrl = readLine("\nEnter SSO Agent Add Logout URL : ex) https://sp.dev.com:8443/sso/Logout.jsp\n", true);

							if (index == 1)
								spDesc.getAssertionConsumerServices().get(0).setIndex(0);
								
							AssertionConsumerService addResponseService =
									(AssertionConsumerService) SAMLUtil.buildXMLObject(AssertionConsumerService.DEFAULT_ELEMENT_NAME);
							addResponseService.setIndex(index);
							addResponseService.setLocation(addResponseUrl);
							spDesc.getAssertionConsumerServices().add(addResponseService);

							SingleLogoutService addLogoutService =
									(SingleLogoutService) SAMLUtil.buildXMLObject(SingleLogoutService.DEFAULT_ELEMENT_NAME);
							addLogoutService.setLocation(addLogoutUrl);
							spDesc.getSingleLogoutServices().add(addLogoutService);
						}
						else {
							break;
						}
					}

					spEntity.getRoleDescriptors().add(spDesc);
					spEntities.getEntityDescriptors().add(spEntity);
				}
				else {
					break;
				}
			}

			parentEntities.getEntitiesDescriptors().add(spEntities);

			SAMLUtil.checkAndMarshall(parentEntities);
			String xmlStr = Util.domToStr(parentEntities.getDOM().getOwnerDocument(), true, "UTF-8");
			//outPrint("\n" + xmlStr + "\n");

			String metaFilename = homepath + "/config/metadata.xml";
			File targetFile = new File(metaFilename);

			BufferedWriter output = new BufferedWriter(new OutputStreamWriter(new FileOutputStream(targetFile.getPath()), "UTF-8"));
			output.write(xmlStr);
			output.close();

			outPrint("\n>>> SSO Metadata Initialization Complete !!!\n");

			setIntegrityJar(homepath, DEK.getKey().clone());
			setIntegrityFile(rootpath + ssopath, homepath, DEK.getKey().clone());

			outPrint("\n>>> SSO Integrity Initialization Complete !!!\n\n");
		}
		catch (Exception e) {
			outPrint("\nInitialize SSO Exception : " + e.getMessage() + "\n\n");
		}
		finally {
			if (KEK != null)  KEK.finalize();
			if (DEK != null)  DEK.finalize();
		}
	}
}