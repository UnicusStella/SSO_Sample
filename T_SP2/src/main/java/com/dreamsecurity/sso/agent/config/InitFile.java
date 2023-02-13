package com.dreamsecurity.sso.agent.config;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Comparator;
import java.util.Scanner;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import com.dreamsecurity.jcaos.asn1.oid.AlgorithmObjectIdentifiers;
import com.dreamsecurity.jcaos.asn1.oid.PKCS5ObjectIdentifiers;
import com.dreamsecurity.jcaos.jce.provider.JCAOSProvider;
import com.dreamsecurity.jcaos.pkcs.PKCS8PrivateKeyInfo;
import com.dreamsecurity.jcaos.util.FileUtil;
import com.dreamsecurity.jcaos.util.encoders.Hex;
import com.dreamsecurity.sso.agent.common.MStatus;
import com.dreamsecurity.sso.agent.crypto.ASN1Util;
import com.dreamsecurity.sso.agent.crypto.CryptoApiException;
import com.dreamsecurity.sso.agent.crypto.SSOSecretKey;
import com.dreamsecurity.sso.agent.util.Util;
import com.dreamsecurity.sso.lib.ccf.XMLConfiguration;

public class InitFile
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

			String ssopath = com.dreamsecurity.sso.sp.crypto.api.MJCryptoApi.class
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
		}
		finally {
			Util.zeroize(key);
			if (bw != null) try { bw.close(); } catch (IOException ie) {}
		}
	}

	public static int setIntegrityFile(String rootpath, String ssopath, String homepath, byte[] key)
	{
		BufferedWriter bw = null;
		int result = 0;

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
					if (index > 0) {
						file = file.substring(0, index);
					}

					String fullpathfile = "";
					int idxsso = pathList.get(i).indexOf("/sso");
					if (idxsso == 0) {
						fullpathfile = rootpath + ssopath + pathList.get(i).substring(4) + "/" + file;
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

			String allhmac = hmac(out.toString().getBytes(), key.clone()) + "\u001a";

			outFile = homepath + "/config/integrity.cfg.hmac";
			bw = new BufferedWriter(new FileWriter(outFile));
			bw.write(allhmac + "\n");
			bw.flush();
			bw.close();
			result = 1;
		}
		catch (Exception e) {
			e.printStackTrace();
			result = 0;
		}
		finally {
			Util.zeroize(key);
			if (bw != null) try { bw.close(); } catch (IOException ie) {}
		}

		return result;
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

			outPrint("\n>>> SSO Integrity Initialization  (Cancel: \"cancel\" Input)\n");

			String rootpath = readLine("\nEnter WAS Container Root Full Path : ex) /home/tomcat/webapps\n", true);

			String homepath = readLine("\nEnter Magic SSO Config Home Full Path : ex) /home/dreamsso\n", true);

			String ssopath  = readLine("\nEnter Magic SSO Home Path : default) /sso\n", false);
			if (ssopath.equals("")) {
				ssopath = "/sso";
			}

			String name = readLine("\nEnter SSO Agent Name : ex) TEST_SP\n", true);

			String xmlFile = homepath + "/config/application/sp.xml";
			XMLConfiguration config = new XMLConfiguration(xmlFile);
			config.setThrowExceptionOnMissing(false);
			String strDEK = config.getString("server.code", "");
			String strBlock = config.getString("server.block", "");

			KEK = generateKEKByPwd(name, homepath + "/cert/" + name + "_Enc.der");

			if (Util.isEmpty(strDEK)) {
				throw new Exception("[server.code] Value Empty.");
			}
			else {
				KEK.setIv(Hex.decode(strBlock));
				byte[] decDEK = decrypt(KEK.getKey(), KEK.getIv(), Hex.decode(strDEK));
				DEK = new SSOSecretKey("SEED", decDEK);
			}

			setIntegrityJar(homepath, DEK.getKey().clone());
			setIntegrityFile(rootpath, ssopath, homepath, DEK.getKey().clone());

			outPrint("\n>>> SSO Integrity Initialization Complete !!!\n\n");
		}
		catch (Throwable e) {
			e.printStackTrace();
			outPrint("\nCancel Initialize SSO\n\n");
		}
		finally {
			if (KEK != null)  KEK.finalize();
			if (DEK != null)  DEK.finalize();
		}
	}
}