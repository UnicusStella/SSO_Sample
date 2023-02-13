package com.dreamsecurity.sso.server.config;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.Scanner;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import com.dreamsecurity.jcaos.jce.provider.JCAOSProvider;
import com.dreamsecurity.jcaos.util.FileUtil;
import com.dreamsecurity.jcaos.util.encoders.Hex;
import com.dreamsecurity.sso.lib.ccf.XMLConfiguration;
import com.dreamsecurity.sso.server.common.MStatus;
import com.dreamsecurity.sso.server.crypto.CryptoApiException;
import com.dreamsecurity.sso.server.crypto.SSOSecretKey;
import com.dreamsecurity.sso.server.util.Util;

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
			byte[] ivParam = new byte[16];
			System.arraycopy(dk, 0, skParam, 0, skParam.length);

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

			String name = readLine("\nEnter SSO Server Name : ex) TEST_IDP\n", true);

			String xmlFile = homepath + "/config/application/idp.xml";
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
			setIntegrityFile(rootpath + ssopath, homepath, DEK.getKey().clone());

			outPrint("\n>>> SSO Integrity Initialization Complete !!!\n\n");
		}
		catch (Exception e) {
			outPrint("\nInitialize SSO Exception : " + e.getMessage() + "\n");
		}
		finally {
			if (KEK != null)  KEK.finalize();
			if (DEK != null)  DEK.finalize();
		}
	}
}