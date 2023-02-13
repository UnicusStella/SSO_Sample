package com.dreamsecurity.sso.server.config;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.security.MessageDigest;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;
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
import com.dreamsecurity.sso.server.crypto.CryptoApiException;
import com.dreamsecurity.sso.server.crypto.SSOSecretKey;
import com.dreamsecurity.sso.server.metadata.CredentialRepository;
import com.dreamsecurity.sso.server.metadata.MetadataRepository;
import com.dreamsecurity.sso.server.util.SAMLUtil;
import com.dreamsecurity.sso.server.util.Util;

public class InitMeta
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

			outPrint("\n>>> SSO Metadata Initialization  (Cancel: \"cancel\" Input)\n");

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