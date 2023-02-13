package com.dreamsecurity.sso.agent.api;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLEncoder;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

import com.dreamsecurity.jcaos.util.FileUtil;
import com.dreamsecurity.sso.agent.config.SSOConfig;
import com.dreamsecurity.sso.agent.crypto.SSOCryptoApi;
import com.dreamsecurity.sso.agent.ha.SyncEvent;
import com.dreamsecurity.sso.agent.ha.SyncMonitor;
import com.dreamsecurity.sso.agent.log.Logger;
import com.dreamsecurity.sso.agent.log.LoggerFactory;
import com.dreamsecurity.sso.agent.metadata.MetadataRepository;
import com.dreamsecurity.sso.agent.util.Util;
import com.dreamsecurity.sso.lib.dss.s2.metadata.IDPSSODescriptor;
import com.dreamsecurity.sso.lib.jsn.JSONObject;

public class AuditService
{
	private static Logger log = LoggerFactory.getInstance().getLogger(AuditService.class);

	public AuditService()
	{
	}

	public void setAuditInfo(String logDate, String logTime, String caseUser, String caseType,
			String caseResult, String caseData)
	{
		SSOConfig config = SSOConfig.getInstance();

		if (!config.isAuditLogSend()) {
			return;
		}

		try {
			IDPSSODescriptor idp = MetadataRepository.getInstance().getIDPDescriptor();
			String idpUrl = idp.getSingleSignOnServices().get(0).getLocation();
			int idx = idpUrl.indexOf("sso");
			if (idx == -1)
				return;
			else
				idpUrl = idpUrl.substring(0, idx + 3) + "/setAuditInfo.jsp";

			URL url = new URL(idpUrl);

			JSONObject jData = new JSONObject();
			jData.put("ld", logDate);
			jData.put("lt", logTime);
			jData.put("cu", caseUser);
			jData.put("ct", caseType);
			jData.put("cr", caseResult);
			jData.put("cd", caseData);
			jData.put("xfr", config.getServerName());
			jData.put("xto", MetadataRepository.getInstance().getIDPName());

			String encData = SSOCryptoApi.getInstance().encryptHttpParam(idpUrl, jData);

			StringBuilder param = new StringBuilder();
			param.append("ED=").append(URLEncoder.encode(encData, "UTF-8"));

			if (idpUrl.indexOf("https") >= 0) {
				TrustManager[] trustAllCerts = new TrustManager[] { new X509TrustManager()
				{
					public java.security.cert.X509Certificate[] getAcceptedIssuers()
					{
						return null;
					}

					public void checkClientTrusted(java.security.cert.X509Certificate[] arg0, String arg1) throws CertificateException
					{
					}

					public void checkServerTrusted(java.security.cert.X509Certificate[] arg0, String arg1) throws CertificateException
					{
					}
				} };

				SSLContext sc = SSLContext.getInstance("SSL");
				sc.init(null, trustAllCerts, new java.security.SecureRandom());
				HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());
				HttpsURLConnection.setDefaultHostnameVerifier(new HostnameVerifier()
				{
					public boolean verify(String hostname, javax.net.ssl.SSLSession sslSession)
					{
						return true;
					}
				});
			}

			HttpURLConnection urlConn = (HttpURLConnection) url.openConnection();
			urlConn.setRequestMethod("POST");
			urlConn.setDoOutput(true);
			urlConn.setRequestProperty("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8");

			OutputStream stream = urlConn.getOutputStream();
			stream.write(param.toString().getBytes("UTF-8"));
			stream.flush();
			stream.close();

			int rcode = urlConn.getResponseCode();
			if (rcode != 200)
				log.error("createAuditInfo() response error : " + rcode);
		}
		catch (Exception e) {
			log.error(e.toString());
		}
	}

	public void setAuditInfo(String caseUser, String caseType, String caseResult, String caseData)
	{
		SSOConfig config = SSOConfig.getInstance();

		if (!config.isAuditLogSend()) {
			return;
		}

		try {
			IDPSSODescriptor idp = MetadataRepository.getInstance().getIDPDescriptor();
			String idpUrl = idp.getSingleSignOnServices().get(0).getLocation();
			int idx = idpUrl.indexOf("sso");
			if (idx == -1)
				return;
			else
				idpUrl = idpUrl.substring(0, idx + 3) + "/setAuditInfo.jsp";

			URL url = new URL(idpUrl);

			JSONObject jData = new JSONObject();
			jData.put("ld", Util.getDateFormat("yyyyMMdd"));
			jData.put("lt", Util.getDateFormat("HHmmss"));
			jData.put("cu", caseUser);
			jData.put("ct", caseType);
			jData.put("cr", caseResult);
			jData.put("cd", caseData);
			jData.put("xfr", config.getServerName());
			jData.put("xto", MetadataRepository.getInstance().getIDPName());

			String encData = SSOCryptoApi.getInstance().encryptHttpParam(idpUrl, jData);

			StringBuilder param = new StringBuilder();
			param.append("ED=").append(URLEncoder.encode(encData, "UTF-8"));

			if (idpUrl.indexOf("https") >= 0) {
				TrustManager[] trustAllCerts = new TrustManager[] { new X509TrustManager()
				{
					public java.security.cert.X509Certificate[] getAcceptedIssuers()
					{
						return null;
					}

					public void checkClientTrusted(java.security.cert.X509Certificate[] arg0, String arg1) throws CertificateException
					{
					}

					public void checkServerTrusted(java.security.cert.X509Certificate[] arg0, String arg1) throws CertificateException
					{
					}
				} };

				SSLContext sc = SSLContext.getInstance("SSL");
				sc.init(null, trustAllCerts, new java.security.SecureRandom());
				HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());
				HttpsURLConnection.setDefaultHostnameVerifier(new HostnameVerifier()
				{
					public boolean verify(String hostname, javax.net.ssl.SSLSession sslSession)
					{
						return true;
					}
				});
			}

			HttpURLConnection urlConn = (HttpURLConnection) url.openConnection();
			urlConn.setRequestMethod("POST");
			urlConn.setDoOutput(true);
			urlConn.setRequestProperty("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8");

			OutputStream stream = urlConn.getOutputStream();
			stream.write(param.toString().getBytes("UTF-8"));
			stream.flush();
			stream.close();

			int rcode = urlConn.getResponseCode();
			if (rcode != 200)
				log.error("createAuditInfo() response error : " + rcode);
		}
		catch (Exception e) {
			log.error(e.toString());
		}
	}

	public ArrayList<String> getVerifyPathList()
	{
		BufferedReader br = null;
		ArrayList<String> pathList = new ArrayList<String>();

		try {
			String inFile = SSOConfig.getInstance().getHomePath("config/integrity.cfg");

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

	public ArrayList<String> getVerifyFileList(String path)
	{
		BufferedReader br = null;
		ArrayList<String> fileList = new ArrayList<String>();

		try {
			String inFile = SSOConfig.getInstance().getHomePath("config/integrity.cfg");

			br = new BufferedReader(new FileReader(inFile));
			boolean bPath = false;
			String line;

			while ((line = br.readLine()) != null) {
				line = line.trim();
				if (Util.isEmpty(line)) continue;
				int index1 = line.indexOf("[");
				int index2 = line.indexOf("]");
				if (index1 == 0 && index2 > 0) {
					if (path.equals(line.substring(index1 + 1, index2)))
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

	public int setIntegrityFile()
	{
		BufferedWriter bw = null;

		try {
			SSOConfig config = SSOConfig.getInstance();
			SSOCryptoApi crypto = SSOCryptoApi.getInstance();
			StringBuilder out = new StringBuilder();

			ArrayList<String> pathList = getVerifyPathList();

			for (int i = 0; i < pathList.size(); i++) {
				if (out.length() != 0) { out.append("\n"); }
				out.append("[" + pathList.get(i) + "]\n");

				ArrayList<String> fileList = getVerifyFileList(pathList.get(i));

				for (int j = 0; j < fileList.size(); j++) {
					String file = fileList.get(j);
					int index = file.indexOf(";");
					if (index > -1) {
						file = file.substring(0, index);
					}

					String fullpathfile = "";
					int idxsso = pathList.get(i).indexOf("/sso");
					if (idxsso == 0) {
						fullpathfile = config.getSsoHomepath() + pathList.get(i).substring(4) + "/" + file;
					}
					else {
						fullpathfile = config.getHomePath() + pathList.get(i) + "/" + file;
					}

					byte[] fileByte = FileUtil.read(fullpathfile);
					if (fileByte == null || fileByte.length < 0) {
						throw new Exception(fileList.get(j) + " file is not exist.");
					}

					String hmac = crypto.hmacByDEK(fileByte);

					out.append(file + ";" + hmac + "\n");
				}
			}

			String outFile = config.getHomePath("config/integrity.cfg");
			bw = new BufferedWriter(new FileWriter(outFile));
			bw.write(out.toString());
			bw.flush();
			bw.close();

			String allhmac = crypto.hmacByDEK(out.toString().getBytes());

			outFile = config.getHomePath("config/integrity.cfg.hmac");
			bw = new BufferedWriter(new FileWriter(outFile));
			bw.write(allhmac + "\n");
			bw.flush();
			bw.close();
		}
		catch (Exception e) {
			e.printStackTrace();
			if (bw != null) try { bw.close(); } catch (IOException ie) {}
			return -1;
		}

		return 0;
	}

	public void setIntegrityJar()
	{
		BufferedWriter bw = null;

		try {
			SSOCryptoApi crypto = SSOCryptoApi.getInstance();

			String cryptopath = com.dreamsecurity.kcmv.jce.provider.MagicJCryptoProvider.class
					.getProtectionDomain().getCodeSource().getLocation().getPath() + ".hmac";

			String ssopath = com.dreamsecurity.sso.sp.crypto.api.MJCryptoApi.class
					.getProtectionDomain().getCodeSource().getLocation().getPath();

			if (!Util.isEmpty(ssopath) && ssopath.length() >= 4 && !ssopath.substring(ssopath.length() - 4).equalsIgnoreCase(".jar")) {
				ssopath = SSOConfig.getInstance().getHomePath("config/" + SSOConfig.getJarVersion() + ".jar");
			}

			String hmacPath = SSOConfig.getInstance().getHomePath("config/" + SSOConfig.getJarVersion() + ".jar.hmac");

			// crypto
			byte[] cryptofileByte = FileUtil.read(cryptopath);
			if (cryptofileByte == null || cryptofileByte.length < 0)
				throw new Exception(cryptopath + " file is not exist.");

			String cryptojarHmac = crypto.hmacByDEK(cryptofileByte);
			
			// sso
			byte[] fileByte = FileUtil.read(ssopath);
			if (fileByte == null || fileByte.length < 0)
				throw new Exception(ssopath + " file is not exist.");

			String jarHmac = crypto.hmacByDEK(fileByte);

			bw = new BufferedWriter(new FileWriter(hmacPath));
			bw.write(cryptojarHmac + "\n" + jarHmac);
			bw.flush();
		}
		catch (Exception e) {
			e.printStackTrace();
		}
		finally {
			if (bw != null) try { bw.close(); } catch (IOException ie) {}
		}
	}

	public void integrityTestSync(String encData)
	{
		try {
			// 이중화 서버 동기화
			SyncMonitor.startMonitor();
			SyncEvent event = new SyncEvent(SyncEvent.EVENT_INTEGRITY, System.currentTimeMillis(), "", encData);
			SyncMonitor.sendEvent(event);

			integrityTest(encData);
		}
		catch (Exception e) {
			e.printStackTrace();
		}
	}

	public void integrityTest(String encData)
	{
		try {
			SSOCryptoApi crypto = SSOCryptoApi.getInstance();
			JSONObject jData = crypto.decryptHttpParam(encData);

			String admnid = (String) jData.get("ad");
			String detail = (String) jData.get("dt");

			crypto.cryptoIntegrity(admnid, detail);
			crypto.ssoIntegrity(admnid, detail);
			crypto.ssoProcess(admnid, detail);
		}
		catch (Exception e) {
			e.printStackTrace();
		}
	}

	public void integritySelfTest()
	{
		try {
			SSOConfig config = SSOConfig.getInstance();
			SSOCryptoApi crypto = SSOCryptoApi.getInstance();

			crypto.cryptoIntegrity(config.getServerName(), config.getServerName() + ", 에이전트 자가 테스트");
			crypto.ssoIntegrity(config.getServerName(), config.getServerName() + ", 에이전트 자가 테스트");
			crypto.ssoProcess(config.getServerName(), config.getServerName() + ", 에이전트 자가 테스트");
		}
		catch (Exception e) {
			e.printStackTrace();
		}
	}

	public int resetIntegrityFile()
	{
		int result = -1;

		try {
			result = setIntegrityFile();

			if (result == 0) {
				SSOConfig config = SSOConfig.getInstance();
				SSOCryptoApi crypto = SSOCryptoApi.getInstance();

				crypto.ssoIntegrity(config.getServerName(), config.getServerName() + ", 에이전트 자가 테스트");
			}
		}
		catch (Exception e) {
			e.printStackTrace();
		}

		return result;
	}
}