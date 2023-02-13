package com.dreamsecurity.sso.agent.api;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLEncoder;
import java.security.cert.CertificateException;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

import com.dreamsecurity.sso.agent.common.MStatus;
import com.dreamsecurity.sso.agent.config.SSOConfig;
import com.dreamsecurity.sso.agent.crypto.SSOCryptoApi;
import com.dreamsecurity.sso.agent.log.Logger;
import com.dreamsecurity.sso.agent.log.LoggerFactory;
import com.dreamsecurity.sso.agent.metadata.MetadataRepository;
import com.dreamsecurity.sso.agent.util.Util;
import com.dreamsecurity.sso.lib.dss.s2.metadata.IDPSSODescriptor;
import com.dreamsecurity.sso.lib.jsn.JSONObject;
import com.dreamsecurity.sso.lib.jsn.parser.JSONParser;

public class UserService
{
	private static Logger log = LoggerFactory.getInstance().getLogger(UserService.class);

	public static JSONObject checkFirstLogin(String uid)
	{
		JSONObject result = null;

		try {
			IDPSSODescriptor idp = MetadataRepository.getInstance().getIDPDescriptor();
			String idpUrl = idp.getSingleSignOnServices().get(0).getLocation();
			int idx = idpUrl.indexOf("sso");
			if (idx == -1) {
				log.error("### checkFirst: Invalid Request Url: " + idpUrl);
				result = new JSONObject();
				result.put("code", String.valueOf(8503));
				result.put("message", "SP: Invalid Request Url");
				result.put("data", "");
				return result;
			}
			else {
				idpUrl = idpUrl.substring(0, idx + 3) + "/setUserInfo.jsp";
			}

			String tid = Util.createTransferId();

			JSONObject jData = new JSONObject();
			jData.put("cmd", "checkfirst");
			jData.put("id", uid);
			jData.put("xid", tid);

			String encData = SSOCryptoApi.getInstance().encryptJsonObject(jData);

			StringBuffer param = new StringBuffer();
			param.append("ED=").append(URLEncoder.encode(encData, "UTF-8"));

			result = sendHttpRequest(idpUrl, param.toString());
		}
		catch (Exception e) {
			log.error("### checkFirst Exception: " + e.getMessage());
			e.printStackTrace();

			result = new JSONObject();
			result.put("code", String.valueOf(8504));
			result.put("message", "SP: checkFirst Exception");
			result.put("data", "");
		}

		return result;
	}

	public static JSONObject setInitPw(String uid, String newPw)
	{
		JSONObject result = null;

		try {
			IDPSSODescriptor idp = MetadataRepository.getInstance().getIDPDescriptor();
			String idpUrl = idp.getSingleSignOnServices().get(0).getLocation();
			int idx = idpUrl.indexOf("sso");
			if (idx == -1) {
				log.error("### setInitPw: Invalid Request Url: " + idpUrl);
				result = new JSONObject();
				result.put("code", String.valueOf(8505));
				result.put("message", "SP: Invalid Request Url");
				result.put("data", "");
				return result;
			}
			else {
				idpUrl = idpUrl.substring(0, idx + 3) + "/setUserInfo.jsp";
			}

			String tid = Util.createTransferId();

			JSONObject jData = new JSONObject();
			jData.put("cmd", "initpw");
			jData.put("id", uid);
			jData.put("npw", newPw);
			jData.put("xid", tid);

			String encData = SSOCryptoApi.getInstance().encryptJsonObject(jData);

			StringBuffer param = new StringBuffer();
			param.append("ED=").append(URLEncoder.encode(encData, "UTF-8"));

			result = sendHttpRequest(idpUrl, param.toString());
		}
		catch (Exception e) {
			log.error("### setInitPw Exception: " + e.getMessage());
			e.printStackTrace();

			result = new JSONObject();
			result.put("code", String.valueOf(8506));
			result.put("message", "SP: setInitPw Exception");
			result.put("data", "");
		}

		return result;
	}

	public static JSONObject setChangePw(String uid, String curPw, String newPw)
	{
		JSONObject result = null;

		try {
			IDPSSODescriptor idp = MetadataRepository.getInstance().getIDPDescriptor();
			String idpUrl = idp.getSingleSignOnServices().get(0).getLocation();
			int idx = idpUrl.indexOf("sso");
			if (idx == -1) {
				log.error("### setChangePw: Invalid Request Url: " + idpUrl);
				result = new JSONObject();
				result.put("code", String.valueOf(8507));
				result.put("message", "SP: Invalid Request Url");
				result.put("data", "");
				return result;
			}
			else {
				idpUrl = idpUrl.substring(0, idx + 3) + "/setUserInfo.jsp";
			}

			String tid = Util.createTransferId();

			JSONObject jData = new JSONObject();
			jData.put("cmd", "changepw");
			jData.put("id", uid);
			jData.put("cpw", curPw);
			jData.put("npw", newPw);
			jData.put("xid", tid);

			String encData = SSOCryptoApi.getInstance().encryptJsonObject(jData);

			StringBuffer param = new StringBuffer();
			param.append("ED=").append(URLEncoder.encode(encData, "UTF-8"));

			result = sendHttpRequest(idpUrl, param.toString());
		}
		catch (Exception e) {
			log.error("### setChangePw Exception: " + e.getMessage());
			e.printStackTrace();

			result = new JSONObject();
			result.put("code", String.valueOf(8508));
			result.put("message", "SP: setChangePw Exception");
			result.put("data", "");
		}

		return result;
	}

	public static JSONObject setUnlockUser(String uid)
	{
		JSONObject result = null;

		try {
			IDPSSODescriptor idp = MetadataRepository.getInstance().getIDPDescriptor();
			String idpUrl = idp.getSingleSignOnServices().get(0).getLocation();
			int idx = idpUrl.indexOf("sso");
			if (idx == -1) {
				log.error("### setUnlockUser: Invalid Request Url: " + idpUrl);
				result = new JSONObject();
				result.put("code", String.valueOf(8509));
				result.put("message", "SP: Invalid Request Url");
				result.put("data", "");
				return result;
			}
			else {
				idpUrl = idpUrl.substring(0, idx + 3) + "/setUserInfo.jsp";
			}

			String tid = Util.createTransferId();

			JSONObject jData = new JSONObject();
			jData.put("cmd", "unlockuser");
			jData.put("id", uid);
			jData.put("xid", tid);

			String encData = SSOCryptoApi.getInstance().encryptJsonObject(jData);

			StringBuffer param = new StringBuffer();
			param.append("ED=").append(URLEncoder.encode(encData, "UTF-8"));

			result = sendHttpRequest(idpUrl, param.toString());
		}
		catch (Exception e) {
			log.error("### setUnlockUser Exception: " + e.getMessage());
			e.printStackTrace();

			result = new JSONObject();
			result.put("code", String.valueOf(8510));
			result.put("message", "SP: setUnlockUser Exception");
			result.put("data", "");
		}

		return result;
	}

	public static JSONObject checkPw(String uid, String upw)
	{
		JSONObject result = null;

		try {
			IDPSSODescriptor idp = MetadataRepository.getInstance().getIDPDescriptor();
			String idpUrl = idp.getSingleSignOnServices().get(0).getLocation();
			int idx = idpUrl.indexOf("sso");

			if (idx == -1) {
				log.error("### checkPw: Invalid Request Url: " + idpUrl);

				result = new JSONObject();
				result.put("code", String.valueOf(8511));
				result.put("message", "SP: Invalid Request Url");
				result.put("data", "");
				return result;
			}
			else {
				idpUrl = idpUrl.substring(0, idx + 3) + "/setUserInfo.jsp";
			}

			String tid = Util.createTransferId();

			JSONObject jData = new JSONObject();
			jData.put("cmd", "checkpw");
			jData.put("id", uid);
			jData.put("pw", upw);
			jData.put("xid", tid);

			String encData = SSOCryptoApi.getInstance().encryptJsonObject(jData);

			StringBuffer param = new StringBuffer();
			param.append("ED=").append(URLEncoder.encode(encData, "UTF-8"));

			result = sendHttpRequest(idpUrl, param.toString());
		}
		catch (Exception e) {
			log.error("### checkPw Exception: " + e.getMessage());
			e.printStackTrace();

			result = new JSONObject();
			result.put("code", String.valueOf(8512));
			result.put("message", "SP: checkPw Exception");
			result.put("data", "");
		}

		return result;
	}

	private static JSONObject sendHttpRequest(String requestUrl, String param)
	{
		JSONObject result = new JSONObject();

		try {
			if (requestUrl.indexOf("https") >= 0) {
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

			URL url = new URL(requestUrl);

			HttpURLConnection urlConn = (HttpURLConnection) url.openConnection();
			urlConn.setRequestMethod("POST");
			urlConn.setDoOutput(true);
			urlConn.setRequestProperty("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8");

			OutputStream stream = urlConn.getOutputStream();
			stream.write(param.getBytes("UTF-8"));
			stream.flush();
			stream.close();

			int rcode = urlConn.getResponseCode();
			if (rcode != 200) {
				result.put("code", String.valueOf(8501));
				result.put("message", "SP: http response error " + rcode);
				result.put("data", "");
				return result;
			}

			BufferedReader br = new BufferedReader(new InputStreamReader(urlConn.getInputStream(), "UTF-8"));

			StringBuffer strBuffer = new StringBuffer();
			String strLine = "";

			while ((strLine = br.readLine()) != null) {
				strBuffer.append(strLine);
			}

			br.close();
			urlConn.disconnect();

			JSONParser parser = new JSONParser();
			JSONObject jsonResponse = (JSONObject) parser.parse(strBuffer.toString());

			result.put("code", jsonResponse.get("code"));
			result.put("message", jsonResponse.get("message"));
			result.put("data", jsonResponse.get("data"));
		}
		catch (Exception e) {
			result.put("code", String.valueOf(8502));
			result.put("message", "SP: sendHttpRequest Exception: " + e.getMessage());
			result.put("data", "");

			e.printStackTrace();
		}

		return result;
	}
}