package com.dreamsecurity.sso.agent.provider;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLEncoder;
import java.security.cert.CertificateException;
import java.util.Iterator;
import java.util.List;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

import com.dreamsecurity.sso.agent.client.ClientModel;
import com.dreamsecurity.sso.agent.client.ClientRepository;
import com.dreamsecurity.sso.agent.common.MStatus;
import com.dreamsecurity.sso.agent.config.SSOConfig;
import com.dreamsecurity.sso.agent.crypto.CryptoApiException;
import com.dreamsecurity.sso.agent.crypto.SSOCryptoApi;
import com.dreamsecurity.sso.agent.exception.SSOException;
import com.dreamsecurity.sso.agent.jwt.JWTBuilder;
import com.dreamsecurity.sso.agent.log.Logger;
import com.dreamsecurity.sso.agent.log.LoggerFactory;
import com.dreamsecurity.sso.agent.util.OIDCUtil;
import com.dreamsecurity.sso.agent.util.Util;
import com.dreamsecurity.sso.lib.jsn.JSONObject;
import com.dreamsecurity.sso.lib.jsn.parser.JSONParser;

public class OidcServiceProvider
{
	private static OidcServiceProvider instance = null;
	private static Logger log = LoggerFactory.getInstance().getLogger(OidcServiceProvider.class);

	public static OidcServiceProvider getInstance() throws SSOException
	{
		if (instance == null) {
			synchronized (OidcServiceProvider.class) {
				if (instance == null) {
					instance = new OidcServiceProvider();
				}
			}
		}

		return instance;
	}

	public JSONObject generateOidcAuthRequest(HttpServletRequest request)
	{
		JSONObject result = null;

		try {
			String response_type = "";
			String state = "";
			String scope = "";
			String clientId = "";
			String nonceEnabled = "";
			String pkceEnabled = "";
			String url = "";
			String authEndpoint = "";
			String redirectUrl = "";
			String logoutUrl = "";
			List<Object> allowScopeList;

			redirectUrl = (String) SSOConfig.getInstance().getProperty("oidc.redirecturi");
			logoutUrl = (String) SSOConfig.getInstance().getProperty("oidc.logout.base");

			if (Util.isEmpty(redirectUrl)) {
				result = new JSONObject();
				result.put("code", String.valueOf(MStatus.ERR_CLIENT_OIDC_SETTING_ERROR));
				result.put("message", "generateOidcAuthParameter() oidc redirectUrl setting error");
				result.put("data", "");
				return result;
			}

			if (Util.isEmpty(logoutUrl)) {
				result = new JSONObject();
				result.put("code", String.valueOf(MStatus.ERR_CLIENT_OIDC_SETTING_ERROR));
				result.put("message", "generateOidcAuthParameter() oidc redirectUrl setting error");
				result.put("data", "");
				return result;
			}

			JSONObject authParameter = new JSONObject();
			ClientRepository clientRepository = ClientRepository.getInstance();

			if (clientRepository == null) {
				result = new JSONObject();
				result.put("code", String.valueOf(MStatus.ERR_CLIENT_REPOSITORY_GET_FAIL));
				result.put("message", "generateOidcAuthParameter() clientRepository get fail");
				result.put("data", "");
				return result;
			}

			ClientModel clientModel = clientRepository.getClientModel();

			clientId = clientModel.getId();
			response_type = clientModel.getResponseType();
			authEndpoint = clientModel.getAuthEndpoint();

			state = OIDCUtil.generateUUID();
			nonceEnabled = clientModel.getNonce();
			pkceEnabled = clientModel.getPkce();
			allowScopeList = clientModel.getScopes();

			for (int i = 0; i < allowScopeList.size(); i++) {
				scope = scope + allowScopeList.get(i);
				if (i + 1 != allowScopeList.size()) {
					scope = scope + "+";
				}
			}

			HttpSession session = request.getSession(true);

			if (nonceEnabled.equals("1")) {
				String nonce = OIDCUtil.generateUUID();
				authParameter.put("nonce", nonce);
				session.setAttribute("nonce", nonce);
			}

			if (pkceEnabled.equals("1")) {
				SSOCryptoApi cryptoApi = SSOCryptoApi.getInstance();
				String codeVerifier = OIDCUtil.randomString();
				String codeChallengeMethod = "S256";
				String codeChallenge = cryptoApi.hash(codeVerifier);

				authParameter.put("code_challenge", codeChallenge);
				authParameter.put("code_challenge_method", codeChallengeMethod);

				session.setAttribute("code_challenge", codeChallenge);
				session.setAttribute("code_challenge_method", codeChallengeMethod);
				session.setAttribute("code_verifier", codeVerifier);
			}

			session.setAttribute("state", state);

			authParameter.put("client_id", clientId);
			authParameter.put("state", state);
			authParameter.put("response_type", response_type);
			authParameter.put("scope", scope);
			authParameter.put("logout_uri", logoutUrl);

			Iterator<String> iterator = authParameter.keySet().iterator();
			StringBuffer addParam = new StringBuffer();

			while (iterator.hasNext()) {
				String name = (String) iterator.next();
				String value = (String) authParameter.get(name);

				value = URLEncoder.encode(value, "UTF-8");

				if (addParam.length() > 0) {
					addParam.append("&");
				}

				addParam.append(name).append("=").append(value);
			}
			addParam.append("&redirect_uri").append("=").append(URLEncoder.encode(redirectUrl, "UTF-8"));

			url = authEndpoint;

			if (!Util.isEmpty(addParam.toString())) {
				int index = url.indexOf("?");

				if (index == -1) {
					url = url + "?" + addParam.toString();
				}
				else {
					url = url + "&" + addParam.toString();
				}
			}

			result = new JSONObject();
			result.put("code", String.valueOf(MStatus.SUCCESS));
			result.put("message", "SUCCESS");
			result.put("data", url);
		}
		catch (IOException e) {
			result = new JSONObject();
			result.put("code", String.valueOf(MStatus.ERR_CLIENT_EXCEPTION));
			result.put("message", "generateOidcAuthParameter() IOException: " + e.getMessage());
			result.put("data", "");
			e.printStackTrace();
		}
		catch (CryptoApiException e) {
			result = new JSONObject();
			result.put("code", String.valueOf(e.getCode()));
			result.put("message", "generateOidcAuthParameter() CryptoApiException: " + e.getMessage());
			result.put("data", "");
			log.debug("### generateAuthnRequest() CryptoApiException: " + e.getCode() + ", " + e.getMessage());
			e.printStackTrace();
		}
		return result;
	}

	public JSONObject generateOidcTokenRequest(HttpServletRequest request)
	{
		JSONObject result = null;

		try {
			String resState = "";
			String code = "";
			String redirectUrl = "";
			String tokenEndpoint = "";
			String grantType = "";
			String clientId = "";
			String codeVerifier = "";
			String pkceEnabled = "";
			String secret = "";
			String error = request.getParameter("error") == null ? "" : request.getParameter("error");
			String error_description = request.getParameter("error_description") == null ? "" : request.getParameter("error_description");
			String error_code = request.getParameter("error_code") == null ? "" : request.getParameter("error_code");

			resState = request.getParameter("state") == null ? "" : request.getParameter("state");
			code = request.getParameter("code") == null ? "" : request.getParameter("code");
			redirectUrl = (String) SSOConfig.getInstance().getProperty("oidc.redirecturi");

			if (!Util.isEmpty(error)) {
				result = new JSONObject();
				result.put("code", String.valueOf(MStatus.ERR_CLIENT_RES_DATA));
				result.put("message", "generateOidcTokenRequest() error: [" + error + "] error_description : [" + error_description
						+ "] error_code : [" + error_code + "]");
				result.put("data", "");
				return result;
			}

			if (Util.isEmpty(resState)) {
				result = new JSONObject();
				result.put("code", String.valueOf(MStatus.ERR_CLIENT_RES_PARAMETER_EMPTY));
				result.put("message", "generateOidcTokenRequest() resState NULL");
				result.put("data", "");
				return result;
			}

			if (Util.isEmpty(code)) {
				result = new JSONObject();
				result.put("code", String.valueOf(MStatus.ERR_CLIENT_RES_PARAMETER_EMPTY));
				result.put("message", "generateOidcTokenRequest() code NULL");
				result.put("data", "");
				return result;
			}

			HttpSession session = request.getSession(false);

			if (session == null) {
				result = new JSONObject();
				result.put("code", String.valueOf(MStatus.ERR_CLIENT_SESSION_INVALID));
				result.put("message", "generateOidcTokenRequest() session NULL");
				result.put("data", "");
				return result;
			}

			String reqState = (String) session.getAttribute("state");

			if (!resState.equals(reqState)) {
				result = new JSONObject();
				result.put("code", String.valueOf(MStatus.ERR_CLIENT_MISMATCH_STATE));
				result.put("message", "generateOidcTokenRequest() state Different");
				result.put("data", "");
				return result;
			}

			session.removeAttribute("state");

			ClientRepository clientRepository = ClientRepository.getInstance();

			if (clientRepository == null) {
				result = new JSONObject();
				result.put("code", String.valueOf(MStatus.ERR_CLIENT_REPOSITORY_GET_FAIL));
				result.put("message", "generateOidcTokenRequest() clientRepository get fail");
				result.put("data", "");
				return result;
			}

			ClientModel clientModel = clientRepository.getClientModel();

			JSONObject authParameter = new JSONObject();

			clientId = clientModel.getId();
			grantType = clientModel.getGrantType();
			tokenEndpoint = clientModel.getTokenEndpoint();
			secret = clientModel.getSecret();

			pkceEnabled = clientModel.getPkce();

			if (pkceEnabled.equals("1")) {
				codeVerifier = (String) session.getAttribute("code_verifier");
				authParameter.put("code_verifier", codeVerifier);
				session.removeAttribute("code_challenge");
				session.removeAttribute("code_challenge_method");
				session.removeAttribute("code_verifier");
			}

			authParameter.put("client_id", clientId);
			authParameter.put("grant_type", grantType);
			authParameter.put("code", code);
			authParameter.put("redirect_uri", redirectUrl);
			authParameter.put("client_secret", secret);

			Iterator<String> iterator = authParameter.keySet().iterator();
			StringBuffer addParam = new StringBuffer();

			while (iterator.hasNext()) {
				String name = (String) iterator.next();
				String value = (String) authParameter.get(name);
				value = URLEncoder.encode(value, "UTF-8");

				if (addParam.length() > 0) {
					addParam.append("&");
				}

				addParam.append(name).append("=").append(value);
			}

			JSONObject reqTokenInfo = new JSONObject();
			reqTokenInfo.put("url", tokenEndpoint);
			reqTokenInfo.put("parameter", addParam.toString());

			result = new JSONObject();
			result.put("code", String.valueOf(MStatus.SUCCESS));
			result.put("message", "SUCCESS");
			result.put("data", reqTokenInfo);

		}
		catch (IOException e) {
			result = new JSONObject();
			result.put("code", String.valueOf(MStatus.ERR_CLIENT_EXCEPTION));
			result.put("message", "generateOidcTokenRequest() Exception: " + e.getMessage());
			result.put("data", "");
			e.printStackTrace();
		}
		return result;
	}

	public JSONObject generateOidcRefreshTokenRequest(HttpServletRequest request)
	{
		JSONObject result = null;

		try {
			String tokenEndpoint = "";
			String grantType = "";
			String clientId = "";
			String refresh_token = "";
			String secret = "";

			ClientRepository clientRepository = ClientRepository.getInstance();

			if (clientRepository == null) {
				result = new JSONObject();
				result.put("code", String.valueOf(MStatus.ERR_CLIENT_REPOSITORY_GET_FAIL));
				result.put("message", "generateOidcTokenRequest() clientRepository get fail");
				result.put("data", "");
				return result;
			}

			ClientModel clientModel = clientRepository.getClientModel();

			JSONObject authParameter = new JSONObject();

			clientId = clientModel.getId();
			grantType = MStatus.REFRESH_TOKEN;
			tokenEndpoint = clientModel.getTokenEndpoint();
			secret = clientModel.getSecret();

			String refreshTokenUse = clientModel.getRefreshTokenUse();

			if (!refreshTokenUse.equals("1")) {
				result = new JSONObject();
				result.put("code", String.valueOf(MStatus.ERR_CLIENT_REFRESH_TOKEN_DISABLED));
				result.put("message", "generateOidcRefreshTokenRequest() refresh_token not use");
				result.put("data", "");
			}

			JSONObject token = null;
			HttpSession session = request.getSession(true);
			token = (JSONObject) session.getAttribute("SSO_Token");

			if (token == null) {
				result = new JSONObject();
				result.put("code", String.valueOf(MStatus.ERR_CLIENT_OIDC_TOKEN_NULL));
				result.put("message", "generateOidcRefreshTokenRequest() Token is null");
				result.put("data", "");
				return result;
			}

			refresh_token = (String) token.get("refresh_token");

			if (Util.isEmpty(refresh_token)) {
				result = new JSONObject();
				result.put("code", String.valueOf(MStatus.ERR_CLIENT_REFRESH_TOKEN_NULL));
				result.put("message", "generateOidcRefreshTokenRequest() refresh_token is null");
				result.put("data", "");
				return result;
			}

			authParameter.put("client_id", clientId);
			authParameter.put("grant_type", grantType);
			authParameter.put("client_secret", secret);
			authParameter.put("refresh_token", refresh_token);

			Iterator<String> iterator = authParameter.keySet().iterator();
			StringBuffer addParam = new StringBuffer();

			while (iterator.hasNext()) {
				String name = (String) iterator.next();
				String value = (String) authParameter.get(name);

				value = URLEncoder.encode(value, "UTF-8");

				if (addParam.length() > 0) {
					addParam.append("&");
				}

				addParam.append(name).append("=").append(value);
			}

			JSONObject reqToken = new JSONObject();
			reqToken.put("url", tokenEndpoint);
			reqToken.put("parameter", addParam.toString());

			result = new JSONObject();
			result.put("code", String.valueOf(MStatus.SUCCESS));
			result.put("message", "SUCCESS");
			result.put("data", reqToken);
		}
		catch (Exception e) {
			result = new JSONObject();
			result.put("code", String.valueOf(MStatus.ERR_CLIENT_EXCEPTION));
			result.put("message", "generateOidcAuthParameter() Exception: " + e.getMessage());
			result.put("data", "");
			e.printStackTrace();
		}
		return result;
	}

	public JSONObject sendHttpRequest(String requestUrl, String param, String method, String type, String credential)
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
			urlConn.setRequestMethod(method);
			urlConn.setDoOutput(true);

			if (!Util.isEmpty(credential)) {
				urlConn.setRequestProperty("Authorization", type +" " + credential);
			}

			if (method.equals("POST")) {
				urlConn.setRequestProperty("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8");
				OutputStream stream = urlConn.getOutputStream();
				stream.write(param.getBytes("UTF-8"));
				stream.flush();
				stream.close();
			}

			int rcode = urlConn.getResponseCode();

			if (rcode != 200 && urlConn.getErrorStream() == null) {
				result.put("code", String.valueOf(6001));
				result.put("message", "SP: http response error " + rcode);
				result.put("data", "");
				return result;
			}

			BufferedReader br = null;

			if (rcode == 200) {
				br = new BufferedReader(new InputStreamReader(urlConn.getInputStream(), "UTF-8"));
			}
			else {
				br = new BufferedReader(new InputStreamReader(urlConn.getErrorStream(), "UTF-8"));
			}

			StringBuffer strBuffer = new StringBuffer();
			String strLine = "";

			while ((strLine = br.readLine()) != null) {
				strBuffer.append(strLine);
			}

			br.close();
			urlConn.disconnect();

			JSONParser parser = new JSONParser();
			JSONObject jsonResponse = (JSONObject) parser.parse(strBuffer.toString());

			result.put("code", "0");
			result.put("message", "success");
			result.put("data", jsonResponse);
		}
		catch (Exception e) {
			result.put("code", String.valueOf(6002));
			result.put("message", "SP: sendHttpRequest Exception: " + e.getMessage());
			result.put("data", "");
			e.printStackTrace();
		}

		return result;
	}

	public JSONObject checkValidTokenResponse(HttpServletRequest request, JSONObject resToken)
	{
		JSONObject result = null;

		try {
			HttpSession session = request.getSession(true);
			String token_type = (String) resToken.get("token_type");
			String access_token = (String) resToken.get("access_token");
			String id_token = (String) resToken.get("id_token");
			String expires_in = (String) resToken.get("expires_in");
			String refresh_expires_in = (String) resToken.get("refresh_expires_in");
			String refresh_token = (String) resToken.get("refresh_token");
			String error = (String) resToken.get("error");
			String error_description = (String) resToken.get("error_description");
			String error_code = (String) resToken.get("error_code");

			ClientRepository clientRepository = ClientRepository.getInstance();
			ClientModel clientModel = clientRepository.getClientModel();

			if (!Util.isEmpty(error)) {
				result = new JSONObject();
				result.put("code", String.valueOf(MStatus.ERR_CLIENT_RES_DATA));
				result.put("message", "checkValidTokenResponse() error: [" + error + "] error_description : [" + error_description
						+ "] error_code : [" + error_code + "]");
				return result;
			}

			if (Util.isEmpty(access_token)) {
				result = new JSONObject();
				result.put("code", String.valueOf(MStatus.ERR_CLIENT_ACCESS_TOKEN_NULL));
				result.put("message", "checkValidTokenResponse() access_token null");
				return result;
			}

			String nonce = (String) session.getAttribute("nonce");
			String clientId = clientModel.getId();
			String issuer = clientModel.getIssuer();
			String refreshTokenUse = clientModel.getRefreshTokenUse();
			List<Object> allowScopeList = clientModel.getScopes();

			boolean idTokenUse = allowScopeList.contains("openid");

			JWTBuilder jwtBuilder = JWTBuilder.getInstance();

			if (idTokenUse == true) {
				if (Util.isEmpty(id_token)) {
					result = new JSONObject();
					result.put("code", String.valueOf(MStatus.ERR_CLIENT_ID_TOKEN_NULL));
					result.put("message", "checkValidTokenResponse() id_token null");
					return result;
				}

				if (jwtBuilder.verifyJWT(id_token) == false) {
					result = new JSONObject();
					result.put("code", String.valueOf(MStatus.ERR_CLIENT_TOKEN_VERIFY_FAIL));
					result.put("message", "checkValidTokenResponse() id_token sign verify fail");
					return result;
				}

				result = jwtBuilder.idTokenValid(id_token, clientId, issuer, nonce, access_token);

				if (Integer.parseInt((String) result.get("code")) != MStatus.SUCCESS) {
					return result;
				}
			}

			if (jwtBuilder.verifyJWT(access_token) == false) {
				result = new JSONObject();
				result.put("code", String.valueOf(MStatus.ERR_CLIENT_TOKEN_VERIFY_FAIL));
				result.put("message", "checkValidTokenResponse() access_token sign verify fail");
				return result;
			}

			result = jwtBuilder.accessTokenValid(access_token, clientId, issuer, nonce, allowScopeList);

			if (Integer.parseInt((String) result.get("code")) != MStatus.SUCCESS) {
				return result;
			}

			if (refreshTokenUse.equals("1")) {
				if (Util.isEmpty(refresh_token)) {
					result = new JSONObject();
					result.put("code", String.valueOf(MStatus.ERR_CLIENT_REFRESH_TOKEN_NULL));
					result.put("message", "checkValidTokenResponse() refresh_token is null");
					result.put("data", "");
					return result;
				}

				if (jwtBuilder.verifyJWT(refresh_token) == false) {
					result = new JSONObject();
					result.put("code", String.valueOf(MStatus.ERR_CLIENT_TOKEN_VERIFY_FAIL));
					result.put("message", "checkValidTokenResponse() refresh_token sign verify fail");
					return result;
				}

				result = jwtBuilder.refreshTokenValid(refresh_token, clientId, issuer, nonce);

				if (Integer.parseInt((String) result.get("code")) != MStatus.SUCCESS) {
					return result;
				}
			}

			result = new JSONObject();
			result.put("code", "0");
			result.put("message", "success");
			session.setAttribute("SSO_Token", resToken);
		}
		catch (Exception e) {
			result = new JSONObject();
			result.put("code", String.valueOf(MStatus.ERR_CLIENT_EXCEPTION));
			result.put("message", "checkValidTokenResponse() Exception: " + e.getMessage());
			return result;
		}

		return result;
	}

	public JSONObject checkValidTokenResponse(JSONObject resToken, String nonce)
	{
		JSONObject result = null;

		try {
			String token_type = (String) resToken.get("token_type");
			String access_token = (String) resToken.get("access_token");
			String id_token = (String) resToken.get("id_token");
			String expires_in = (String) resToken.get("expires_in");
			String refresh_expires_in = (String) resToken.get("refresh_expires_in");
			String refresh_token = (String) resToken.get("refresh_token");
			String error = (String) resToken.get("error");
			String error_description = (String) resToken.get("error_description");
			String error_code = (String) resToken.get("error_code");
			
			ClientRepository clientRepository = ClientRepository.getInstance();
			ClientModel clientModel = clientRepository.getClientModel();
						
			if (!Util.isEmpty(error)) {
				result = new JSONObject();
				result.put("code", String.valueOf(MStatus.ERR_CLIENT_RES_DATA));
				result.put("message", "checkValidTokenResponse() error: [" + error + "] error_description : [" + error_description + "] error_code : [" + error_code + "]");
				return result;
			}

			if (Util.isEmpty(access_token)) {
				result = new JSONObject();
				result.put("code", String.valueOf(MStatus.ERR_CLIENT_ACCESS_TOKEN_NULL));
				result.put("message", "checkValidTokenResponse() access_token null");
				return result;	
			}

			String clientId = clientModel.getId();
			String issuer = clientModel.getIssuer();
			String refreshTokenUse = clientModel.getRefreshTokenUse();
			List<Object> allowScopeList = clientModel.getScopes();
			
			boolean idTokenUse = allowScopeList.contains("openid");

			JWTBuilder jwtBuilder = JWTBuilder.getInstance();
			
			if (idTokenUse == true) {
				if (Util.isEmpty(id_token)) {
					result = new JSONObject();
					result.put("code", String.valueOf(MStatus.ERR_CLIENT_ID_TOKEN_NULL));
					result.put("message", "checkValidTokenResponse() id_token null");
					return result;	
				}
				if (jwtBuilder.verifyJWT(id_token) == false) {
					result = new JSONObject();
					result.put("code", String.valueOf(MStatus.ERR_CLIENT_TOKEN_VERIFY_FAIL));
					result.put("message", "checkValidTokenResponse() id_token sign verify fail");
					return result;	
				}
				result = jwtBuilder.idTokenValid(id_token, clientId, issuer, nonce, access_token);
				if (Integer.parseInt((String) result.get("code")) != MStatus.SUCCESS) {
					return result;
				}
			}

			if (jwtBuilder.verifyJWT(access_token) == false) {
				result = new JSONObject();
				result.put("code", String.valueOf(MStatus.ERR_CLIENT_TOKEN_VERIFY_FAIL));
				result.put("message", "checkValidTokenResponse() access_token sign verify fail");
				return result;	
			}
			
			result = jwtBuilder.accessTokenValid(access_token, clientId, issuer, nonce, allowScopeList);
			if (Integer.parseInt((String) result.get("code")) != MStatus.SUCCESS) {
				return result;
			}
			
			if (refreshTokenUse.equals("1")) {
				if (Util.isEmpty(refresh_token)) {
					result = new JSONObject();
					result.put("code", String.valueOf(MStatus.ERR_CLIENT_REFRESH_TOKEN_NULL));
					result.put("message", "checkValidTokenResponse() refresh_token is null");
					result.put("data", "");
					return result;
				}
				if (jwtBuilder.verifyJWT(refresh_token) == false) {
					result = new JSONObject();
					result.put("code", String.valueOf(MStatus.ERR_CLIENT_TOKEN_VERIFY_FAIL));
					result.put("message", "checkValidTokenResponse() refresh_token sign verify fail");
					return result;	
				}
				result = jwtBuilder.refreshTokenValid(refresh_token, clientId, issuer, nonce);
				if (Integer.parseInt((String) result.get("code")) != MStatus.SUCCESS) {
					return result;
				}
			}

			result = new JSONObject();
			result.put("code", "0");
			result.put("message", "success");
			result.put("data", resToken);
			
		} catch (Exception e) {
			result = new JSONObject();
			result.put("code", String.valueOf(MStatus.ERR_CLIENT_EXCEPTION));
			result.put("message", "checkValidTokenResponse() Exception: "+ e.getMessage());
			return result;
		}

		return result;
	}

	public JSONObject generateOidcLogout(HttpServletRequest request)
	{
		JSONObject result = new JSONObject();

		try {
			ClientRepository clientRepository = ClientRepository.getInstance();
			ClientModel clientModel = clientRepository.getClientModel();

			result.put("code", String.valueOf(MStatus.SUCCESS));
			result.put("message", "SUCCESS");
			result.put("data", clientModel.getLogoutEndpoint());
		}
		catch (Exception e) {
			result.put("code", String.valueOf(MStatus.ERR_CLIENT_EXCEPTION));
			result.put("message", "generateOidcLogout() Exception: " + e.getMessage());
			result.put("data", "");
			e.printStackTrace();
		}

		return result;
	}
}