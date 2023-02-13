package com.dreamsecurity.sso.agent.api;

import java.net.URLEncoder;
import java.util.Iterator;

import com.dreamsecurity.sso.agent.client.ClientModel;
import com.dreamsecurity.sso.agent.client.ClientRepository;
import com.dreamsecurity.sso.agent.common.MStatus;
import com.dreamsecurity.sso.agent.crypto.SSOCryptoApi;
import com.dreamsecurity.sso.agent.log.Logger;
import com.dreamsecurity.sso.agent.log.LoggerFactory;
import com.dreamsecurity.sso.agent.provider.OidcServiceProvider;
import com.dreamsecurity.sso.agent.util.Util;
import com.dreamsecurity.sso.lib.jsn.JSONObject;

public class OidcService
{
	private static Logger log = LoggerFactory.getInstance().getLogger(OidcService.class);

	public OidcService()
	{
	}

	public JSONObject getRefreshToken(String refreshToken, String nonce)
	{
		JSONObject result = null;

		try {
			String tokenEndpoint = "";
			String grantType = "";
			String clientId = "";
			String secret = "";

			ClientRepository clientRepository = ClientRepository.getInstance();

			if (clientRepository == null) {
				log.error("### getRefreshToken() clientRepository get fail, " + String.valueOf(MStatus.ERR_CLIENT_REPOSITORY_GET_FAIL));

				result = new JSONObject();
				result.put("code", String.valueOf(MStatus.ERR_CLIENT_REPOSITORY_GET_FAIL));
				result.put("message", "getRefreshToken() clientRepository get fail");
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
				log.error("### getRefreshToken() refresh_token not use, " + String.valueOf(MStatus.ERR_CLIENT_REFRESH_TOKEN_DISABLED));

				result = new JSONObject();
				result.put("code", String.valueOf(MStatus.ERR_CLIENT_REFRESH_TOKEN_DISABLED));
				result.put("message", "getRefreshToken() refresh_token not use");
				result.put("data", "");
				return result;
			}

			if (Util.isEmpty(refreshToken)) {
				log.error("### getRefreshToken() refresh_token is null, " + String.valueOf(MStatus.ERR_CLIENT_REFRESH_TOKEN_NULL));

				result = new JSONObject();
				result.put("code", String.valueOf(MStatus.ERR_CLIENT_REFRESH_TOKEN_NULL));
				result.put("message", "getRefreshToken() refresh_token is null");
				result.put("data", "");
				return result;
			}

			authParameter.put("client_id", clientId);
			authParameter.put("grant_type", grantType);
			authParameter.put("client_secret", secret);
			authParameter.put("refresh_token", refreshToken);

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

			OidcServiceProvider sp = OidcServiceProvider.getInstance();
			result = sp.sendHttpRequest(tokenEndpoint, addParam.toString(), "POST", null, null);

			if (Integer.parseInt((String) result.get("code")) != MStatus.SUCCESS) {
				log.error("### getRefreshToken() " + (String) result.get("message") + ", " + (String) result.get("code"));
				return result;
			}

			JSONObject resToken = (JSONObject) result.get("data");
			result = sp.checkValidTokenResponse(resToken, nonce);

			if (Integer.parseInt((String) result.get("code")) != MStatus.SUCCESS) {
				log.error("### getRefreshToken() " + (String) result.get("message") + ", " + (String) result.get("code"));
			}
		}
		catch (Exception e) {
			log.error("### getRefreshToken() Exception: " + e.getMessage());

			result = null;
			result = new JSONObject();
			result.put("code", String.valueOf(MStatus.ERR_CLIENT_EXCEPTION));
			result.put("message", "getRefreshToken() Exception: " + e.getMessage());
			result.put("data", "");
			e.printStackTrace();
		}

		return result;
	}

	public JSONObject verifyToken(String accessToken, String token, String type)
	{
		JSONObject result = null;

		try {
			String introspectEndpoint = "";

			String clientId = "";
			String secret = "";
			StringBuffer credentialBuffer = new StringBuffer();
			String credential = "";
			String authType = "";

			ClientRepository clientRepository = ClientRepository.getInstance();

			if (clientRepository == null) {
				log.error("### verifyToken() clientRepository get fail, " + String.valueOf(MStatus.ERR_CLIENT_REPOSITORY_GET_FAIL));

				result = new JSONObject();
				result.put("code", String.valueOf(MStatus.ERR_CLIENT_REPOSITORY_GET_FAIL));
				result.put("message", "verifyToken() clientRepository get fail");
				result.put("data", "");
				return result;
			}

			ClientModel clientModel = clientRepository.getClientModel();

			JSONObject authParameter = new JSONObject();

			if (Util.isEmpty(accessToken)) {
				clientId = clientModel.getId();
				secret = clientModel.getSecret();
				credentialBuffer.append(clientId).append(":").append(secret);
				credential = SSOCryptoApi.encode64(credentialBuffer.toString().getBytes());
				authType = MStatus.AUTHORIZATION_HEADER_TYPE_BASIC;
				authParameter.put("token", token);
				authParameter.put("token_type_hint", type);
			} else {
				credential = accessToken;
				authType = MStatus.AUTHORIZATION_HEADER_TYPE_BEARER;
				authParameter.put("token", token);
			}

			introspectEndpoint = clientModel.getIntrospectEndpoint();

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

			OidcServiceProvider sp = OidcServiceProvider.getInstance();
			result = sp.sendHttpRequest(introspectEndpoint, addParam.toString(), "POST", authType, credential);

			if (Integer.parseInt((String) result.get("code")) != MStatus.SUCCESS) {
				log.error("### verifyToken() " + (String) result.get("message") + ", " + (String) result.get("code"));
			}
		}
		catch (Exception e) {
			log.error("### verifyToken() Exception: " + e.getMessage());

			result = new JSONObject();
			result.put("code", String.valueOf(MStatus.ERR_CLIENT_EXCEPTION));
			result.put("message", "verifyToken() Exception: " + e.getMessage());
			result.put("data", "");
			e.printStackTrace();
		}

		return result;
	}

	public JSONObject getUserInfo(String accessToken)
	{
		JSONObject result = null;

		try {
			String userinfoEndpoint = "";
			String credential = "";

			String authType = MStatus.AUTHORIZATION_HEADER_TYPE_BEARER;
			if (Util.isEmpty(accessToken)) {
				log.error("### getUserInfo() access_token is null, " + String.valueOf(MStatus.ERR_CLIENT_ACCESS_TOKEN_NULL));

				result = new JSONObject();
				result.put("code", String.valueOf(MStatus.ERR_CLIENT_ACCESS_TOKEN_NULL));
				result.put("message", "getUserInfo() access_token is null");
				result.put("data", "");
				return result;				
			}

			ClientRepository clientRepository = ClientRepository.getInstance();
			if (clientRepository == null) {
				log.error("### getUserInfo() clientRepository get fail, " + String.valueOf(MStatus.ERR_CLIENT_REPOSITORY_GET_FAIL));

				result = new JSONObject();
				result.put("code", String.valueOf(MStatus.ERR_CLIENT_REPOSITORY_GET_FAIL));
				result.put("message", "getUserInfo() clientRepository get fail");
				result.put("data", "");
				return result;
			}

			ClientModel clientModel = clientRepository.getClientModel();
			userinfoEndpoint = clientModel.getUserinfoEndpoint();
			credential = accessToken;

			OidcServiceProvider sp = OidcServiceProvider.getInstance();
			result = sp.sendHttpRequest(userinfoEndpoint, "", "GET", authType, credential);

			if (Integer.parseInt((String) result.get("code")) != MStatus.SUCCESS) {
				log.error("### getUserInfo() " + (String) result.get("message") + ", " + (String) result.get("code"));
			}
		}
		catch (Exception e) {
			log.error("### getUserInfo() Exception: " + e.getMessage());

			result = new JSONObject();
			result.put("code", String.valueOf(MStatus.ERR_CLIENT_EXCEPTION));
			result.put("message", "getUserInfo() Exception: " + e.getMessage());
			result.put("data", "");
			e.printStackTrace();
		}

		return result;
	}
}