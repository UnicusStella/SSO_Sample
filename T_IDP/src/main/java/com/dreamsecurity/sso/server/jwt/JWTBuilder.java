package com.dreamsecurity.sso.server.jwt;

import java.io.IOException;
import java.util.Date;
import java.util.List;

import com.dreamsecurity.sso.lib.jsn.JSONObject;
import com.dreamsecurity.sso.lib.jsn.parser.JSONParser;
import com.dreamsecurity.sso.server.common.MStatus;
import com.dreamsecurity.sso.server.crypto.CryptoApiException;
import com.dreamsecurity.sso.server.crypto.SSOCryptoApi;
import com.dreamsecurity.sso.server.provider.OidcIdentificationProvider;
import com.dreamsecurity.sso.server.session.OidcSessionManager;
import com.dreamsecurity.sso.server.session.RootAuthSession;
import com.dreamsecurity.sso.server.session.SubAuthSession;
import com.dreamsecurity.sso.server.util.OIDCUtil;
import com.dreamsecurity.sso.server.util.Util;

public class JWTBuilder
{
	private static JWTBuilder instance = null;

	private String typ = "JWT";
	private String alg = "RS256";

	private String signAlgorithm = "SHA256withRSA";
	private String hashAlgorithm = "SHA256";

	private JWTBuilder()
	{
	}

	public static JWTBuilder getInstance()
	{
		if (instance == null) {
			synchronized (JWTBuilder.class) {
				if (instance == null) {
					instance = new JWTBuilder();
				}
			}
		}

		return instance;
	}

	public String generateJWT(String token)
	{
		String jwtHeader = null;
		String jwtPayload = null;
		StringBuilder buffer = new StringBuilder();
		String jwt = null;
		String jwtSign = null;

		try {
			jwtHeader = encodeHeader();
		}
		catch (CryptoApiException e) {
			e.printStackTrace();
		}
		catch (IOException e) {
			e.printStackTrace();
		}

		jwtPayload = SSOCryptoApi.encode64(token.getBytes());
		jwtPayload = OIDCUtil.base64ToBase64url(jwtPayload);
		jwtHeader = OIDCUtil.base64ToBase64url(jwtHeader);

		buffer.append(jwtHeader);
		buffer.append('.');
		buffer.append(jwtPayload);

		try {
			jwtSign = SSOCryptoApi.getInstance().signJWT(buffer.toString().getBytes(), this.signAlgorithm);
			jwtSign = OIDCUtil.base64ToBase64url(jwtSign);
		}
		catch (CryptoApiException e) {
			e.printStackTrace();
		}

		buffer.append('.');
		buffer.append(jwtSign);
		jwt = buffer.toString();

		return jwt;
	}

	private String encodeHeader() throws CryptoApiException, IOException
	{
		StringBuilder builder = new StringBuilder("{");
		builder.append("\"alg\":\"").append(this.alg).append("\"");

		if (this.typ != null)
			builder.append(",\"typ\" : \"").append(this.typ).append("\"");

		builder.append("}");

		return SSOCryptoApi.encode64(builder.toString().getBytes());
	}

	public boolean verifyJWT(String token)
	{
		boolean valid = false;
		String jwtHeader = null;
		String jwtPayload = null;
		StringBuilder buffer = new StringBuilder();
		String jwtSign = null;
		String[] jwtData = token.split("\\.");
		jwtHeader = jwtData[0];
		jwtPayload = jwtData[1];
		jwtSign = OIDCUtil.base64urlToBase64(jwtData[2]);

		buffer.append(jwtHeader);
		buffer.append('.');
		buffer.append(jwtPayload);

		try {
			SSOCryptoApi.getInstance().verifyJWT(jwtSign, buffer.toString().getBytes(), this.signAlgorithm);
			valid = true;
		}
		catch (CryptoApiException e) {
			e.printStackTrace();
			valid = false;
		}

		return valid;
	}

	public String getTokenString(String token)
	{
		String jwtPayload = null;
		String tokenString = null;

		String[] jwtData = token.split("\\.");

		if (jwtData.length != 3) {
			return null;
		}

		jwtPayload = jwtData[1];
		jwtPayload = OIDCUtil.base64urlToBase64(jwtData[1]);

		try {
			tokenString = new String(SSOCryptoApi.decode64(jwtPayload));
		}
		catch (CryptoApiException e) {
			e.printStackTrace();
		}

		return tokenString;
	}

	public String generateAtHash(String accessToken)
	{
		String output = "";

		try {
			byte[] hash = SSOCryptoApi.getInstance().hash(accessToken.getBytes(), this.hashAlgorithm);
			byte[] sixteen_bytes = new byte[16];
			System.arraycopy(hash, 0, sixteen_bytes, 0, 16);
			String athash = SSOCryptoApi.encode64(sixteen_bytes);
			output = OIDCUtil.base64ToBase64url(athash);
		}
		catch (CryptoApiException e) {
			output = "";
		}

		return output;
	}

	public String generateSID(String subAuthSessionId, String rootAuthSessionId)
	{
		StringBuffer sid = new StringBuffer();

		sid = sid.append(subAuthSessionId);
		sid = sid.append(".");
		sid = sid.append(rootAuthSessionId);

		return sid.toString();
	}

	public JSONObject refreshTokenValid(String refreshJwt, String clientId, String issuer, String refreshTokenUse, boolean tokenStatusReturn)
	{
		JSONObject result = null;
		JSONObject resJson = null;

		try {
			if (refreshTokenUse.equals("0")) {
				result = new JSONObject();
				resJson = new JSONObject();
				result.put("code", String.valueOf(MStatus.ERR_REFRESH_TOKEN_DISABLED));
				result.put("message", "refreshTokenGrant() invalid_grant not using refresh_token");

				if (tokenStatusReturn) {
					resJson.put("active", "false");
					resJson.put("msg", "not using refresh_token");
					resJson.put("http_status_code", 200);
				}
				else {
					resJson.put("error", "invalid_grant");
					resJson.put("error_description", "not using refresh_token");
					resJson.put("error_code", String.valueOf(MStatus.ERR_REFRESH_TOKEN_DISABLED));
					resJson.put("http_status_code", 400);
				}

				result.put("data", resJson);
				return result;
			}

			String refreshTokenStr = getTokenString(refreshJwt);

			if (Util.isEmpty(refreshTokenStr)) {
				result = new JSONObject();
				resJson = new JSONObject();
				result.put("code", String.valueOf(MStatus.ERR_REFRESH_TOKEN_ERROR_FORMAT));
				result.put("message", "refreshTokenValid() invalid_grant error format refresh_token");

				if (tokenStatusReturn) {
					resJson.put("active", "false");
					resJson.put("msg", "error format refresh_token");
					resJson.put("http_status_code", 200);
				}
				else {
					resJson.put("error", "invalid_grant");
					resJson.put("error_description", "error format refresh_token");
					resJson.put("error_code", String.valueOf(MStatus.ERR_REFRESH_TOKEN_ERROR_FORMAT));
					resJson.put("http_status_code", 400);
				}

				result.put("data", resJson);
				return result;
			}

			JSONParser parser = new JSONParser();
			JSONObject refreshTokenJson = null;
			refreshTokenJson = (JSONObject) parser.parse(refreshTokenStr);

			String iss = (String) refreshTokenJson.get("iss");
			String aud = (String) refreshTokenJson.get("aud");
			String sid = (String) refreshTokenJson.get("sid");
			String tokenType = (String) refreshTokenJson.get("typ");
			String[] sidParse = sid.split("\\.");

			long exp = Long.parseLong(refreshTokenJson.get("exp").toString());
			Date curDate = new Date(System.currentTimeMillis());
			Date expDate = new Date(exp * 1000);

			if (!tokenType.equals(MStatus.REFRESH_TOKEN_TYPE)) {
				result = new JSONObject();
				resJson = new JSONObject();
				result.put("code", String.valueOf(MStatus.ERR_MISMATCH_TOKEN_TYPE));
				result.put("message", "refreshTokenValid() invalid_grant invalid token type");

				if (tokenStatusReturn) {
					resJson.put("active", "false");
					resJson.put("msg", "invalid token type");
					resJson.put("http_status_code", 200);
				}
				else {
					resJson.put("error", "invalid_grant");
					resJson.put("error_description", "invalid token type");
					resJson.put("error_code", String.valueOf(MStatus.ERR_MISMATCH_TOKEN_TYPE));
					resJson.put("http_status_code", 400);
				}

				result.put("data", resJson);
				return result;
			}

			if (sidParse.length != 2) {
				result = new JSONObject();
				resJson = new JSONObject();
				result.put("code", String.valueOf(MStatus.ERR_TOKEN_SID_PARSE_FAIL));
				result.put("message", "refreshTokenValid() invalid_grant failed parsing sid");

				if (tokenStatusReturn) {
					resJson.put("active", "false");
					resJson.put("msg", "failed parsing sid");
					resJson.put("http_status_code", 200);
				}
				else {
					resJson.put("error", "invalid_grant");
					resJson.put("error_description", "failed parsing sid");
					resJson.put("error_code", String.valueOf(MStatus.ERR_TOKEN_SID_PARSE_FAIL));
					resJson.put("http_status_code", 400);
				}

				result.put("data", resJson);
				return result;
			}

			String rootAuthSessionId = sidParse[1];
			String subAuthSessionId = sidParse[0];

			RootAuthSession rootAuthSession = null;
			SubAuthSession subAuthSession = null;

			if (Util.isEmpty(rootAuthSessionId)) {
				result = new JSONObject();
				resJson = new JSONObject();
				result.put("code", String.valueOf(MStatus.ERR_ROOTAUTHSESSION_ID_NOT_EXIST));
				result.put("message", "refreshTokenValid() invalid_grant not found rootAuthSessionId");

				if (tokenStatusReturn) {
					resJson.put("active", "false");
					resJson.put("msg", "not found rootAuthSessionId");
					resJson.put("http_status_code", 200);
				}
				else {
					resJson.put("error", "invalid_grant");
					resJson.put("error_description", "not found rootAuthSessionId");
					resJson.put("error_code", String.valueOf(MStatus.ERR_ROOTAUTHSESSION_ID_NOT_EXIST));
					resJson.put("http_status_code", 400);
				}

				result.put("data", resJson);
				return result;
			}
			else {
				rootAuthSession = OidcSessionManager.getInstance().getRootAuthSession(rootAuthSessionId);
			}

			// 동기화 서버에 요청
			if (rootAuthSession == null) {
				rootAuthSession = OidcIdentificationProvider.getInstance().getRootAuthSessionByEvent(rootAuthSessionId);
			}

			if (rootAuthSession == null) {
				result = new JSONObject();
				resJson = new JSONObject();
				result.put("code", String.valueOf(MStatus.ERR_ROOTAUTHSESSION_NOT_EXIST));
				result.put("message", "refreshTokenValid() invalid_grant not found rootAuthSession");

				if (tokenStatusReturn) {
					resJson.put("active", "false");
					resJson.put("msg", "not found rootAuthSession");
					resJson.put("http_status_code", 200);
				}
				else {
					resJson.put("error", "invalid_grant");
					resJson.put("error_description", "not found rootAuthSession");
					resJson.put("error_code", String.valueOf(MStatus.ERR_ROOTAUTHSESSION_NOT_EXIST));
					resJson.put("http_status_code", 400);
				}

				result.put("data", resJson);
				return result;
			}

			if (Util.isEmpty(subAuthSessionId)) {
				result = new JSONObject();
				resJson = new JSONObject();
				result.put("code", String.valueOf(MStatus.ERR_SUBAUTHSESSION_ID_NOT_EXIST));
				result.put("message", "refreshTokenValid() invalid_grant not found subAuthSessionId");

				if (tokenStatusReturn) {
					resJson.put("active", "false");
					resJson.put("msg", "not found subAuthSessionId");
					resJson.put("http_status_code", 200);
				}
				else {
					resJson.put("error", "invalid_grant");
					resJson.put("error_description", "not found subAuthSessionId");
					resJson.put("error_code", String.valueOf(MStatus.ERR_SUBAUTHSESSION_ID_NOT_EXIST));
					resJson.put("http_status_code", 400);
				}

				result.put("data", resJson);
				return result;
			}
			else {
				subAuthSession = rootAuthSession.getSubAuthSession(subAuthSessionId);
			}

			if (subAuthSession == null) {
				result = new JSONObject();
				resJson = new JSONObject();
				result.put("code", String.valueOf(MStatus.ERR_SUBAUTHSESSION_NOT_EXIST));
				result.put("message", "refreshTokenValid() invalid_grant not found subAuthSession");

				if (tokenStatusReturn) {
					resJson.put("active", "false");
					resJson.put("msg", "not found subAuthSession");
					resJson.put("http_status_code", 200);
				}
				else {
					resJson.put("error", "invalid_grant");
					resJson.put("error_description", "not found subAuthSession");
					resJson.put("error_code", String.valueOf(MStatus.ERR_SUBAUTHSESSION_NOT_EXIST));
					resJson.put("http_status_code", 400);
				}

				result.put("data", resJson);
				return result;
			}

			if (!subAuthSession.getRefreshJwt().equals(refreshJwt)) {
				result = new JSONObject();
				resJson = new JSONObject();
				result.put("code", String.valueOf(MStatus.ERR_MISMATCH_TOKEN_CUR_SESSION));
				result.put("message", "refreshTokenValid() refreshJwt Different");

				if (tokenStatusReturn) {
					resJson.put("active", "false");
					resJson.put("msg", "refreshJwt Different");
					resJson.put("http_status_code", 200);
				}
				else {
					resJson.put("error", "invalid_grant");
					resJson.put("error_description", "refreshJwt Different");
					resJson.put("error_code", String.valueOf(MStatus.ERR_MISMATCH_TOKEN_CUR_SESSION));
					resJson.put("http_status_code", 400);
				}

				result.put("data", resJson);
				return result;
			}

			if (!issuer.equals(iss)) {
				result = new JSONObject();
				resJson = new JSONObject();
				result.put("code", String.valueOf(MStatus.ERR_MISMATCH_CLAIM_ISS));
				result.put("message", "refreshTokenValid() claim(iss) Different");

				if (tokenStatusReturn) {
					resJson.put("active", "false");
					resJson.put("msg", "claim(iss) Different");
					resJson.put("http_status_code", 200);
				}
				else {
					resJson.put("error", "invalid_grant");
					resJson.put("error_description", "claim(iss) Different");
					resJson.put("error_code", String.valueOf(MStatus.ERR_MISMATCH_CLAIM_ISS));
					resJson.put("http_status_code", 400);
				}

				result.put("data", resJson);
				return result;
			}

			if (!clientId.equals(aud)) {
				result = new JSONObject();
				resJson = new JSONObject();
				result.put("code", String.valueOf(MStatus.ERR_MISMATCH_CLAIM_AUD));
				result.put("message", "refreshTokenValid() invalid_grant claim(aud) Different");

				if (tokenStatusReturn) {
					resJson.put("active", "false");
					resJson.put("msg", "claim(aud) Different");
					resJson.put("http_status_code", 200);
				}
				else {
					resJson.put("error", "invalid_grant");
					resJson.put("error_description", "claim(aud) Different");
					resJson.put("error_code", String.valueOf(MStatus.ERR_MISMATCH_CLAIM_AUD));
					resJson.put("http_status_code", 400);
				}

				result.put("data", resJson);
				return result;
			}

			if (curDate.compareTo(expDate) >= 0) {
				result = new JSONObject();
				resJson = new JSONObject();
				result.put("code", String.valueOf(MStatus.ERR_TOKEN_EXPIRED));
				result.put("message", "refreshTokenValid() invalid_grant expired token");

				if (tokenStatusReturn) {
					resJson.put("active", "false");
					resJson.put("msg", "expired token");
					resJson.put("http_status_code", 200);
				}
				else {
					resJson.put("error", "invalid_grant");
					resJson.put("error_description", "expired token");
					resJson.put("error_code", String.valueOf(MStatus.ERR_TOKEN_EXPIRED));
					resJson.put("http_status_code", 400);
				}

				result.put("data", resJson);
				return result;
			}

			result = new JSONObject();
			resJson = new JSONObject();
			result.put("code", "0");
			result.put("message", "success");
			resJson.put("rootAuthSessionId", rootAuthSessionId);
			resJson.put("subAuthSessionId", subAuthSessionId);
			result.put("data", resJson);
		}
		catch (Exception e) {
			result = new JSONObject();
			resJson = new JSONObject();
			result.put("code", String.valueOf(MStatus.ERR_SERVER_EXCEPTION));
			result.put("message", "refreshTokenValid() Exception: " + e.getMessage());
			resJson.put("error", "server_error");
			resJson.put("error_description", "unexpected server error");
			resJson.put("error_code", String.valueOf(MStatus.ERR_SERVER_EXCEPTION));
			resJson.put("http_status_code", 500);
			result.put("data", resJson);
		}

		return result;
	}

	public JSONObject accessTokenValid(String accessJwt, String clientId, String issuer, List<Object> allowScopeList,
			boolean tokenStatusReturn)
	{
		JSONObject result = null;
		JSONObject resJson = null;

		try {
			String accessTokenStr = getTokenString(accessJwt);

			if (Util.isEmpty(accessTokenStr)) {
				result = new JSONObject();
				resJson = new JSONObject();
				result.put("code", String.valueOf(MStatus.ERR_ACCESS_TOKEN_ERROR_FORMAT));
				result.put("message", "accessTokenValid() invalid_grant error format access_token");

				if (tokenStatusReturn) {
					resJson.put("active", "false");
					resJson.put("msg", "error format access_token");
					resJson.put("http_status_code", 200);
				}
				else {
					resJson.put("error", "invalid_grant");
					resJson.put("error_description", "error format access_token");
					resJson.put("error_code", String.valueOf(MStatus.ERR_ACCESS_TOKEN_ERROR_FORMAT));
					resJson.put("http_status_code", 400);
				}

				result.put("data", resJson);
				return result;
			}

			JSONParser parser = new JSONParser();
			JSONObject accessTokenJson = null;
			accessTokenJson = (JSONObject) parser.parse(accessTokenStr);

			String iss = (String) accessTokenJson.get("iss");
			String aud = (String) accessTokenJson.get("aud");
			String sid = (String) accessTokenJson.get("sid");
			String scope = (String) accessTokenJson.get("scope");
			String tokenType = (String) accessTokenJson.get("typ");

			String[] sidParse = sid.split("\\.");
			long exp = Long.parseLong(accessTokenJson.get("exp").toString());
			Date curDate = new Date(System.currentTimeMillis());
			Date expDate = new Date(exp * 1000);

			if (!tokenType.equals(MStatus.ACCESS_TOKEN_TYPE)) {
				result = new JSONObject();
				resJson = new JSONObject();
				result.put("code", String.valueOf(MStatus.ERR_MISMATCH_TOKEN_TYPE));
				result.put("message", "accessTokenValid() invalid_grant token type invalid");

				if (tokenStatusReturn) {
					resJson.put("active", "false");
					resJson.put("msg", "invalid token type");
					resJson.put("http_status_code", 200);
				}
				else {
					resJson.put("error", "invalid_grant");
					resJson.put("error_description", "token type invalid");
					resJson.put("error_code", String.valueOf(MStatus.ERR_MISMATCH_TOKEN_TYPE));
					resJson.put("http_status_code", 400);
				}

				result.put("data", resJson);
				return result;
			}

			if (sidParse.length != 2) {
				result = new JSONObject();
				resJson = new JSONObject();
				result.put("code", String.valueOf(MStatus.ERR_TOKEN_SID_PARSE_FAIL));
				result.put("message", "accessTokenValid() invalid_grant error format sid");

				if (tokenStatusReturn) {
					resJson.put("active", "false");
					resJson.put("msg", "failed parsing sid");
					resJson.put("http_status_code", 200);
				}
				else {
					resJson.put("error", "invalid_grant");
					resJson.put("error_description", "error format sid");
					resJson.put("error_code", String.valueOf(MStatus.ERR_TOKEN_SID_PARSE_FAIL));
					resJson.put("http_status_code", 400);
				}

				result.put("data", resJson);
				return result;
			}

			String rootAuthSessionId = sidParse[1];
			String subAuthSessionId = sidParse[0];

			RootAuthSession rootAuthSession = null;
			SubAuthSession subAuthSession = null;

			if (Util.isEmpty(rootAuthSessionId)) {
				result = new JSONObject();
				resJson = new JSONObject();
				result.put("code", String.valueOf(MStatus.ERR_ROOTAUTHSESSION_ID_NOT_EXIST));
				result.put("message", "accessTokenValid() invalid_grant not found rootAuthSessionId");

				if (tokenStatusReturn) {
					resJson.put("active", "false");
					resJson.put("msg", "not found rootAuthSessionId");
					resJson.put("http_status_code", 200);
				}
				else {
					resJson.put("error", "invalid_grant");
					resJson.put("error_description", "not found rootAuthSessionId");
					resJson.put("error_code", String.valueOf(MStatus.ERR_ROOTAUTHSESSION_ID_NOT_EXIST));
					resJson.put("http_status_code", 400);
				}

				result.put("data", resJson);
				return result;
			}
			else {
				rootAuthSession = OidcSessionManager.getInstance().getRootAuthSession(rootAuthSessionId);
			}

			// 동기화 서버에 요청
			if (rootAuthSession == null) {
				rootAuthSession = OidcIdentificationProvider.getInstance().getRootAuthSessionByEvent(rootAuthSessionId);
			}

			if (rootAuthSession == null) {
				result = new JSONObject();
				resJson = new JSONObject();
				result.put("code", String.valueOf(MStatus.ERR_ROOTAUTHSESSION_NOT_EXIST));
				result.put("message", "accessTokenValid() invalid_grant not found rootAuthSession");

				if (tokenStatusReturn) {
					resJson.put("active", "false");
					resJson.put("msg", "not found rootAuthSession");
					resJson.put("http_status_code", 200);
				}
				else {
					resJson.put("error", "invalid_grant");
					resJson.put("error_description", "not found rootAuthSession");
					resJson.put("error_code", String.valueOf(MStatus.ERR_ROOTAUTHSESSION_NOT_EXIST));
					resJson.put("http_status_code", 400);
				}

				result.put("data", resJson);
				return result;
			}

			if (Util.isEmpty(subAuthSessionId)) {
				result = new JSONObject();
				resJson = new JSONObject();
				result.put("code", String.valueOf(MStatus.ERR_SUBAUTHSESSION_ID_NOT_EXIST));
				result.put("message", "accessTokenValid() invalid_grant not found subAuthSessionId");

				if (tokenStatusReturn) {
					resJson.put("active", "false");
					resJson.put("msg", "not found subAuthSessionId");
					resJson.put("http_status_code", 200);
				}
				else {
					resJson.put("error", "invalid_grant");
					resJson.put("error_description", "not found subAuthSessionId");
					resJson.put("error_code", String.valueOf(MStatus.ERR_SUBAUTHSESSION_ID_NOT_EXIST));
					resJson.put("http_status_code", 400);
				}

				result.put("data", resJson);
				return result;
			}
			else {
				subAuthSession = rootAuthSession.getSubAuthSession(subAuthSessionId);
			}

			if (subAuthSession == null) {
				result = new JSONObject();
				resJson = new JSONObject();
				result.put("code", String.valueOf(MStatus.ERR_SUBAUTHSESSION_NOT_EXIST));
				result.put("message", "accessTokenValid() invalid_grant not found subAuthSession");

				if (tokenStatusReturn) {
					resJson.put("active", "false");
					resJson.put("msg", "not found subAuthSession");
					resJson.put("http_status_code", 200);
				}
				else {
					resJson.put("error", "invalid_grant");
					resJson.put("error_description", "not found subAuthSession");
					resJson.put("error_code", String.valueOf(MStatus.ERR_SUBAUTHSESSION_NOT_EXIST));
					resJson.put("http_status_code", 400);
				}

				result.put("data", resJson);
				return result;
			}

			if (!subAuthSession.getAccessJwt().equals(accessJwt)) {
				result = new JSONObject();
				resJson = new JSONObject();
				result.put("code", String.valueOf(MStatus.ERR_MISMATCH_TOKEN_CUR_SESSION));
				result.put("message", "accessTokenValid() accessJwt Different");

				if (tokenStatusReturn) {
					resJson.put("active", "false");
					resJson.put("msg", "accessJwt Different");
					resJson.put("http_status_code", 200);
				}
				else {
					resJson.put("error", "invalid_grant");
					resJson.put("error_description", "accessJwt Different");
					resJson.put("error_code", String.valueOf(MStatus.ERR_MISMATCH_TOKEN_CUR_SESSION));
					resJson.put("http_status_code", 400);
				}

				result.put("data", resJson);
				return result;
			}

			String[] scopes = scope.split(" ");

			for (int i = 0; i < scopes.length; i++) {
				if (!allowScopeList.contains(scopes[i])) {
					result = new JSONObject();
					resJson = new JSONObject();
					result.put("code", String.valueOf(MStatus.ERR_INVALID_SCOPE));
					result.put("message", "accessTokenValid() invalid_scope " + scopes[i]);

					if (tokenStatusReturn) {
						resJson.put("active", "false");
						resJson.put("msg", "invalid_scope " + scopes[i]);
						resJson.put("http_status_code", 200);
					}
					else {
						resJson.put("error", "invalid_scope");
						resJson.put("error_description", "invalid_scope " + scopes[i]);
						resJson.put("error_code", String.valueOf(MStatus.ERR_INVALID_SCOPE));
						resJson.put("http_status_code", 400);
					}

					result.put("data", resJson);
					return result;
				}
			}

			if (!issuer.equals(iss)) {
				result = new JSONObject();
				resJson = new JSONObject();
				result.put("code", String.valueOf(MStatus.ERR_MISMATCH_CLAIM_ISS));
				result.put("message", "accessTokenValid() invalid_grant access_token iss Different");

				if (tokenStatusReturn) {
					resJson.put("active", "false");
					resJson.put("msg", "claim(iss) Different");
					resJson.put("http_status_code", 200);
				}
				else {
					resJson.put("error", "invalid_grant");
					resJson.put("error_description", "access_token iss Different");
					resJson.put("error_code", String.valueOf(MStatus.ERR_MISMATCH_CLAIM_ISS));
					resJson.put("http_status_code", 400);
				}

				result.put("data", resJson);
				return result;
			}

			if (!clientId.equals(aud)) {
				result = new JSONObject();
				resJson = new JSONObject();
				result.put("code", String.valueOf(MStatus.ERR_MISMATCH_CLAIM_AUD));
				result.put("message", "accessTokenValid() invalid_grant access_token aud Different");

				if (tokenStatusReturn) {
					resJson.put("active", "false");
					resJson.put("msg", "claim(aud) Different");
					resJson.put("http_status_code", 200);
				}
				else {
					resJson.put("error", "invalid_grant");
					resJson.put("error_description", "access_token aud Different");
					resJson.put("error_code", String.valueOf(MStatus.ERR_MISMATCH_CLAIM_AUD));
					resJson.put("http_status_code", 400);
				}

				result.put("data", resJson);
				return result;
			}

			if (curDate.compareTo(expDate) >= 0) {
				result = new JSONObject();
				resJson = new JSONObject();
				result.put("code", String.valueOf(MStatus.ERR_TOKEN_EXPIRED));
				result.put("message", "accessTokenValid() invalid_grant access_token exp time expiration");

				if (tokenStatusReturn) {
					resJson.put("active", "false");
					resJson.put("msg", "expired token");
					resJson.put("http_status_code", 200);
				}
				else {
					resJson.put("error", "invalid_grant");
					resJson.put("error_description", "access_token exp time expiration");
					resJson.put("error_code", String.valueOf(MStatus.ERR_TOKEN_EXPIRED));
					resJson.put("http_status_code", 400);
				}

				result.put("data", resJson);
				return result;
			}

			result = new JSONObject();
			resJson = new JSONObject();
			result.put("code", "0");
			result.put("message", "success");
			resJson.put("rootAuthSessionId", rootAuthSessionId);
			resJson.put("subAuthSessionId", subAuthSessionId);
			result.put("data", resJson);
		}
		catch (Exception e) {
			result = new JSONObject();
			resJson = new JSONObject();
			result.put("code", String.valueOf(MStatus.ERR_SERVER_EXCEPTION));
			result.put("message", "accessTokenValid() Exception: " + e.getMessage());
			resJson.put("error", "server_error");
			resJson.put("error_description", "unexpected server error");
			resJson.put("error_code", String.valueOf(MStatus.ERR_SERVER_EXCEPTION));
			resJson.put("http_status_code", 500);
			result.put("data", resJson);
		}

		return result;
	}

	public JSONObject idTokenValid(String idJwt, String clientId, String issuer, List<Object> allowScopeList, boolean tokenStatusReturn)
	{
		JSONObject result = null;
		JSONObject resJson = null;

		try {
			String idTokenStr = getTokenString(idJwt);

			if (Util.isEmpty(idTokenStr)) {
				result = new JSONObject();
				resJson = new JSONObject();
				result.put("code", String.valueOf(MStatus.ERR_ID_TOKEN_ERROR_FORMAT));
				result.put("message", "idTokenValid() invalid_grant error format id_token");

				if (tokenStatusReturn) {
					resJson.put("active", "false");
					resJson.put("msg", "error format id_token");
					resJson.put("http_status_code", 200);
				}
				else {
					resJson.put("error", "invalid_grant");
					resJson.put("error_description", "error format id_token");
					resJson.put("error_code", String.valueOf(MStatus.ERR_ID_TOKEN_ERROR_FORMAT));
					resJson.put("http_status_code", 400);
				}

				result.put("data", resJson);
				return result;
			}

			JSONParser parser = new JSONParser();
			JSONObject idTokenJson = null;
			idTokenJson = (JSONObject) parser.parse(idTokenStr);

			String iss = (String) idTokenJson.get("iss");
			String aud = (String) idTokenJson.get("aud");
			String sid = (String) idTokenJson.get("sid");
			String scope = (String) idTokenJson.get("scope");
			String tokenType = (String) idTokenJson.get("typ");

			String[] sidParse = sid.split("\\.");
			long exp = Long.parseLong(idTokenJson.get("exp").toString());
			Date curDate = new Date(System.currentTimeMillis());
			Date expDate = new Date(exp * 1000);

			if (!tokenType.equals(MStatus.ID_TOKEN_TYPE)) {
				result = new JSONObject();
				resJson = new JSONObject();
				result.put("code", String.valueOf(MStatus.ERR_MISMATCH_TOKEN_TYPE));
				result.put("message", "idTokenValid() invalid_grant token type invalid");

				if (tokenStatusReturn) {
					resJson.put("active", "false");
					resJson.put("msg", "invalid token type");
					resJson.put("http_status_code", 200);
				}
				else {
					resJson.put("error", "invalid_grant");
					resJson.put("error_description", "token type invalid");
					resJson.put("error_code", String.valueOf(MStatus.ERR_MISMATCH_TOKEN_TYPE));
					resJson.put("http_status_code", 400);
				}

				result.put("data", resJson);
				return result;
			}

			if (sidParse.length != 2) {
				result = new JSONObject();
				resJson = new JSONObject();
				result.put("code", String.valueOf(MStatus.ERR_TOKEN_SID_PARSE_FAIL));
				result.put("message", "idTokenValid() invalid_grant error format sid");

				if (tokenStatusReturn) {
					resJson.put("active", "false");
					resJson.put("msg", "failed parsing sid");
					resJson.put("http_status_code", 200);
				}
				else {
					resJson.put("error", "invalid_grant");
					resJson.put("error_description", "error format sid");
					resJson.put("error_code", String.valueOf(MStatus.ERR_TOKEN_SID_PARSE_FAIL));
					resJson.put("http_status_code", 400);
				}

				result.put("data", resJson);
				return result;
			}

			String rootAuthSessionId = sidParse[1];
			String subAuthSessionId = sidParse[0];

			RootAuthSession rootAuthSession = null;
			SubAuthSession subAuthSession = null;

			if (Util.isEmpty(rootAuthSessionId)) {
				result = new JSONObject();
				resJson = new JSONObject();
				result.put("code", String.valueOf(MStatus.ERR_ROOTAUTHSESSION_ID_NOT_EXIST));
				result.put("message", "idTokenValid() invalid_grant not found rootAuthSessionId");

				if (tokenStatusReturn) {
					resJson.put("active", "false");
					resJson.put("msg", "not found rootAuthSessionId");
					resJson.put("http_status_code", 200);
				}
				else {
					resJson.put("error", "invalid_grant");
					resJson.put("error_description", "not found rootAuthSessionId");
					resJson.put("error_code", String.valueOf(MStatus.ERR_ROOTAUTHSESSION_ID_NOT_EXIST));
					resJson.put("http_status_code", 400);
				}

				result.put("data", resJson);
				return result;
			}
			else {
				rootAuthSession = OidcSessionManager.getInstance().getRootAuthSession(rootAuthSessionId);
			}

			// 동기화 서버에 요청
			if (rootAuthSession == null) {
				rootAuthSession = OidcIdentificationProvider.getInstance().getRootAuthSessionByEvent(rootAuthSessionId);
			}

			if (rootAuthSession == null) {
				result = new JSONObject();
				resJson = new JSONObject();
				result.put("code", String.valueOf(MStatus.ERR_ROOTAUTHSESSION_NOT_EXIST));
				result.put("message", "idTokenValid() invalid_grant not found rootAuthSession");

				if (tokenStatusReturn) {
					resJson.put("active", "false");
					resJson.put("msg", "not found rootAuthSession");
					resJson.put("http_status_code", 200);
				}
				else {
					resJson.put("error", "invalid_grant");
					resJson.put("error_description", "not found rootAuthSession");
					resJson.put("error_code", String.valueOf(MStatus.ERR_ROOTAUTHSESSION_NOT_EXIST));
					resJson.put("http_status_code", 400);
				}

				result.put("data", resJson);
				return result;
			}

			if (Util.isEmpty(subAuthSessionId)) {
				result = new JSONObject();
				resJson = new JSONObject();
				result.put("code", String.valueOf(MStatus.ERR_SUBAUTHSESSION_ID_NOT_EXIST));
				result.put("message", "idTokenValid() invalid_grant not found subAuthSessionId");

				if (tokenStatusReturn) {
					resJson.put("active", "false");
					resJson.put("msg", "not found subAuthSessionId");
					resJson.put("http_status_code", 200);
				}
				else {
					resJson.put("error", "invalid_grant");
					resJson.put("error_description", "not found subAuthSessionId");
					resJson.put("error_code", String.valueOf(MStatus.ERR_SUBAUTHSESSION_ID_NOT_EXIST));
					resJson.put("http_status_code", 400);
				}

				result.put("data", resJson);
				return result;
			}
			else {
				subAuthSession = rootAuthSession.getSubAuthSession(subAuthSessionId);
			}

			if (subAuthSession == null) {
				result = new JSONObject();
				resJson = new JSONObject();
				result.put("code", String.valueOf(MStatus.ERR_SUBAUTHSESSION_NOT_EXIST));
				result.put("message", "idTokenValid() invalid_grant not found subAuthSession");

				if (tokenStatusReturn) {
					resJson.put("active", "false");
					resJson.put("msg", "not found subAuthSession");
					resJson.put("http_status_code", 200);
				}
				else {
					resJson.put("error", "invalid_grant");
					resJson.put("error_description", "not found subAuthSession");
					resJson.put("error_code", String.valueOf(MStatus.ERR_SUBAUTHSESSION_NOT_EXIST));
					resJson.put("http_status_code", 400);
				}

				result.put("data", resJson);
				return result;
			}

			if (!subAuthSession.getIdJwt().equals(idJwt)) {
				result = new JSONObject();
				resJson = new JSONObject();
				result.put("code", String.valueOf(MStatus.ERR_MISMATCH_TOKEN_CUR_SESSION));
				result.put("message", "idTokenValid() idJwt Different");

				if (tokenStatusReturn) {
					resJson.put("active", "false");
					resJson.put("msg", "idJwt Different");
					resJson.put("http_status_code", 200);
				}
				else {
					resJson.put("error", "invalid_grant");
					resJson.put("error_description", "idJwt Different");
					resJson.put("error_code", String.valueOf(MStatus.ERR_MISMATCH_TOKEN_CUR_SESSION));
					resJson.put("http_status_code", 400);
				}

				result.put("data", resJson);
				return result;
			}

			if (!allowScopeList.contains("openid")) {
				result = new JSONObject();
				resJson = new JSONObject();
				result.put("code", String.valueOf(MStatus.ERR_INVALID_SCOPE));
				result.put("message", "idTokenValid() invalid_scope oidc");

				if (tokenStatusReturn) {
					resJson.put("active", "false");
					resJson.put("msg", "invalid_scope oidc");
					resJson.put("http_status_code", 200);
				}
				else {
					resJson.put("error", "invalid_scope");
					resJson.put("error_description", "invalid_scope oidc");
					resJson.put("error_code", String.valueOf(MStatus.ERR_INVALID_SCOPE));
					resJson.put("http_status_code", 400);
				}

				result.put("data", resJson);
				return result;
			}

			if (!issuer.equals(iss)) {
				result = new JSONObject();
				resJson = new JSONObject();
				result.put("code", String.valueOf(MStatus.ERR_MISMATCH_CLAIM_ISS));
				result.put("message", "idTokenValid() invalid_grant id_token iss Different");

				if (tokenStatusReturn) {
					resJson.put("active", "false");
					resJson.put("msg", "claim(iss) Different");
					resJson.put("http_status_code", 200);
				}
				else {
					resJson.put("error", "invalid_grant");
					resJson.put("error_description", "id_token iss Different");
					resJson.put("error_code", String.valueOf(MStatus.ERR_MISMATCH_CLAIM_ISS));
					resJson.put("http_status_code", 400);
				}

				result.put("data", resJson);
				return result;
			}

			if (!clientId.equals(aud)) {
				result = new JSONObject();
				resJson = new JSONObject();
				result.put("code", String.valueOf(MStatus.ERR_MISMATCH_CLAIM_AUD));
				result.put("message", "idTokenValid() invalid_grant id_token aud Different");

				if (tokenStatusReturn) {
					resJson.put("active", "false");
					resJson.put("msg", "claim(aud) Different");
					resJson.put("http_status_code", 200);
				}
				else {
					resJson.put("error", "invalid_grant");
					resJson.put("error_description", "id_token aud Different");
					resJson.put("error_code", String.valueOf(MStatus.ERR_MISMATCH_CLAIM_AUD));
					resJson.put("http_status_code", 400);
				}

				result.put("data", resJson);
				return result;
			}

			if (curDate.compareTo(expDate) >= 0) {
				result = new JSONObject();
				resJson = new JSONObject();
				result.put("code", String.valueOf(MStatus.ERR_TOKEN_EXPIRED));
				result.put("message", "idTokenValid() invalid_grant id_token exp time expiration");

				if (tokenStatusReturn) {
					resJson.put("active", "false");
					resJson.put("msg", "expired token");
					resJson.put("http_status_code", 200);
				}
				else {
					resJson.put("error", "invalid_grant");
					resJson.put("error_description", "id_token exp time expiration");
					resJson.put("error_code", String.valueOf(MStatus.ERR_TOKEN_EXPIRED));
					resJson.put("http_status_code", 400);
				}

				result.put("data", resJson);
				return result;
			}

			result = new JSONObject();
			resJson = new JSONObject();
			result.put("code", "0");
			result.put("message", "success");
			resJson.put("rootAuthSessionId", rootAuthSessionId);
			resJson.put("subAuthSessionId", subAuthSessionId);
			result.put("data", resJson);
		}
		catch (Exception e) {
			result = new JSONObject();
			resJson = new JSONObject();
			result.put("code", String.valueOf(MStatus.ERR_SERVER_EXCEPTION));
			result.put("message", "idTokenValid() Exception: " + e.getMessage());
			resJson.put("error", "server_error");
			resJson.put("error_description", "unexpected server error");
			resJson.put("error_code", String.valueOf(MStatus.ERR_SERVER_EXCEPTION));
			resJson.put("http_status_code", 500);
			result.put("data", resJson);
		}

		return result;
	}

	public JSONObject getTokenType(String reqToken, String tokenTypeHint, boolean tokenStatusReturn)
	{
		JSONObject result = null;
		JSONObject resJson = null;

		try {
			String tokenType = "";

			if (!Util.isEmpty(tokenTypeHint)) {
				tokenType = tokenTypeHint;
			}
			else {
				String reqTokenStr = getTokenString(reqToken);

				if (Util.isEmpty(reqTokenStr)) {
					result = new JSONObject();
					resJson = new JSONObject();
					result.put("code", String.valueOf(MStatus.ERR_TOKEN_ERROR_FORMAT));
					result.put("message", "getTokenType() invalid_grant error format token");

					if (tokenStatusReturn) {
						resJson.put("active", "false");
						resJson.put("msg", "invalid token format");
						resJson.put("http_status_code", 200);
					}
					else {
						resJson.put("error", "invalid_grant");
						resJson.put("error_description", "error format token");
						resJson.put("error_code", String.valueOf(MStatus.ERR_TOKEN_ERROR_FORMAT));
						resJson.put("http_status_code", 400);
					}

					result.put("data", resJson);
					return result;
				}

				JSONParser parser = new JSONParser();
				JSONObject reqTokenJson = null;
				reqTokenJson = (JSONObject) parser.parse(reqTokenStr);

				tokenType = (String) reqTokenJson.get("typ");

				if (Util.isEmpty(tokenType)) {
					result = new JSONObject();
					resJson = new JSONObject();
					result.put("code", String.valueOf(MStatus.ERR_CLAIM_TYP_EMPTY));
					result.put("message", "getTokenType() invalid_grant not found Token type");

					if (tokenStatusReturn) {
						resJson.put("active", "false");
						resJson.put("msg", "not found token type");
						resJson.put("http_status_code", 200);
					}
					else {
						resJson.put("error", "invalid_grant");
						resJson.put("error_description", "not found Token type");
						resJson.put("error_code", String.valueOf(MStatus.ERR_CLAIM_TYP_EMPTY));
						resJson.put("http_status_code", 400);
					}

					result.put("data", resJson);
					return result;
				}
			}

			result = new JSONObject();
			result.put("code", "0");
			result.put("message", "success");
			result.put("data", tokenType);
		}
		catch (Exception e) {
			result = new JSONObject();
			resJson = new JSONObject();
			result.put("code", String.valueOf(MStatus.ERR_SERVER_EXCEPTION));
			result.put("message", "getTokenType() Exception: " + e.getMessage());
			resJson.put("error", "server_error");
			resJson.put("error_description", "unexpected server error");
			resJson.put("error_code", String.valueOf(MStatus.ERR_SERVER_EXCEPTION));
			resJson.put("http_status_code", 500);
			result.put("data", resJson);
		}

		return result;
	}
}