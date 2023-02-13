package com.dreamsecurity.sso.agent.jwt;

import java.io.IOException;
import java.util.Date;
import java.util.List;

import com.dreamsecurity.sso.agent.client.ClientModel;
import com.dreamsecurity.sso.agent.client.ClientRepository;
import com.dreamsecurity.sso.agent.common.MStatus;
import com.dreamsecurity.sso.agent.crypto.CryptoApiException;
import com.dreamsecurity.sso.agent.crypto.SSOCryptoApi;
import com.dreamsecurity.sso.agent.util.OIDCUtil;
import com.dreamsecurity.sso.agent.util.Util;
import com.dreamsecurity.sso.lib.jsn.JSONObject;
import com.dreamsecurity.sso.lib.jsn.parser.JSONParser;

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

	private String encodeHeader() throws CryptoApiException, IOException
	{
		StringBuilder builder = new StringBuilder("{");
		builder.append("\"alg\":\"").append(alg).append("\"");

		if (typ != null)
			builder.append(",\"typ\" : \"").append(typ).append("\"");

		builder.append("}");

		return SSOCryptoApi.encode64(builder.toString().getBytes());
	}

	public boolean verifyJWT(String token)
	{
		boolean valid = false;

		try {
			String jwtHeader = null;
			String jwtPayload = null;
			StringBuilder buffer = new StringBuilder();
			String jwtSign = null;

			String[] jwtData = token.split("\\.");

			if (jwtData.length != 3) {
				valid = false;
				return valid;
			}

			jwtHeader = jwtData[0];
			jwtPayload = jwtData[1];
			jwtSign = OIDCUtil.base64urlToBase64(jwtData[2]);

			buffer.append(jwtHeader);
			buffer.append('.');
			buffer.append(jwtPayload);

			ClientModel clientModel = ClientRepository.getInstance().getClientModel();
			String signPublicKey = clientModel.getServerCert();

			SSOCryptoApi.getInstance().verifyJWT(jwtSign, buffer.toString().getBytes(), this.signAlgorithm, signPublicKey);

			valid = true;
		}
		catch (Exception e) {
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
			byte[] hash = SSOCryptoApi.getInstance().hash(accessToken.getBytes(), hashAlgorithm);
			byte[] sixteen_bytes = new byte[16];
			System.arraycopy(hash, 0, sixteen_bytes, 0, 16);
			String athash = SSOCryptoApi.encode64(sixteen_bytes);
			output = OIDCUtil.base64ToBase64url(athash);
		}
		catch (CryptoApiException e) {
			e.printStackTrace();
			output = "";
		}

		return output;
	}

	public JSONObject accessTokenValid(String accessJwt, String clientId, String issuer, String nonce, List<Object> allowScopeList)
	{
		JSONObject result = null;
		try {
			String accessTokenStr = getTokenString(accessJwt);

			if (Util.isEmpty(accessTokenStr)) {
				result = new JSONObject();
				result.put("code", String.valueOf(MStatus.ERR_CLIENT_ACCESS_TOKEN_FORMAT));
				result.put("message", "accessTokenValid() error format access_token");
				return result;
			}

			JSONParser parser = new JSONParser();
			JSONObject accessTokenJson = (JSONObject) parser.parse(accessTokenStr);
			String iss = (String) accessTokenJson.get("iss");
			String aud = (String) accessTokenJson.get("aud");
			String scope = (String) accessTokenJson.get("scope");

			long exp = Long.parseLong(accessTokenJson.get("exp").toString());
			Date curDate = new Date(System.currentTimeMillis());
			Date expDate = new Date(exp * 1000);

			if (!issuer.equals(iss)) {
				result = new JSONObject();
				result.put("code", String.valueOf(MStatus.ERR_CLIENT_MISMATCH_CLAIM_ISS));
				result.put("message", "accessTokenValid() access_token iss Different");
				return result;
			}

			if (!clientId.equals(aud)) {
				result = new JSONObject();
				result.put("code", String.valueOf(MStatus.ERR_CLIENT_MISMATCH_CLAIM_AUD));
				result.put("message", "accessTokenValid() access_token aud Different");
				return result;
			}

			if (curDate.compareTo(expDate) >= 0) {
				result = new JSONObject();
				result.put("code", String.valueOf(MStatus.ERR_CLIENT_TOKEN_EXPIRED));
				result.put("message", "accessTokenValid() access_token exp time expiration ");
				result.put("data", "");
				return result;
			}

			ClientRepository clientRepository = ClientRepository.getInstance();
			ClientModel clientModel = clientRepository.getClientModel();
			String nonceEnabled = clientModel.getNonce();

			if (nonceEnabled.equals("1")) {
				String jwtNonce = (String) accessTokenJson.get("nonce");
				if (Util.isEmpty(nonce) || Util.isEmpty(jwtNonce)) {
					result = new JSONObject();
					result.put("code", String.valueOf(MStatus.ERR_CLIENT_NONCE_NULL));
					result.put("message", "accessTokenValid() nonce is null");
					return result;
				}

				if (!nonce.equals(jwtNonce)) {
					result = new JSONObject();
					result.put("code", String.valueOf(MStatus.ERR_CLIENT_MISMATCH_CLAIM_NONCE));
					result.put("message", "accessTokenValid() mismatch nonce");
					return result;
				}
			}

			String[] scopes = scope.split(" ");

			for (int i = 0; i < scopes.length; i++) {
				if (!allowScopeList.contains(scopes[i])) {
					result = new JSONObject();
					result.put("code", String.valueOf(MStatus.ERR_CLIENT_INVALID_SCOPE));
					result.put("message", "accessTokenValid() invalid_scope");
					result.put("data", "");
					return result;
				}
			}

			result = new JSONObject();
			result.put("code", "0");
			result.put("message", "success");
			result.put("data", "");
		}
		catch (Exception e) {
			result = new JSONObject();
			result.put("code", String.valueOf(MStatus.ERR_CLIENT_EXCEPTION));
			result.put("message", "accessTokenValid() Exception: " + e.getMessage());
		}

		return result;
	}

	public JSONObject idTokenValid(String idJwt, String clientId, String issuer, String nonce, String accessJwt)
	{
		JSONObject result = null;

		try {
			String idTokenStr = getTokenString(idJwt);

			if (Util.isEmpty(idTokenStr)) {
				result = new JSONObject();
				result.put("code", String.valueOf(MStatus.ERR_CLIENT_ID_TOKEN_FORMAT));
				result.put("message", "idTokenValid() error format id_token");
				return result;
			}

			JSONParser parser = new JSONParser();
			JSONObject idTokenJson = null;
			idTokenJson = (JSONObject) parser.parse(idTokenStr);

			String iss = (String) idTokenJson.get("iss");
			String aud = (String) idTokenJson.get("aud");
			String atHash = (String) idTokenJson.get("at_hash");

			long exp = Long.parseLong(idTokenJson.get("exp").toString());
			Date curDate = new Date(System.currentTimeMillis());
			Date expDate = new Date(exp * 1000);

			if (!issuer.equals(iss)) {
				result = new JSONObject();
				result.put("code", String.valueOf(MStatus.ERR_CLIENT_MISMATCH_CLAIM_ISS));
				result.put("message", "idTokenValid() id_token iss Different");
				return result;
			}

			if (!clientId.equals(aud)) {
				result = new JSONObject();
				result.put("code", String.valueOf(MStatus.ERR_CLIENT_MISMATCH_CLAIM_AUD));
				result.put("message", "idTokenValid() id_token aud Different");
				return result;
			}

			if (curDate.compareTo(expDate) >= 0) {
				result = new JSONObject();
				result.put("code", String.valueOf(MStatus.ERR_CLIENT_TOKEN_EXPIRED));
				result.put("message", "idTokenValid() exp time expiration ");
				result.put("data", "");
				return result;
			}

			ClientRepository clientRepository = ClientRepository.getInstance();
			ClientModel clientModel = clientRepository.getClientModel();
			String nonceEnabled = clientModel.getNonce();

			if (nonceEnabled.equals("1")) {
				String jwtNonce = (String) idTokenJson.get("nonce");
				if (Util.isEmpty(nonce) || Util.isEmpty(jwtNonce)) {
					result = new JSONObject();
					result.put("code", String.valueOf(MStatus.ERR_CLIENT_NONCE_NULL));
					result.put("message", "idTokenValid() nonce is null");
					return result;
				}

				if (!nonce.equals(jwtNonce)) {
					result = new JSONObject();
					result.put("code", String.valueOf(MStatus.ERR_CLIENT_MISMATCH_CLAIM_NONCE));
					result.put("message", "idTokenValid() mismatch nonce");
					return result;
				}
			}

			String newAtHash = generateAtHash(accessJwt);

			if (!atHash.equals(newAtHash)) {
				result = new JSONObject();
				result.put("code", String.valueOf(MStatus.ERR_CLIENT_MISMATCH_CLAIM_ATHASH));
				result.put("message", "idTokenValid() id_token at_hash Different");
				return result;
			}

			result = new JSONObject();
			result.put("code", "0");
			result.put("message", "success");
			result.put("data", "");
		}
		catch (Exception e) {
			result = new JSONObject();
			result.put("code", String.valueOf(MStatus.ERR_CLIENT_EXCEPTION));
			result.put("message", "idTokenValid() Exception: " + e.getMessage());
			return result;
		}

		return result;
	}

	public JSONObject refreshTokenValid(String refreshJwt, String clientId, String issuer, String nonce)
	{
		JSONObject result = null;

		try {
			String refreshTokenStr = getTokenString(refreshJwt);

			if (Util.isEmpty(refreshTokenStr)) {
				result = new JSONObject();
				result.put("code", String.valueOf(MStatus.ERR_CLIENT_REFRESH_TOKEN_FORMAT));
				result.put("message", "refreshTokenValid() error format refresh_token");
				return result;
			}

			JSONParser parser = new JSONParser();
			JSONObject refreshTokenJson = null;
			refreshTokenJson = (JSONObject) parser.parse(refreshTokenStr);

			String iss = (String) refreshTokenJson.get("iss");
			String aud = (String) refreshTokenJson.get("aud");

			long exp = Long.parseLong(refreshTokenJson.get("exp").toString());
			Date curDate = new Date(System.currentTimeMillis());
			Date expDate = new Date(exp * 1000);

			if (!issuer.equals(iss)) {
				result = new JSONObject();
				result.put("code", String.valueOf(MStatus.ERR_CLIENT_MISMATCH_CLAIM_ISS));
				result.put("message", "refreshTokenValid() refresh_token iss Different");
				return result;
			}

			if (!clientId.equals(aud)) {
				result = new JSONObject();
				result.put("code", String.valueOf(MStatus.ERR_CLIENT_MISMATCH_CLAIM_AUD));
				result.put("message", "refreshTokenValid() refresh_token aud Different");
				return result;
			}

			if (curDate.compareTo(expDate) >= 0) {
				result = new JSONObject();
				result.put("code", String.valueOf(MStatus.ERR_CLIENT_TOKEN_EXPIRED));
				result.put("message", "refreshTokenValid() exp time expiration ");
				result.put("data", "");
				return result;
			}

			ClientRepository clientRepository = ClientRepository.getInstance();
			ClientModel clientModel = clientRepository.getClientModel();
			String nonceEnabled = clientModel.getNonce();

			if (nonceEnabled.equals("1")) {
				String jwtNonce = (String) refreshTokenJson.get("nonce");
				if (Util.isEmpty(nonce) || Util.isEmpty(jwtNonce)) {
					result = new JSONObject();
					result.put("code", String.valueOf(MStatus.ERR_CLIENT_NONCE_NULL));
					result.put("message", "refreshTokenValid() nonce is null");
					return result;
				}

				if (!nonce.equals(jwtNonce)) {
					result = new JSONObject();
					result.put("code", String.valueOf(MStatus.ERR_CLIENT_MISMATCH_CLAIM_NONCE));
					result.put("message", "refreshTokenValid() mismatch nonce");
					return result;
				}
			}

			result = new JSONObject();
			result.put("code", "0");
			result.put("message", "success");
			result.put("data", "");
		}
		catch (Exception e) {
			result = new JSONObject();
			result.put("code", String.valueOf(MStatus.ERR_CLIENT_EXCEPTION));
			result.put("message", "refreshTokenValid() Exception: " + e.getMessage());
			return result;
		}

		return result;
	}
}