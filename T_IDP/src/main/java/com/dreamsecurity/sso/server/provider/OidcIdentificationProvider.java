package com.dreamsecurity.sso.server.provider;

import java.net.URLEncoder;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import com.dreamsecurity.sso.lib.dsx.security.credential.Credential;
import com.dreamsecurity.sso.lib.dsx.security.x509.BasicX509Credential;
import com.dreamsecurity.sso.lib.jsn.JSONArray;
import com.dreamsecurity.sso.lib.jsn.JSONObject;
import com.dreamsecurity.sso.lib.jsn.parser.JSONParser;
import com.dreamsecurity.sso.lib.jtm.DateTime;
import com.dreamsecurity.sso.lib.slf.Logger;
import com.dreamsecurity.sso.lib.slf.LoggerFactory;
import com.dreamsecurity.sso.server.api.UserApiFactory;
import com.dreamsecurity.sso.server.api.admin.vo.ClientVO;
import com.dreamsecurity.sso.server.api.user.UserController;
import com.dreamsecurity.sso.server.client.ClientModel;
import com.dreamsecurity.sso.server.client.ClientRepository;
import com.dreamsecurity.sso.server.common.MStatus;
import com.dreamsecurity.sso.server.config.SSOConfig;
import com.dreamsecurity.sso.server.crypto.CryptoApiException;
import com.dreamsecurity.sso.server.crypto.SSOCryptoApi;
import com.dreamsecurity.sso.server.exception.SSOException;
import com.dreamsecurity.sso.server.ha.SyncMonitor;
import com.dreamsecurity.sso.server.jwt.JWTBuilder;
import com.dreamsecurity.sso.server.metadata.CredentialRepository;
import com.dreamsecurity.sso.server.session.OidcSessionManager;
import com.dreamsecurity.sso.server.session.RootAuthSession;
import com.dreamsecurity.sso.server.session.SubAuthSession;
import com.dreamsecurity.sso.server.token.AccessToken;
import com.dreamsecurity.sso.server.token.IDToken;
import com.dreamsecurity.sso.server.token.OAuth2Code;
import com.dreamsecurity.sso.server.token.RefreshToken;
import com.dreamsecurity.sso.server.util.OIDCUtil;
import com.dreamsecurity.sso.server.util.Util;

public class OidcIdentificationProvider
{
	private static Logger log = LoggerFactory.getLogger(OidcIdentificationProvider.class);
	private static OidcIdentificationProvider instance = null;

	OidcIdentificationProvider() throws SSOException
	{
		super();
	}

	public static OidcIdentificationProvider getInstance() throws SSOException
	{
		if (instance == null) {
			synchronized (OidcIdentificationProvider.class) {
				if (instance == null) {
					instance = new OidcIdentificationProvider();
				}
			}
		}

		return instance;
	}

	public JSONObject checkValidParamsAuth(HttpServletRequest request)
	{
		JSONObject result = null;
		JSONObject resJson = null;

		SSOConfig config = SSOConfig.getInstance();

		if (config.getAuthStatus() != 0) {
			log.error("### 인증 비활성화 상태");
			resJson = new JSONObject();
			resJson.put("error", "server_error");
			resJson.put("error_description", "Authentication disabled status");
			resJson.put("error_code", String.valueOf(MStatus.AUTH_NON_ACTIVE));
			resJson.put("http_status_code", 400);
			result = new JSONObject();
			result.put("code", String.valueOf(MStatus.AUTH_NON_ACTIVE));
			result.put("message", "인증 비활성화 상태");
			result.put("data", resJson);
			return result;
		}

		try {
			String code_challenge = request.getParameter("code_challenge") == null ? "" : request.getParameter("code_challenge");
			String scope = request.getParameter("scope") == null ? "" : request.getParameter("scope");
			String response_type = request.getParameter("response_type") == null ? "" : request.getParameter("response_type");
			String nonce = request.getParameter("nonce") == null ? "" : request.getParameter("nonce");
			String code_challenge_method = request.getParameter("code_challenge_method") == null ? "" : request.getParameter("code_challenge_method");
			String state = request.getParameter("state") == null ? "" : request.getParameter("state");
			String client_id = request.getParameter("client_id") == null ? "" : request.getParameter("client_id");
			String redirect_uri = request.getParameter("redirect_uri") == null ? "" : request.getParameter("redirect_uri");
			String[] scopes = scope.split("\\+");
			String redirectUrl = "";

			Map<String, String[]> formParams = request.getParameterMap();

			for (String key : formParams.keySet()) {
				if (formParams.get(key).length != 1) {
					resJson = new JSONObject();
					resJson.put("error", "invalid_request");
					resJson.put("error_description", "duplicated parameter " + key);
					resJson.put("error_code", String.valueOf(MStatus.ERR_DUPLICATE_PARAMETER));
					resJson.put("http_status_code", 400);
					result = new JSONObject();
					result.put("code", String.valueOf(MStatus.ERR_DUPLICATE_PARAMETER));
					result.put("message", "checkValidParamsAuth() invalid_request duplicated parameter " + key);
					result.put("data", resJson);
					return result;
				}
			}

			if (Util.isEmpty(client_id)) {
				resJson = new JSONObject();
				resJson.put("error", "invalid_request");
				resJson.put("error_description", "null parameter client_id");
				resJson.put("error_code", String.valueOf(MStatus.ERR_REQ_PARAMETER_EMPTY));
				resJson.put("http_status_code", 400);
				result = new JSONObject();
				result.put("code", String.valueOf(MStatus.ERR_REQ_PARAMETER_EMPTY));
				result.put("message", "checkValidParamsAuth() invalid_request null parameter client_id");
				result.put("data", resJson);
				return result;
			}

			// Check License
			result = EnvironInform.getInstance().checkLicense(client_id);

			if (Integer.parseInt((String) result.get("code")) != MStatus.SUCCESS) {
				resJson = new JSONObject();
				resJson.put("error", "server_error");
				resJson.put("error_description", result.get("message"));
				resJson.put("error_code", result.get("code"));
				resJson.put("http_status_code", 400);

				result.put("data", resJson);
				return result;
			}
			else {
				result = null;
			}

			if (Util.isEmpty(redirect_uri)) {
				resJson = new JSONObject();
				resJson.put("error", "invalid_request");
				resJson.put("error_description", "null parameter redirect_uri");
				resJson.put("error_code", String.valueOf(MStatus.ERR_REQ_PARAMETER_EMPTY));
				resJson.put("http_status_code", 400);
				result = new JSONObject();
				result.put("code", String.valueOf(MStatus.ERR_REQ_PARAMETER_EMPTY));
				result.put("message", "checkValidParamsAuth() invalid_request null parameter redirect_uri");
				result.put("data", resJson);
				return result;
			}

			ClientRepository clientRepository = ClientRepository.getInstance();
			ClientModel clientModel = clientRepository.getClient(client_id);

			if (clientModel == null) {
				resJson = new JSONObject();
				resJson.put("error", "invalid_client");
				resJson.put("error_description", "not found clientModel");
				resJson.put("error_code", String.valueOf(MStatus.ERR_CLIENT_NOT_EXIST));
				resJson.put("http_status_code", 401);
				result = new JSONObject();
				result.put("code", String.valueOf(MStatus.ERR_CLIENT_NOT_EXIST));
				result.put("message", "checkValidParamsAuth() invalid_client not found clientModel");
				result.put("data", resJson);
				return result;
			}

			ClientVO clientInfo = clientModel.getClientInfo();

			if (clientInfo == null) {
				resJson = new JSONObject();
				resJson.put("error", "invalid_client");
				resJson.put("error_description", "not found clientInfo");
				resJson.put("error_code", String.valueOf(MStatus.ERR_CLIENT_NOT_EXIST));
				resJson.put("http_status_code", 401);
				result = new JSONObject();
				result.put("code", String.valueOf(MStatus.ERR_CLIENT_NOT_EXIST));
				result.put("message", "checkValidParamsAuth() invalid_client not found clientInfo");
				result.put("data", resJson);
				return result;
			}

			List<Object> allowRedirectUriList = (List<Object>) clientModel.getRedirecturis();

			if (!allowRedirectUriList.contains(URLEncoder.encode(redirect_uri, "UTF-8"))) {
				resJson = new JSONObject();
				resJson.put("error", "invalid_grant");
				resJson.put("error_description", "invalid redirect_uri");
				resJson.put("error_code", String.valueOf(MStatus.ERR_INVALID_REDIRECT_URI));
				resJson.put("http_status_code", 400);
				result = new JSONObject();
				result.put("code", String.valueOf(MStatus.ERR_INVALID_REDIRECT_URI));
				result.put("message", "checkValidParamsAuth() invalid_grant invalid redirect_uri");
				result.put("data", resJson);
				return result;
			}

			if (Util.isEmpty(scope)) {
				JSONObject parameters = new JSONObject();
				parameters.put("error", "invalid_request");
				parameters.put("error_description", "null parameter scope");
				parameters.put("error_code", String.valueOf(MStatus.ERR_REQ_PARAMETER_EMPTY));
				redirectUrl = OIDCUtil.generateRedirectUrl(redirect_uri, parameters);
				resJson = new JSONObject();
				resJson.put("error", "invalid_request");
				resJson.put("error_description", "null parameter scope");
				resJson.put("error_code", String.valueOf(MStatus.ERR_REQ_PARAMETER_EMPTY));
				resJson.put("http_status_code", 400);
				resJson.put("redirectUrl", redirectUrl);
				result = new JSONObject();
				result.put("code", String.valueOf(MStatus.ERR_REQ_PARAMETER_EMPTY));
				result.put("message", "checkValidParamsAuth() invalid_request null parameter scope");
				result.put("data", resJson);
				return result;
			}

			if (Util.isEmpty(response_type)) {
				JSONObject parameters = new JSONObject();
				parameters.put("error", "invalid_request");
				parameters.put("error_description", "null parameter response_type");
				parameters.put("error_code", String.valueOf(MStatus.ERR_REQ_PARAMETER_EMPTY));
				redirectUrl = OIDCUtil.generateRedirectUrl(redirect_uri, parameters);
				resJson = new JSONObject();
				resJson.put("error", "invalid_request");
				resJson.put("error_description", "null parameter response_type");
				resJson.put("error_code", String.valueOf(MStatus.ERR_REQ_PARAMETER_EMPTY));
				resJson.put("http_status_code", 400);
				resJson.put("redirectUrl", redirectUrl);
				result = new JSONObject();
				result.put("code", String.valueOf(MStatus.ERR_REQ_PARAMETER_EMPTY));
				result.put("message", "checkValidParamsAuth() invalid_request null parameter response_type");
				result.put("data", resJson);
				return result;
			}

			if (Util.isEmpty(state)) {
				JSONObject parameters = new JSONObject();
				parameters.put("error", "invalid_request");
				parameters.put("error_description", "null parameter state");
				parameters.put("error_code", String.valueOf(MStatus.ERR_REQ_PARAMETER_EMPTY));
				redirectUrl = OIDCUtil.generateRedirectUrl(redirect_uri, parameters);
				resJson = new JSONObject();
				resJson.put("error", "invalid_request");
				resJson.put("error_description", "null parameter state");
				resJson.put("error_code", String.valueOf(MStatus.ERR_REQ_PARAMETER_EMPTY));
				resJson.put("http_status_code", 400);
				resJson.put("redirectUrl", redirectUrl);
				result = new JSONObject();
				result.put("code", String.valueOf(MStatus.ERR_REQ_PARAMETER_EMPTY));
				result.put("message", "checkValidParamsAuth() invalid_request null parameter state");
				result.put("data", resJson);
				return result;
			}

			if (clientInfo.getEnabled().equals("0")) {
				JSONObject parameters = new JSONObject();
				parameters.put("error", "invalid_grant");
				parameters.put("error_description", "disable client");
				parameters.put("error_code", String.valueOf(MStatus.ERR_CLIENT_DISABLED));
				redirectUrl = OIDCUtil.generateRedirectUrl(redirect_uri, parameters);
				resJson = new JSONObject();
				resJson.put("error", "invalid_grant");
				resJson.put("error_description", "disable client");
				resJson.put("error_code", String.valueOf(MStatus.ERR_CLIENT_DISABLED));
				resJson.put("http_status_code", 401);
				resJson.put("redirectUrl", redirectUrl);
				result = new JSONObject();
				result.put("code", String.valueOf(MStatus.ERR_CLIENT_DISABLED));
				result.put("message", "checkValidParamsAuth() invalid_grant disable client");
				result.put("data", resJson);
				return result;
			}

			if (!response_type.equals(clientInfo.getResponseType())) {
				JSONObject parameters = new JSONObject();
				parameters.put("error", "Unauthorized_client");
				parameters.put("error_description", "response type mismatch");
				parameters.put("error_code", String.valueOf(MStatus.ERR_MISMATCH_RESPONSE_TYPE));
				redirectUrl = OIDCUtil.generateRedirectUrl(redirect_uri, parameters);
				resJson = new JSONObject();
				resJson.put("error", "Unauthorized_client");
				resJson.put("error_description", "response type mismatch");
				resJson.put("error_code", String.valueOf(MStatus.ERR_MISMATCH_RESPONSE_TYPE));
				resJson.put("http_status_code", 401);
				resJson.put("redirectUrl", redirectUrl);
				result = new JSONObject();
				result.put("code", String.valueOf(MStatus.ERR_MISMATCH_RESPONSE_TYPE));
				result.put("message", "checkValidParamsAuth() Unauthorized_client response type mismatch");
				result.put("data", resJson);
				return result;
			}

			if (clientInfo.getNonce().equals("1")) {
				if (Util.isEmpty(nonce)) {
					JSONObject parameters = new JSONObject();
					parameters.put("error", "invalid_request");
					parameters.put("error_description", "null parameter nonce");
					parameters.put("error_code", String.valueOf(MStatus.ERR_REQ_PARAMETER_EMPTY));
					redirectUrl = OIDCUtil.generateRedirectUrl(redirect_uri, parameters);
					resJson = new JSONObject();
					resJson.put("error", "invalid_request");
					resJson.put("error_description", "null parameter nonce");
					resJson.put("error_code", String.valueOf(MStatus.ERR_REQ_PARAMETER_EMPTY));
					resJson.put("http_status_code", 400);
					resJson.put("redirectUrl", redirectUrl);
					result = new JSONObject();
					result.put("code", String.valueOf(MStatus.ERR_REQ_PARAMETER_EMPTY));
					result.put("message", "checkValidParamsAuth() invalid_request null parameter nonce");
					result.put("data", resJson);
					return result;
				}
			}

			if (clientInfo.getPkce().equals("1")) {
				if (Util.isEmpty(code_challenge_method) || Util.isEmpty(code_challenge)) {
					JSONObject parameters = new JSONObject();
					parameters.put("error", "invalid_request");
					parameters.put("error_description", "null parameter pkce");
					parameters.put("error_code", String.valueOf(MStatus.ERR_REQ_PARAMETER_EMPTY));
					redirectUrl = OIDCUtil.generateRedirectUrl(redirect_uri, parameters);
					resJson = new JSONObject();
					resJson.put("error", "invalid_request");
					resJson.put("error_description", "null parameter pkce");
					resJson.put("error_code", String.valueOf(MStatus.ERR_REQ_PARAMETER_EMPTY));
					resJson.put("http_status_code", 400);
					resJson.put("redirectUrl", redirectUrl);
					result = new JSONObject();
					result.put("code", String.valueOf(MStatus.ERR_REQ_PARAMETER_EMPTY));
					result.put("message", "checkValidParamsAuth() invalid_request null parameter pkce");
					result.put("data", resJson);
					return result;
				}
			}

			// scope
			List<Object> allowScopeList = (List<Object>) clientModel.getScopes();

			for (int i = 0; i < scopes.length; i++)
				if (!allowScopeList.contains(scopes[i])) {
					JSONObject parameters = new JSONObject();
					parameters.put("error", "invalid_scope");
					parameters.put("error_description", "invalid_scope " + scopes[i]);
					parameters.put("error_code", String.valueOf(MStatus.ERR_INVALID_SCOPE));
					redirectUrl = OIDCUtil.generateRedirectUrl(redirect_uri, parameters);
					resJson = new JSONObject();
					resJson.put("error", "invalid_scope");
					resJson.put("error_description", "invalid_scope " + scopes[i]);
					resJson.put("error_code", String.valueOf(MStatus.ERR_INVALID_SCOPE));
					resJson.put("http_status_code", 400);
					resJson.put("redirectUrl", redirectUrl);
					result = new JSONObject();
					result.put("code", String.valueOf(MStatus.ERR_INVALID_SCOPE));
					result.put("message", "checkValidParamsAuth() invalid_scope " + scopes[i]);
					result.put("data", resJson);
					return result;
				}

			result = new JSONObject();
			result.put("code", String.valueOf(MStatus.SUCCESS));
			result.put("message", "SUCCESS");
			result.put("data", clientInfo.getId());
		}
		catch (Exception e) {
			resJson = new JSONObject();
			resJson.put("error", "server_error");
			resJson.put("error_description", "unexpected server error");
			resJson.put("error_code", String.valueOf(MStatus.ERR_SERVER_EXCEPTION));
			resJson.put("http_status_code", 500);
			result = new JSONObject();
			result.put("code", String.valueOf(MStatus.ERR_SERVER_EXCEPTION));
			result.put("message", "checkValidParamsAuth() Exception: " + e.getMessage());
			result.put("data", resJson);
		}

		return result;
	}

	public JSONObject authCodeAuthorizationResponse(HttpServletRequest request, HttpServletResponse response, String id)
	{
		JSONObject result = null;
		JSONObject resJson = null;

		try {
			HttpSession session = request.getSession(true);
			String rootAuthSessionId = (String) session.getAttribute("DS_SESSION_ID");
			RootAuthSession rootAuthSession = null;
			SubAuthSession subAuthSession = null;

			ClientModel clientModel = ClientRepository.getInstance().getClient(id);
			ClientVO clientInfo = clientModel.getClientInfo();

			int sessionLifespan = SSOConfig.getInstance().getInt("oidc.session.validtime", 24);
			DateTime rootAuthSessionExpDate = new DateTime().plusHours(sessionLifespan);

			if (Util.isEmpty(rootAuthSessionId)) {
				rootAuthSession = OidcSessionManager.getInstance().generateRootAuthSession(session);
			}
			else {
				rootAuthSession = OidcSessionManager.getInstance().getRootAuthSession(rootAuthSessionId);
			}

			// 동기화 서버에 요청
			if (rootAuthSession == null) {
				rootAuthSession = getRootAuthSessionByEvent(rootAuthSessionId);
			}

			// Cookie에는 존재하지만, rootAuthSession이 만료돼서 사라 졌을 경우 재생성
			if (rootAuthSession == null) {
				rootAuthSession = OidcSessionManager.getInstance().generateRootAuthSession(session);
			}

			rootAuthSession.setExpDate(rootAuthSessionExpDate);
			rootAuthSessionId = rootAuthSession.getSessionId();
			subAuthSession = rootAuthSession.generateSubAuthSession();

			updatesubAuthSession(request, subAuthSession);
			boolean validSession = false;

			JWTBuilder jwtBuilder = JWTBuilder.getInstance();
			String identityJwt = rootAuthSession.getIdentityJwt();

			if (!Util.isEmpty(identityJwt)) {
				validSession = jwtBuilder.verifyJWT(identityJwt);
			}

			if (validSession) {
				String redirect_uri = subAuthSession.attributes.get("redirect_uri");
				OAuth2Code oauth2Code = null;
				int codeLifespan = Integer.parseInt(clientInfo.getCodeLifespan());
				DateTime oauth2CodeExpDate = new DateTime().plusSeconds(codeLifespan);

				oauth2Code = new OAuth2Code(rootAuthSessionId, subAuthSession.getSessionId(), oauth2CodeExpDate);

				subAuthSession.attributes.put("acr", "0");

				OidcSessionManager.getInstance().addOAuth2Code(oauth2Code);

				JSONObject parameters = new JSONObject();
				String state = subAuthSession.attributes.get("state");

				parameters.put("state", state); // state
				parameters.put("code", oauth2Code.getId()); // code
				String url = OIDCUtil.generateRedirectUrl(redirect_uri, parameters);

				JSONObject data = new JSONObject();
				data.put("validSession", validSession);
				data.put("url", url);

				result = new JSONObject();
				result.put("code", String.valueOf(MStatus.SUCCESS));
				result.put("message", "SUCCESS");
				result.put("data", data);

				// 다중화 서버 간 동기화
				SyncMonitor.startMonitor();
				SyncMonitor.registOidcAuthCodeRedirectEvent(rootAuthSession, oauth2Code);

				// Audit, Access Log
				String uid = rootAuthSession.attributes.get("uid");
				String uip = Util.getClientIP(request);
				String ubr = request.getAttribute("loginBr") == null ? "NN" : (String) request.getAttribute("loginBr");

				UserApiFactory.getUserApi().setConnectLog(uid, uip, ubr, clientInfo.getId());
				Util.setAuditInfo(uid, "AH", "0", uip + ", " + clientInfo.getId());
			}
			else {
				JSONObject data = new JSONObject();
				data.put("validSession", validSession);
				data.put("subAuthSessionId", subAuthSession.getSessionId());

				result = new JSONObject();
				result.put("code", String.valueOf(MStatus.SUCCESS));
				result.put("message", "SUCCESS");
				result.put("data", data);

				// 다중화 서버 간 동기화
				SyncMonitor.startMonitor();
				SyncMonitor.registOidcAuthEvent(rootAuthSession);
			}
		}
		catch (Exception e) {
			resJson = new JSONObject();
			resJson.put("error", "server_error");
			resJson.put("error_description", "unexpected server error");
			resJson.put("error_code", String.valueOf(MStatus.ERR_SERVER_EXCEPTION));
			resJson.put("http_status_code", 500);

			result = new JSONObject();
			result.put("code", String.valueOf(MStatus.ERR_SERVER_EXCEPTION));
			result.put("message", "authCodeAuthorizationResponse() Exception: " + e.getMessage());
			result.put("data", resJson);
		}

		return result;
	}

	public void updatesubAuthSession(HttpServletRequest request, SubAuthSession subAuthSession)
	{
		String code_challenge = request.getParameter("code_challenge") == null ? "" : request.getParameter("code_challenge");
		String scope = request.getParameter("scope") == null ? "" : request.getParameter("scope");
		String response_type = request.getParameter("response_type") == null ? "" : request.getParameter("response_type");
		String nonce = request.getParameter("nonce") == null ? "" : request.getParameter("nonce");
		String code_challenge_method = request.getParameter("code_challenge_method") == null ? "" : request.getParameter("code_challenge_method");
		String state = request.getParameter("state") == null ? "" : request.getParameter("state");
		String client_id = request.getParameter("client_id") == null ? "" : request.getParameter("client_id");
		String redirect_uri = request.getParameter("redirect_uri") == null ? "" : request.getParameter("redirect_uri");
		String logout_uri = request.getParameter("logout_uri") == null ? "" : request.getParameter("logout_uri");

		subAuthSession.attributes.put("scope", scope);
		subAuthSession.attributes.put("state", state);
		subAuthSession.attributes.put("client_id", client_id);
		subAuthSession.attributes.put("redirect_uri", redirect_uri);

		if (!Util.isEmpty(code_challenge)) {
			subAuthSession.attributes.put("code_challenge", code_challenge);
		}
		
		if (!Util.isEmpty(code_challenge_method)) {
			subAuthSession.attributes.put("code_challenge_method", code_challenge_method);
		}

		if (!Util.isEmpty(nonce)) {
			subAuthSession.attributes.put("nonce", nonce);
		}

		if (!Util.isEmpty(logout_uri)) {
			subAuthSession.attributes.put("logout_uri", logout_uri);
		}
	}

	public JSONObject checkValidSessionAuthenticate(HttpServletRequest request)
	{
		JSONObject result = null;
		JSONObject resJson = null;

		try {
			HttpSession session = request.getSession(false);
			String rootAuthSessionId = (String) session.getAttribute("DS_SESSION_ID");
			String subAuthSessionId = request.getParameter("SubAuthSessionId") == null ? "" : request.getParameter("SubAuthSessionId");

			if (Util.isEmpty(subAuthSessionId)) {
				result = new JSONObject();
				resJson = new JSONObject();
				result.put("code", String.valueOf(MStatus.ERR_SUBAUTHSESSION_ID_NOT_EXIST));
				result.put("message", "checkValidSessionAuthenticate() invalid_grant not found subAuthSessionId");
				resJson.put("error", "invalid_grant");
				resJson.put("error_description", "not found subAuthSessionId");
				resJson.put("error_code", String.valueOf(MStatus.ERR_SUBAUTHSESSION_ID_NOT_EXIST));
				resJson.put("http_status_code", 400);
				result.put("data", resJson);
				return result;
			}

			if (Util.isEmpty(rootAuthSessionId)) {
				result = new JSONObject();
				resJson = new JSONObject();
				result.put("code", String.valueOf(MStatus.ERR_ROOTAUTHSESSION_ID_NOT_EXIST));
				result.put("message", "checkValidSessionAuthenticate() invalid_grant not found rootAuthSessionId");
				resJson.put("error", "invalid_grant");
				resJson.put("error_description", "not found rootAuthSessionId");
				resJson.put("error_code", String.valueOf(MStatus.ERR_ROOTAUTHSESSION_ID_NOT_EXIST));
				resJson.put("http_status_code", 400);
				result.put("data", resJson);
				return result;
			}

			RootAuthSession rootAuthSession = OidcSessionManager.getInstance().getRootAuthSession(rootAuthSessionId);

			// 동기화 서버에 요청
			if (rootAuthSession == null) {
				rootAuthSession = getRootAuthSessionByEvent(rootAuthSessionId);
			}

			if (rootAuthSession == null) {
				result = new JSONObject();
				resJson = new JSONObject();
				result.put("code", String.valueOf(MStatus.ERR_ROOTAUTHSESSION_NOT_EXIST));
				result.put("message", "checkValidSessionAuthenticate() invalid_grant not found rootAuthSession");
				resJson.put("error", "invalid_grant");
				resJson.put("error_description", "not found rootAuthSession");
				resJson.put("error_code", String.valueOf(MStatus.ERR_ROOTAUTHSESSION_NOT_EXIST));
				resJson.put("http_status_code", 400);
				result.put("data", resJson);
				return result;
			}

			SubAuthSession subAuthSession = rootAuthSession.getSubAuthSession(subAuthSessionId);

			if (subAuthSession == null) {
				result = new JSONObject();
				resJson = new JSONObject();
				result.put("code", String.valueOf(MStatus.ERR_SUBAUTHSESSION_NOT_EXIST));
				result.put("message", "checkValidSessionAuthenticate() invalid_grant not found subAuthSession");
				resJson.put("error", "invalid_grant");
				resJson.put("error_description", "not found subAuthSession");
				resJson.put("error_code", String.valueOf(MStatus.ERR_SUBAUTHSESSION_NOT_EXIST));
				resJson.put("http_status_code", 400);
				result.put("data", resJson);
				return result;
			}

			result = new JSONObject();
			result.put("code", String.valueOf(MStatus.SUCCESS));
			result.put("message", "SUCCESS");
			result.put("data", "");
		}
		catch (Exception e) {
			result = new JSONObject();
			resJson = new JSONObject();
			result.put("code", String.valueOf(MStatus.ERR_SERVER_EXCEPTION));
			result.put("message", "checkValidSessionAuthenticate() Exception: " + e.getMessage());
			resJson.put("error", "server_error");
			resJson.put("error_description", "unexpected server error");
			resJson.put("error_code", String.valueOf(MStatus.ERR_SERVER_EXCEPTION));
			resJson.put("http_status_code", 500);
			result.put("data", resJson);
		}
		return result;
	}

	public JSONObject oidcLogin(HttpServletRequest request)
	{
		JSONObject result = null;

		try {
			String uid = request.getParameter("uid") == null ? "" : request.getParameter("uid");
			String upw = request.getParameter("upw") == null ? "" : request.getParameter("upw");
			String subAuthSessionId = request.getParameter("SubAuthSessionId") == null ? "" : request.getParameter("SubAuthSessionId");

			HttpSession session = request.getSession(false);
			String rootAuthSessionId = (String) session.getAttribute("DS_SESSION_ID");

			if (Util.isEmpty(uid)) {
				result = new JSONObject();
				result.put("code", String.valueOf(MStatus.ERR_USER_ID_NOT_EXIST));
				result.put("message", "oidcLogin() invalid_request null parameter uid");
				result.put("data", "");
				return result;
			}

			if (Util.isEmpty(upw)) {
				result = new JSONObject();
				result.put("code", String.valueOf(MStatus.ERR_USER_PW_NOT_EXIST));
				result.put("message", "oidcLogin() invalid_request null parameter upw");
				result.put("data", "");
				return result;
			}

			String url = "";
			String clientId = "";
			RootAuthSession rootAuthSession = OidcSessionManager.getInstance().getRootAuthSession(rootAuthSessionId);
			SubAuthSession subAuthSession = rootAuthSession.getSubAuthSession(subAuthSessionId);

			clientId = subAuthSession.attributes.get("client_id");
			request.setAttribute("spname", clientId);
			request.setAttribute("logintype", "ID_PW");
			request.setAttribute("id", uid);
			request.setAttribute("pw", upw);

			result = UserApiFactory.getUserApi().oidcLogin(request, rootAuthSession);

			if (Integer.parseInt((String) result.get("code")) != MStatus.SUCCESS) {
				return result;
			}
			subAuthSession.attributes.put("acr", "1");
		}
		catch (SSOException e) {
			log.error("### authnLogin() Exception: {}", e.getMessage());
			result = new JSONObject();
			result.put("code", String.valueOf(MStatus.ERR_SERVER_EXCEPTION));
			result.put("message", "oidcLogin() Exception: " + e.getMessage());
			result.put("data", "");
		}

		return result;
	}

	public JSONObject authCodeRedirect(HttpServletRequest request)
	{
		JSONObject result = null;
		JSONObject resJson = null;

		try {
			HttpSession session = request.getSession(false);
			String subAuthSessionId = request.getParameter("SubAuthSessionId") == null ? "" : request.getParameter("SubAuthSessionId");
			String rootAuthSessionId = (String) session.getAttribute("DS_SESSION_ID");
			String url = "";

			RootAuthSession rootAuthSession = OidcSessionManager.getInstance().getRootAuthSession(rootAuthSessionId);
			SubAuthSession subAuthSession = rootAuthSession.getSubAuthSession(subAuthSessionId);

			String uid = rootAuthSession.attributes.get("uid");
			String clientId = subAuthSession.attributes.get("client_id");

			ClientModel clientModel = ClientRepository.getInstance().getClient(clientId);

			if (clientModel == null) {
				result = new JSONObject();
				resJson = new JSONObject();
				result.put("code", String.valueOf(MStatus.ERR_CLIENT_NOT_EXIST));
				result.put("message", "authCodeRedirect() invalid_client not found clientModel");
				resJson.put("error", "invalid_client");
				resJson.put("error_description", "not found clientModel");
				resJson.put("error_code", String.valueOf(MStatus.ERR_CLIENT_NOT_EXIST));
				resJson.put("http_status_code", 401);
				result.put("data", resJson);
				return result;
			}

			ClientVO clientInfo = clientModel.getClientInfo();

			if (clientInfo == null) {
				result = new JSONObject();
				resJson = new JSONObject();
				result.put("code", String.valueOf(MStatus.ERR_CLIENT_NOT_EXIST));
				result.put("message", "authCodeRedirect() invalid_client not found clientInfo");
				resJson.put("error", "invalid_client");
				resJson.put("error_description", "not found clientInfo");
				resJson.put("error_code", String.valueOf(MStatus.ERR_CLIENT_NOT_EXIST));
				resJson.put("http_status_code", 401);
				result.put("data", resJson);
				return result;
			}

			if (clientInfo.getEnabled().equals("0")) {
				result = new JSONObject();
				resJson = new JSONObject();
				result.put("code", String.valueOf(MStatus.ERR_CLIENT_DISABLED));
				result.put("message", "authCodeRedirect() invalid_grant disable client");
				resJson.put("error", "invalid_grant");
				resJson.put("error_description", "disable client");
				resJson.put("error_code", String.valueOf(MStatus.ERR_CLIENT_DISABLED));
				resJson.put("http_status_code", 401);
				result.put("data", resJson);
				return result;
			}

			String client_id = clientInfo.getId();

			if (!subAuthSession.attributes.get("client_id").equals(client_id)) {
				result = new JSONObject();
				resJson = new JSONObject();
				result.put("code", String.valueOf(MStatus.ERR_MISMATCH_CLIENT_ID_CUR_SESSION));
				result.put("message", "authCodeRedirect() invalid_client not match client_id in session");
				resJson.put("error", "invalid_client");
				resJson.put("error_description", "not match client_id in session");
				resJson.put("error_code", String.valueOf(MStatus.ERR_MISMATCH_CLIENT_ID_CUR_SESSION));
				resJson.put("http_status_code", 401);
				result.put("data", resJson);
				return result;
			}

			List<Object> allowScopeList = (List<Object>) clientModel.getScopes();

			String scope = subAuthSession.attributes.get("scope");
			scope = scope.replace("+", " ");
			String[] scopes = scope.split(" ");

			for (int i = 0; i < scopes.length; i++) {
				if (!allowScopeList.contains(scopes[i])) {
					result = new JSONObject();
					resJson = new JSONObject();
					result.put("code", String.valueOf(MStatus.ERR_INVALID_SCOPE));
					result.put("message", "authCodeRedirect() invalid_scope " + scopes[i]);
					resJson.put("error", "invalid_scope");
					resJson.put("error_description", "invalid_scope " + scopes[i]);
					resJson.put("error_code", String.valueOf(MStatus.ERR_INVALID_SCOPE));
					resJson.put("http_status_code", 400);
					result.put("data", resJson);
					return result;
				}
			}

			List<Object> allowRedirectUriList = (List<Object>) clientModel.getRedirecturis();
			String redirect_uri = subAuthSession.attributes.get("redirect_uri");

			if (!allowRedirectUriList.contains(URLEncoder.encode(redirect_uri, "UTF-8"))) {
				result = new JSONObject();
				resJson = new JSONObject();
				result.put("code", String.valueOf(MStatus.ERR_MISMATCH_REDIRECT_URI_CUR_SESSION));
				result.put("message", "authCodeRedirect() invalid_grant not match redirect_uri in session");
				resJson.put("error", "invalid_grant");
				resJson.put("error_description", "not match redirect_uri in session");
				resJson.put("error_code", String.valueOf(MStatus.ERR_MISMATCH_REDIRECT_URI_CUR_SESSION));
				resJson.put("http_status_code", 400);
				result.put("data", resJson);
				return result;
			}

			// authcode 생성
			int codeLifespan = Integer.parseInt(clientInfo.getCodeLifespan());
			DateTime oauth2CodeExpDate = new DateTime().plusSeconds(codeLifespan);

			OAuth2Code oauth2Code = new OAuth2Code(rootAuthSessionId, subAuthSession.getSessionId(), oauth2CodeExpDate);

			OidcSessionManager.getInstance().addOAuth2Code(oauth2Code);

			JSONObject parameters = new JSONObject();
			String state = subAuthSession.attributes.get("state");

			parameters.put("state", state); // state
			parameters.put("code", oauth2Code.getId()); // code

			Iterator<String> iterator = parameters.keySet().iterator();
			StringBuffer addParam = new StringBuffer();
			url = OIDCUtil.generateRedirectUrl(redirect_uri, parameters);

			result = new JSONObject();
			result.put("code", String.valueOf(MStatus.SUCCESS));
			result.put("message", "SUCCESS");
			result.put("data", url);

			// 다중화 서버 간 동기화
			SyncMonitor.startMonitor();
			SyncMonitor.registOidcAuthCodeRedirectEvent(rootAuthSession, oauth2Code);
		}
		catch (Exception e) {
			result = new JSONObject();
			resJson = new JSONObject();
			result.put("code", String.valueOf(MStatus.ERR_SERVER_EXCEPTION));
			result.put("message", "authCodeRedirect() Exception: " + e.getMessage());
			resJson.put("error", "server_error");
			resJson.put("error_description", "unexpected server error");
			resJson.put("error_code", String.valueOf(MStatus.ERR_SERVER_EXCEPTION));
			resJson.put("http_status_code", 500);
			result.put("data", resJson);
		}
		return result;
	}

	public JSONObject checkGrantType(HttpServletRequest request)
	{
		JSONObject result = null;
		JSONObject resJson = null;

		try {
			Map<String, String[]> formParams = request.getParameterMap();

			for (String key : formParams.keySet()) {
				if (formParams.get(key).length != 1) {
					result = new JSONObject();
					resJson = new JSONObject();
					result.put("code", String.valueOf(MStatus.ERR_DUPLICATE_PARAMETER));
					result.put("message", "checkGrantType() invalid_request duplicated parameter " + key);
					resJson.put("error", "invalid_request");
					resJson.put("error_description", "duplicated parameter " + key);
					resJson.put("error_code", String.valueOf(MStatus.ERR_DUPLICATE_PARAMETER));
					resJson.put("http_status_code", 400);
					result.put("data", resJson);
					return result;
				}
			}

			String grant_type = request.getParameter("grant_type") == null ? "" : request.getParameter("grant_type");

			if (Util.isEmpty(grant_type)) {
				result = new JSONObject();
				resJson = new JSONObject();
				result.put("code", String.valueOf(MStatus.ERR_REQ_PARAMETER_EMPTY));
				result.put("message", "checkGrantType() invalid_request null parameter grant_type");
				resJson.put("error", "invalid_request");
				resJson.put("error_description", "null parameter grant_type");
				resJson.put("error_code", String.valueOf(MStatus.ERR_REQ_PARAMETER_EMPTY));
				resJson.put("http_status_code", 400);
				result.put("data", resJson);
				return result;
			}

			if (grant_type.equals(MStatus.AUTHORIZATION_CODE)) {
				result = new JSONObject();
				result.put("code", String.valueOf(MStatus.SUCCESS));
				result.put("message", "SUCCESS");
				result.put("data", MStatus.AUTHORIZATION_CODE_GRANT_TYPE);
			}
			else if (grant_type.equals(MStatus.REFRESH_TOKEN)) {
				result = new JSONObject();
				result.put("code", String.valueOf(MStatus.SUCCESS));
				result.put("message", "SUCCESS");
				result.put("data", MStatus.REFRESH_TOKEN_GRANT_TYPE);
			}
			else {
				result = new JSONObject();
				resJson = new JSONObject();
				result.put("code", String.valueOf(MStatus.ERR_UNSUPPORTED_GRANT_TYPE));
				result.put("message", "checkGrantType() unsupported_grant_type " + grant_type);
				resJson.put("error", "unsupported_grant_type");
				resJson.put("error_description", "unsupported_grant_type " + grant_type);
				resJson.put("error_code", String.valueOf(MStatus.ERR_UNSUPPORTED_GRANT_TYPE));
				resJson.put("http_status_code", 400);
				result.put("data", resJson);
			}
		}
		catch (Exception e) {
			result = new JSONObject();
			resJson = new JSONObject();
			result.put("code", String.valueOf(MStatus.ERR_SERVER_EXCEPTION));
			result.put("message", "checkGrantType() Exception: " + e.getMessage());
			resJson.put("error", "server_error");
			resJson.put("error_description", "unexpected server error");
			resJson.put("error_code", String.valueOf(MStatus.ERR_SERVER_EXCEPTION));
			resJson.put("http_status_code", 500);
			result.put("data", resJson);
		}

		return result;
	}

	public JSONObject codeToToken(HttpServletRequest request)
	{
		JSONObject result = null;
		JSONObject resJson = null;

		try {
			String code_verifier = request.getParameter("code_verifier") == null ? "" : request.getParameter("code_verifier");
			String grant_type = request.getParameter("grant_type") == null ? "" : request.getParameter("grant_type");
			String code = request.getParameter("code") == null ? "" : request.getParameter("code");
			String client_id = request.getParameter("client_id") == null ? "" : request.getParameter("client_id");
			String redirect_uri = request.getParameter("redirect_uri") == null ? "" : request.getParameter("redirect_uri");
			String client_secret = request.getParameter("client_secret") == null ? "" : request.getParameter("client_secret");

			// parameter null check
			if (Util.isEmpty(code)) {
				result = new JSONObject();
				resJson = new JSONObject();
				result.put("code", String.valueOf(MStatus.ERR_REQ_PARAMETER_EMPTY));
				result.put("message", "codeToToken() invalid_request null parameter code");
				resJson.put("error", "invalid_request");
				resJson.put("error_description", "null parameter code");
				resJson.put("error_code", String.valueOf(MStatus.ERR_REQ_PARAMETER_EMPTY));
				resJson.put("http_status_code", 400);
				result.put("data", resJson);
				return result;
			}

			if (Util.isEmpty(client_id)) {
				result = new JSONObject();
				resJson = new JSONObject();
				result.put("code", String.valueOf(MStatus.ERR_REQ_PARAMETER_EMPTY));
				result.put("message", "codeToToken() invalid_request null parameter client_id");
				resJson.put("error", "invalid_request");
				resJson.put("error_description", "null parameter client_id");
				resJson.put("error_code", String.valueOf(MStatus.ERR_REQ_PARAMETER_EMPTY));
				resJson.put("http_status_code", 400);
				result.put("data", resJson);
				return result;
			}

			if (Util.isEmpty(redirect_uri)) {
				result = new JSONObject();
				resJson = new JSONObject();
				result.put("code", String.valueOf(MStatus.ERR_REQ_PARAMETER_EMPTY));
				result.put("message", "codeToToken() invalid_request null parameter redirect_uri");
				resJson.put("error", "invalid_request");
				resJson.put("error_description", "null parameter redirect_uri");
				resJson.put("error_code", String.valueOf(MStatus.ERR_REQ_PARAMETER_EMPTY));
				resJson.put("http_status_code", 400);
				result.put("data", resJson);
				return result;
			}

			if (Util.isEmpty(client_secret)) {
				result = new JSONObject();
				resJson = new JSONObject();
				result.put("code", String.valueOf(MStatus.ERR_REQ_PARAMETER_EMPTY));
				result.put("message", "codeToToken() invalid_request null parameter client_secret");
				resJson.put("error", "invalid_request");
				resJson.put("error_description", "null parameter client_secret");
				resJson.put("error_code", String.valueOf(MStatus.ERR_REQ_PARAMETER_EMPTY));
				resJson.put("http_status_code", 400);
				result.put("data", resJson);
				return result;
			}

			// authcode check
			OAuth2Code oauth2Code = OidcSessionManager.getInstance().getOAuth2Code(code);

			if (oauth2Code == null) {
				result = new JSONObject();
				resJson = new JSONObject();
				result.put("code", String.valueOf(MStatus.ERR_AUTH_CODE_NOT_EXIST));
				result.put("message", "codeToToken() invalid_grant not found code");
				resJson.put("error", "invalid_grant");
				resJson.put("error_description", "not found code");
				resJson.put("error_code", String.valueOf(MStatus.ERR_AUTH_CODE_NOT_EXIST));
				resJson.put("http_status_code", 400);
				result.put("data", resJson);
				return result;
			}

			DateTime curDate = new DateTime();
			DateTime expDate = oauth2Code.getExpDate();

			// authcode time compare
			if (expDate.compareTo(curDate) < 0) {
				result = new JSONObject();
				resJson = new JSONObject();
				result.put("code", String.valueOf(MStatus.ERR_AUTH_CODE_AUTH_CODE_EXPIRED));
				result.put("message", "codeToToken() invalid_grant invalid code");
				resJson.put("error", "invalid_grant");
				resJson.put("error_description", "invalid code");
				resJson.put("error_code", String.valueOf(MStatus.ERR_AUTH_CODE_AUTH_CODE_EXPIRED));
				resJson.put("http_status_code", 400);
				result.put("data", resJson);
				return result;
			}

			String rootAuthSessionId = oauth2Code.getRootSessionId();
			String subAuthSessionId = oauth2Code.getSubSessionId();
			RootAuthSession rootAuthSession = null;
			SubAuthSession subAuthSession = null;

			if (Util.isEmpty(rootAuthSessionId)) {
				result = new JSONObject();
				resJson = new JSONObject();
				result.put("code", String.valueOf(MStatus.ERR_ROOTAUTHSESSION_ID_NOT_EXIST));
				result.put("message", "codeToToken() invalid_grant not found rootAuthSessionId");
				resJson.put("error", "invalid_grant");
				resJson.put("error_description", "not found rootAuthSessionId");
				resJson.put("error_code", String.valueOf(MStatus.ERR_ROOTAUTHSESSION_ID_NOT_EXIST));
				resJson.put("http_status_code", 400);
				result.put("data", resJson);
				return result;
			}
			else {
				rootAuthSession = OidcSessionManager.getInstance().getRootAuthSession(rootAuthSessionId);
			}

			// 동기화 서버에 요청
			if (rootAuthSession == null) {
				rootAuthSession = getRootAuthSessionByEvent(rootAuthSessionId);
			}

			if (rootAuthSession == null) {
				result = new JSONObject();
				resJson = new JSONObject();
				result.put("code", String.valueOf(MStatus.ERR_ROOTAUTHSESSION_NOT_EXIST));
				result.put("message", "codeToToken() invalid_grant not found rootAuthSession");
				resJson.put("error", "invalid_grant");
				resJson.put("error_description", "not found rootAuthSession");
				resJson.put("error_code", String.valueOf(MStatus.ERR_ROOTAUTHSESSION_NOT_EXIST));
				resJson.put("http_status_code", 400);
				result.put("data", resJson);
				return result;
			}

			if (Util.isEmpty(subAuthSessionId)) {
				result = new JSONObject();
				resJson = new JSONObject();
				result.put("code", String.valueOf(MStatus.ERR_SUBAUTHSESSION_ID_NOT_EXIST));
				result.put("message", "codeToToken() invalid_grant not found subAuthSessionId");
				resJson.put("error", "invalid_grant");
				resJson.put("error_description", "not found subAuthSessionId");
				resJson.put("error_code", String.valueOf(MStatus.ERR_SUBAUTHSESSION_ID_NOT_EXIST));
				resJson.put("http_status_code", 400);
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
				result.put("message", "codeToToken() invalid_grant not found subAuthSession");
				resJson.put("error", "invalid_grant");
				resJson.put("error_description", "not found subAuthSession");
				resJson.put("error_code", String.valueOf(MStatus.ERR_SUBAUTHSESSION_NOT_EXIST));
				resJson.put("http_status_code", 400);
				result.put("data", resJson);
				return result;
			}

			String clientId = subAuthSession.attributes.get("client_id");
			ClientModel clientModel = ClientRepository.getInstance().getClient(clientId);

			if (clientModel == null) {
				result = new JSONObject();
				resJson = new JSONObject();
				result.put("code", String.valueOf(MStatus.ERR_CLIENT_NOT_EXIST));
				result.put("message", "codeToToken() invalid_client not found clientModel");
				resJson.put("error", "invalid_client");
				resJson.put("error_description", "not found clientModel");
				resJson.put("error_code", String.valueOf(MStatus.ERR_CLIENT_NOT_EXIST));
				resJson.put("http_status_code", 401);
				result.put("data", resJson);
				return result;
			}

			ClientVO clientInfo = clientModel.getClientInfo();

			if (clientInfo == null) {
				result = new JSONObject();
				resJson = new JSONObject();
				result.put("code", String.valueOf(MStatus.ERR_CLIENT_NOT_EXIST));
				result.put("message", "codeToToken() invalid_client not found clientInfo");
				resJson.put("error", "invalid_client");
				resJson.put("error_description", "not found clientInfo");
				resJson.put("error_code", String.valueOf(MStatus.ERR_CLIENT_NOT_EXIST));
				resJson.put("http_status_code", 401);
				result.put("data", resJson);
				return result;
			}

			if (!clientInfo.getGrantType().equals(grant_type)) {
				result = new JSONObject();
				resJson = new JSONObject();
				result.put("code", String.valueOf(MStatus.ERR_MISMATCH_GRANT_TYPE));
				result.put("message", "codeToToken() Unauthorized_client grant type mismatch");
				resJson.put("error", "Unauthorized_client");
				resJson.put("error_description", "grant type mismatch");
				resJson.put("error_code", String.valueOf(MStatus.ERR_MISMATCH_GRANT_TYPE));
				resJson.put("http_status_code", 400);
				result.put("data", resJson);
				return result;
			}

			if (!clientInfo.getSecret().equals(client_secret)) {
				result = new JSONObject();
				resJson = new JSONObject();
				result.put("code", String.valueOf(MStatus.ERR_MISMATCH_CLIENT_SECRET));
				result.put("message", "codeToToken() invalid_grant client secret mismatch");
				resJson.put("error", "invalid_grant");
				resJson.put("error_description", "Invalid client secret mismatch");
				resJson.put("error_code", String.valueOf(MStatus.ERR_MISMATCH_CLIENT_SECRET));
				resJson.put("http_status_code", 400);
				result.put("data", resJson);
				return result;
			}

			if (clientInfo.getEnabled().equals("0")) {
				result = new JSONObject();
				resJson = new JSONObject();
				result.put("code", String.valueOf(MStatus.ERR_CLIENT_DISABLED));
				result.put("message", "codeToToken() invalid_grant disable client");
				resJson.put("error", "invalid_grant");
				resJson.put("error_description", "disable client");
				resJson.put("error_code", String.valueOf(MStatus.ERR_CLIENT_DISABLED));
				resJson.put("http_status_code", 401);
				result.put("data", resJson);
				return result;
			}

			if (clientInfo.getPkce().equals("1")) {
				if (Util.isEmpty(code_verifier)) {
					result = new JSONObject();
					resJson = new JSONObject();
					result.put("code", String.valueOf(MStatus.ERR_REQ_PARAMETER_EMPTY));
					result.put("message", "codeToToken() invalid_request null parameter code_verifier");
					resJson.put("error", "invalid_request");
					resJson.put("error_description", "null parameter code_verifier");
					resJson.put("error_code", String.valueOf(MStatus.ERR_REQ_PARAMETER_EMPTY));
					resJson.put("http_status_code", 400);
					result.put("data", resJson);
					return result;
				}

				String code_challenge = subAuthSession.attributes.get("code_challenge");
				String code_challenge_method = subAuthSession.attributes.get("code_challenge_method");

				if (Util.isEmpty(code_challenge_method) || Util.isEmpty(code_challenge)) {
					result = new JSONObject();
					resJson = new JSONObject();
					result.put("code", String.valueOf(MStatus.ERR_PKCE_NOT_EXIST));
					result.put("message", "codeToToken() invalid_grant not found code_challenge_method, code_challenge");
					resJson.put("error", "invalid_grant");
					resJson.put("error_description", "not found code_challenge_method, code_challenge");
					resJson.put("error_code", String.valueOf(MStatus.ERR_PKCE_NOT_EXIST));
					resJson.put("http_status_code", 400);
					result.put("data", resJson);
					return result;
				}

				SSOCryptoApi cryptoApi;
				cryptoApi = SSOCryptoApi.getInstance();

				if (!cryptoApi.hash(code_verifier).equals(code_challenge)) {
					result = new JSONObject();
					resJson = new JSONObject();
					result.put("code", String.valueOf(MStatus.ERR_PKCE_FAIL));
					result.put("message", "codeToToken() invalid_client fail pkce");
					resJson.put("error", "invalid_client");
					resJson.put("error_description", "fail pkce");
					resJson.put("error_code", String.valueOf(MStatus.ERR_PKCE_FAIL));
					resJson.put("http_status_code", 400);
					result.put("data", resJson);
					return result;
				}
			}

			if (!subAuthSession.attributes.get("client_id").equals(client_id)) {
				result = new JSONObject();
				resJson = new JSONObject();
				result.put("code", String.valueOf(MStatus.ERR_MISMATCH_CLIENT_ID_CUR_SESSION));
				result.put("message", "codeToToken() invalid_client not match client_id in session");
				resJson.put("error", "invalid_client");
				resJson.put("error_description", "not match client_id in session");
				resJson.put("error_code", String.valueOf(MStatus.ERR_MISMATCH_CLIENT_ID_CUR_SESSION));
				resJson.put("http_status_code", 401);
				result.put("data", resJson);
				return result;
			}

			if (!clientInfo.getId().equals(client_id)) {
				result = new JSONObject();
				resJson = new JSONObject();
				result.put("code", String.valueOf(MStatus.ERR_CLIENT_NOT_EXIST));
				result.put("message", "codeToToken() invalid_client not found client_id");
				resJson.put("error", "invalid_client");
				resJson.put("error_description", "not found client_id");
				resJson.put("error_code", String.valueOf(MStatus.ERR_CLIENT_NOT_EXIST));
				resJson.put("http_status_code", 401);
				result.put("data", resJson);
				return result;
			}

			if (!subAuthSession.attributes.get("redirect_uri").equals(redirect_uri)) {
				result = new JSONObject();
				resJson = new JSONObject();
				result.put("code", String.valueOf(MStatus.ERR_MISMATCH_REDIRECT_URI_CUR_SESSION));
				result.put("message", "codeToToken() invalid_grant not match redirect_uri in session");
				resJson.put("error", "invalid_grant");
				resJson.put("error_description", "not match redirect_uri in session");
				resJson.put("error_code", String.valueOf(MStatus.ERR_MISMATCH_REDIRECT_URI_CUR_SESSION));
				resJson.put("http_status_code", 400);
				result.put("data", resJson);
				return result;
			}

			List<Object> allowRedirectUriList = (List<Object>) clientModel.getRedirecturis();

			if (!allowRedirectUriList.contains(URLEncoder.encode(redirect_uri, "UTF-8"))) {
				result = new JSONObject();
				resJson = new JSONObject();
				result.put("code", String.valueOf(MStatus.ERR_INVALID_REDIRECT_URI));
				result.put("message", "codeToToken() invalid_grant invalid redirect_uri");
				resJson.put("error", "invalid_grant");
				resJson.put("error_description", "invalid redirect_uri");
				resJson.put("error_code", String.valueOf(MStatus.ERR_INVALID_REDIRECT_URI));
				resJson.put("http_status_code", 400);
				result.put("data", resJson);
				return result;
			}

			JWTBuilder jwtBuilder = JWTBuilder.getInstance();
			String identityJwt = rootAuthSession.getIdentityJwt();

			if (Util.isEmpty(identityJwt)) {
				result = new JSONObject();
				resJson = new JSONObject();
				result.put("code", String.valueOf(MStatus.ERR_LOGIN_TOKEN_NOT_EXIST));
				result.put("message", "codeToToken() invalid_grant not found login Token");
				resJson.put("error", "invalid_grant");
				resJson.put("error_description", "not found login Token");
				resJson.put("error_code", String.valueOf(MStatus.ERR_LOGIN_TOKEN_NOT_EXIST));
				resJson.put("http_status_code", 400);
				result.put("data", resJson);
				return result;
			}

			boolean validSession = false;
			validSession = jwtBuilder.verifyJWT(identityJwt);

			if (validSession == false) {
				result = new JSONObject();
				resJson = new JSONObject();
				result.put("code", String.valueOf(MStatus.ERR_AUTH_SESSION_INVALID));
				result.put("message", "codeToToken() invalid_grant auth session invalid");
				resJson.put("error", "invalid_grant");
				resJson.put("error_description", "auth session invalid");
				resJson.put("error_code", String.valueOf(MStatus.ERR_AUTH_SESSION_INVALID));
				resJson.put("http_status_code", 400);
				result.put("data", resJson);
				return result;
			}

			String identityTokenStr = jwtBuilder.getTokenString(identityJwt);

			if (Util.isEmpty(identityTokenStr)) {
				result = new JSONObject();
				resJson = new JSONObject();
				result.put("code", String.valueOf(MStatus.ERR_LOGIN_TOKEN_ERROR_FORMAT));
				result.put("message", "codeToToken() invalid_grant error format login Token");
				resJson.put("error", "invalid_grant");
				resJson.put("error_description", "error format login Token");
				resJson.put("error_code", String.valueOf(MStatus.ERR_LOGIN_TOKEN_ERROR_FORMAT));
				resJson.put("http_status_code", 400);
				result.put("data", resJson);
				return result;
			}

			resJson = new JSONObject();
			JSONParser parser = new JSONParser();
			JSONObject identityTokenJson = (JSONObject) parser.parse(identityTokenStr);

			String sub = (String) identityTokenJson.get("sub");
			String acr = subAuthSession.attributes.get("acr");
			String nonce = subAuthSession.attributes.get("nonce");
			String aud = clientInfo.getId();
			String auth_time = rootAuthSession.attributes.get("auth_time");
			String sid = jwtBuilder.generateSID(subAuthSessionId, rootAuthSessionId);
			String name = (String) identityTokenJson.get("name");
			String email = (String) identityTokenJson.get("email");

			if (clientInfo.getNonce().equals("1")) {
				if (Util.isEmpty(nonce)) {
					result = new JSONObject();
					resJson = new JSONObject();
					result.put("code", String.valueOf(MStatus.ERR_NONCE_NULL));
					result.put("message", "codeToToken() invalid_grant nonce is null");
					resJson.put("error", "invalid_grant");
					resJson.put("error_description", "nonce is null");
					resJson.put("error_code", String.valueOf(MStatus.ERR_NONCE_NULL));
					resJson.put("http_status_code", 400);
					result.put("data", resJson);
					return result;
				}
			}
			else {
				subAuthSession.attributes.remove("nonce");
				nonce = null;
			}

			int tokenLifespan = Integer.parseInt(clientInfo.getTokenLifespan());
			long iat = ((new Date(System.currentTimeMillis())).getTime() / 1000);
			long tokenExp = iat + tokenLifespan;

			List<Object> allowScopeList = (List<Object>) clientModel.getScopes();

			String scope = subAuthSession.attributes.get("scope");
			scope = scope.replace("+", " ");
			String[] scopes = scope.split(" ");

			for (int i = 0; i < scopes.length; i++) {
				if (!allowScopeList.contains(scopes[i])) {
					result = new JSONObject();
					resJson = new JSONObject();
					result.put("code", String.valueOf(MStatus.ERR_INVALID_SCOPE));
					result.put("message", "codeToToken() invalid_scope " + scopes[i]);
					resJson.put("error", "invalid_scope");
					resJson.put("error_description", "invalid_scope " + scopes[i]);
					resJson.put("error_code", String.valueOf(MStatus.ERR_INVALID_SCOPE));
					resJson.put("http_status_code", 400);
					result.put("data", resJson);
					return result;
				}
			}

			boolean idTokenUse = false;

			for (int i = 0; i < scopes.length; i++) {
				if (scopes[i].equals("openid")) {
					idTokenUse = true;
				}
			}

			String issuer = OIDCUtil.generateBaseUrl(request);
			
			// Access Token Generate
			AccessToken accessToken = new AccessToken(sub, sid, issuer, aud, iat, tokenExp, nonce, acr, scope,
					Long.parseLong(auth_time));
			String accessTokenStr = accessToken.tokenToJsonString();

			String accessJwt = jwtBuilder.generateJWT(accessTokenStr);
			subAuthSession.setAccessJwt(accessJwt);

			if (idTokenUse) {
				String at_hash = jwtBuilder.generateAtHash(accessJwt);
				// ID Token Generate
				IDToken idToken = new IDToken(sub, sid, name, email, issuer, aud, iat, tokenExp, nonce, acr, at_hash, Long.parseLong(auth_time));
				String idTokenStr = idToken.tokenToJsonString();
				String idJwt = jwtBuilder.generateJWT(idTokenStr);
				resJson.put("id_token", idJwt);
				subAuthSession.setIdJwt(idJwt);
			}

			if (clientInfo.getRefreshTokenUse().equals("1")) {
				int refreshTokenLifespan = Integer.parseInt(clientInfo.getRefreshTokenLifespan());
				long refreshExp = iat + refreshTokenLifespan;
				RefreshToken refreshToken = new RefreshToken(sub, sid, issuer, aud, iat, refreshExp, nonce, acr);
				String refreshTokenStr = refreshToken.tokenToJsonString();
				String refreshJwt = jwtBuilder.generateJWT(refreshTokenStr);
				resJson.put("refresh_token", refreshJwt);
				resJson.put("refresh_expires_in", Integer.toString(refreshTokenLifespan));
				subAuthSession.setRefreshJwt(refreshJwt);
			}

			resJson.put("access_token", accessJwt);
			resJson.put("token_type", "Bearer");
			resJson.put("expires_in", Integer.toString(tokenLifespan));

			int sessionLifespan = SSOConfig.getInstance().getInt("oidc.session.validtime", 24);
			DateTime rootAuthSessionExpDate = new DateTime().plusHours(sessionLifespan);
			rootAuthSession.setExpDate(rootAuthSessionExpDate);

			String clientLogoutUrl = subAuthSession.attributes.get("logout_uri");

			if (!Util.isEmpty(clientLogoutUrl)) {
				rootAuthSession.addLogoutUrl(clientLogoutUrl);
			}

			result = new JSONObject();
			result.put("code", String.valueOf(MStatus.SUCCESS));
			result.put("message", "SUCCESS");
			result.put("data", resJson);

			// 다중화 서버 간 동기화
			SyncMonitor.startMonitor();
			SyncMonitor.registOidcTokenGenerateEvent(rootAuthSession, oauth2Code);
		}
		catch (Exception e) {
			result = new JSONObject();
			resJson = new JSONObject();
			result.put("code", String.valueOf(MStatus.ERR_SERVER_EXCEPTION));
			result.put("message", "codeToToken() Exception: " + e.getMessage());
			resJson.put("error", "server_error");
			resJson.put("error_description", "unexpected server error");
			resJson.put("error_code", String.valueOf(MStatus.ERR_SERVER_EXCEPTION));
			resJson.put("http_status_code", 500);
			result.put("data", resJson);
		}

		return result;
	}

	public JSONObject refreshTokenGrant(HttpServletRequest request)
	{
		JSONObject result = null;
		JSONObject resJson = null;

		try {
			String client_id = request.getParameter("client_id") == null ? "" : request.getParameter("client_id");
			String cur_refresh_token = request.getParameter("refresh_token") == null ? "" : request.getParameter("refresh_token");
			String client_secret = request.getParameter("client_secret") == null ? "" : request.getParameter("client_secret");

			// parameter null check
			if (Util.isEmpty(client_id)) {
				result = new JSONObject();
				resJson = new JSONObject();
				result.put("code", String.valueOf(MStatus.ERR_REQ_PARAMETER_EMPTY));
				result.put("message", "refreshTokenGrant() invalid_request null parameter client_id");
				resJson.put("error", "invalid_request");
				resJson.put("error_description", "null parameter client_id");
				resJson.put("error_code", String.valueOf(MStatus.ERR_REQ_PARAMETER_EMPTY));
				resJson.put("http_status_code", 400);
				result.put("data", resJson);
				return result;
			}

			if (Util.isEmpty(cur_refresh_token)) {
				result = new JSONObject();
				resJson = new JSONObject();
				result.put("code", String.valueOf(MStatus.ERR_REQ_PARAMETER_EMPTY));
				result.put("message", "refreshTokenGrant() invalid_request null parameter refresh_token");
				resJson.put("error", "invalid_request");
				resJson.put("error_description", "null parameter refresh_token");
				resJson.put("error_code", String.valueOf(MStatus.ERR_REQ_PARAMETER_EMPTY));
				resJson.put("http_status_code", 400);
				result.put("data", resJson);
				return result;
			}

			if (Util.isEmpty(client_secret)) {
				result = new JSONObject();
				resJson = new JSONObject();
				result.put("code", String.valueOf(MStatus.ERR_REQ_PARAMETER_EMPTY));
				result.put("message", "refreshTokenGrant() invalid_request null parameter client_secret");
				resJson.put("error", "invalid_request");
				resJson.put("error_description", "null parameter client_secret");
				resJson.put("error_code", String.valueOf(MStatus.ERR_REQ_PARAMETER_EMPTY));
				resJson.put("http_status_code", 400);
				result.put("data", resJson);
				return result;
			}

			ClientRepository clientRepository = ClientRepository.getInstance();
			ClientModel clientModel = clientRepository.getClient(client_id);

			if (clientModel == null) {
				result = new JSONObject();
				resJson = new JSONObject();
				result.put("code", String.valueOf(MStatus.ERR_CLIENT_NOT_EXIST));
				result.put("message", "refreshTokenGrant() invalid_client not found clientModel");
				resJson.put("error", "invalid_client");
				resJson.put("error_description", "not found clientModel");
				resJson.put("error_code", String.valueOf(MStatus.ERR_CLIENT_NOT_EXIST));
				resJson.put("http_status_code", 401);
				result.put("data", resJson);
				return result;
			}

			ClientVO clientInfo = clientModel.getClientInfo();

			if (clientInfo == null) {
				result = new JSONObject();
				resJson = new JSONObject();
				result.put("code", String.valueOf(MStatus.ERR_CLIENT_NOT_EXIST));
				result.put("message", "refreshTokenGrant() invalid_client not found clientInfo");
				resJson.put("error", "invalid_client");
				resJson.put("error_description", "not found clientInfo");
				resJson.put("error_code", String.valueOf(MStatus.ERR_CLIENT_NOT_EXIST));
				resJson.put("http_status_code", 401);
				result.put("data", resJson);
				return result;
			}

			if (clientInfo.getEnabled().equals("0")) {
				result = new JSONObject();
				resJson = new JSONObject();
				result.put("code", String.valueOf(MStatus.ERR_CLIENT_DISABLED));
				result.put("message", "refreshTokenGrant() invalid_grant disable client");
				resJson.put("error", "invalid_grant");
				resJson.put("error_description", "disable client");
				resJson.put("error_code", String.valueOf(MStatus.ERR_CLIENT_DISABLED));
				resJson.put("http_status_code", 401);
				result.put("data", resJson);
				return result;
			}

			if (!clientInfo.getSecret().equals(client_secret)) {
				result = new JSONObject();
				resJson = new JSONObject();
				result.put("code", String.valueOf(MStatus.ERR_MISMATCH_CLIENT_SECRET));
				result.put("message", "refreshTokenGrant() invalid_grant Invalid client secret");
				resJson.put("error", "invalid_grant");
				resJson.put("error_description", "Invalid client secret");
				resJson.put("error_code", String.valueOf(MStatus.ERR_MISMATCH_CLIENT_SECRET));
				resJson.put("http_status_code", 400);
				result.put("data", resJson);
				return result;
			}

			JWTBuilder jwtBuilder = JWTBuilder.getInstance();

			if (jwtBuilder.verifyJWT(cur_refresh_token) == false) {
				result = new JSONObject();
				resJson = new JSONObject();
				result.put("code", String.valueOf(MStatus.ERR_TOKEN_VERIFY_FAIL));
				result.put("message", "refreshTokenGrant() invalid_grant verify fail refresh_token");
				resJson.put("error", "invalid_grant");
				resJson.put("error_description", "verify fail refresh_token");
				resJson.put("error_code", String.valueOf(MStatus.ERR_TOKEN_VERIFY_FAIL));
				resJson.put("http_status_code", 400);
				result.put("data", resJson);
				return result;
			}

			String issuer = OIDCUtil.generateBaseUrl(request);

			result = jwtBuilder.refreshTokenValid(cur_refresh_token, client_id, issuer, clientInfo.getRefreshTokenUse(),
					false);

			if (Integer.parseInt((String) result.get("code")) != MStatus.SUCCESS) {
				return result;
			}

			JSONObject sessionIds = (JSONObject) result.get("data");
			String rootAuthSessionId = (String) sessionIds.get("rootAuthSessionId");
			String subAuthSessionId = (String) sessionIds.get("subAuthSessionId");

			RootAuthSession rootAuthSession = null;
			SubAuthSession subAuthSession = null;

			rootAuthSession = OidcSessionManager.getInstance().getRootAuthSession(rootAuthSessionId);
			subAuthSession = rootAuthSession.getSubAuthSession(subAuthSessionId);

			String identityJwt = rootAuthSession.getIdentityJwt();

			if (Util.isEmpty(identityJwt)) {
				result = new JSONObject();
				resJson = new JSONObject();
				result.put("code", String.valueOf(MStatus.ERR_LOGIN_TOKEN_NOT_EXIST));
				result.put("message", "refreshTokenGrant() invalid_grant not found login Token");
				resJson.put("error", "invalid_grant");
				resJson.put("error_description", "not found login Token");
				resJson.put("error_code", String.valueOf(MStatus.ERR_LOGIN_TOKEN_NOT_EXIST));
				resJson.put("http_status_code", 400);
				result.put("data", resJson);
				return result;
			}

			boolean validSession = jwtBuilder.verifyJWT(identityJwt);

			if (validSession == false) {
				result = new JSONObject();
				resJson = new JSONObject();
				result.put("code", String.valueOf(MStatus.ERR_AUTH_SESSION_INVALID));
				result.put("message", "refreshTokenGrant() invalid_grant auth session invalid");
				resJson.put("error", "invalid_grant");
				resJson.put("error_description", "auth session invalid");
				resJson.put("error_code", String.valueOf(MStatus.ERR_AUTH_SESSION_INVALID));
				resJson.put("http_status_code", 400);
				result.put("data", resJson);
				return result;
			}

			if (!client_id.equals(subAuthSession.attributes.get("client_id"))) {
				result = new JSONObject();
				resJson = new JSONObject();
				result.put("code", String.valueOf(MStatus.ERR_MISMATCH_CLIENT_ID_CUR_SESSION));
				result.put("message", "refreshTokenGrant() invalid_client not match client_id in session");
				resJson.put("error", "invalid_client");
				resJson.put("error_description", "not match client_id in session");
				resJson.put("error_code", String.valueOf(MStatus.ERR_MISMATCH_CLIENT_ID_CUR_SESSION));
				resJson.put("http_status_code", 401);
				result.put("data", resJson);
				return result;
			}

			// scope
			List<Object> allowScopeList = (List<Object>) clientModel.getScopes();
			String scope = subAuthSession.attributes.get("scope");
			scope = scope.replace("+", " ");
			String[] scopes = scope.split(" ");

			for (int i = 0; i < scopes.length; i++) {
				if (!allowScopeList.contains(scopes[i])) {
					result = new JSONObject();
					resJson = new JSONObject();
					result.put("code", String.valueOf(MStatus.ERR_INVALID_SCOPE));
					result.put("message", "refreshTokenGrant() invalid_scope " + scopes[i]);
					resJson.put("error", "invalid_scope");
					resJson.put("error_description", "invalid_scope " + scopes[i]);
					resJson.put("error_code", String.valueOf(MStatus.ERR_INVALID_SCOPE));
					resJson.put("http_status_code", 400);
					result.put("data", resJson);
					return result;
				}
			}

			JSONParser parser = new JSONParser();
			String identityTokenStr = jwtBuilder.getTokenString(identityJwt);

			if (Util.isEmpty(identityTokenStr)) {
				result = new JSONObject();
				resJson = new JSONObject();
				result.put("code", String.valueOf(MStatus.ERR_LOGIN_TOKEN_ERROR_FORMAT));
				result.put("message", "refreshTokenGrant() invalid_grant error format login Token");
				resJson.put("error", "invalid_grant");
				resJson.put("error_description", "error format login Token");
				resJson.put("error_code", String.valueOf(MStatus.ERR_LOGIN_TOKEN_ERROR_FORMAT));
				resJson.put("http_status_code", 400);
				result.put("data", resJson);
				return result;
			}

			JSONObject identityTokenJson = (JSONObject) parser.parse(identityTokenStr);
			String sub = (String) identityTokenJson.get("sub");
			String auth_time = rootAuthSession.attributes.get("auth_time");
			String nonce = subAuthSession.attributes.get("nonce");
			String aud = clientInfo.getId();
			Date curDate = new Date(System.currentTimeMillis());
			int tokenLifespan = Integer.parseInt(clientInfo.getTokenLifespan());
			long iat = curDate.getTime() / 1000;
			long tokenExp = iat + tokenLifespan;
			String acr = subAuthSession.attributes.get("acr");
			String sid = jwtBuilder.generateSID(subAuthSessionId, rootAuthSessionId);
			String name = (String) identityTokenJson.get("name");
			String email = (String) identityTokenJson.get("email");
			
			if (clientInfo.getNonce().equals("1")) {
				if (Util.isEmpty(nonce)) {
					result = new JSONObject();
					resJson = new JSONObject();
					result.put("code", String.valueOf(MStatus.ERR_NONCE_NULL));
					result.put("message", "refreshTokenGrant() invalid_grant nonce is null");
					resJson.put("error", "invalid_grant");
					resJson.put("error_description", "nonce is null");
					resJson.put("error_code", String.valueOf(MStatus.ERR_NONCE_NULL));
					resJson.put("http_status_code", 400);
					result.put("data", resJson);
					return result;
				}
			} else {
				subAuthSession.attributes.remove("nonce");
				nonce = null;
			}

			AccessToken newAccessToken = new AccessToken(sub, sid, issuer, aud, iat, tokenExp, nonce, acr, scope,
					Long.parseLong(auth_time));
			String newAccessTokenStr = newAccessToken.tokenToJsonString();
			String newAccessJwt = jwtBuilder.generateJWT(newAccessTokenStr);
			subAuthSession.setAccessJwt(newAccessJwt);

			resJson = new JSONObject();

			boolean idTokenUse = false;

			for (int i = 0; i < scopes.length; i++) {
				if (scopes[i].equals("openid")) {
					idTokenUse = true;
				}
			}

			if (idTokenUse) {
				String at_hash = jwtBuilder.generateAtHash(newAccessJwt);
				IDToken newIdToken = new IDToken(sub, sid, name, email, issuer, aud, iat, tokenExp, nonce, acr, at_hash,
						Long.parseLong(auth_time));
				String newIdTokenStr = newIdToken.tokenToJsonString();
				String newIdJwt = jwtBuilder.generateJWT(newIdTokenStr);
				subAuthSession.setIdJwt(newIdJwt);
				resJson.put("id_token", newIdJwt);

			}

			int refreshTokenLifespan = Integer.parseInt(clientInfo.getRefreshTokenLifespan());
			long refreshExp = iat + refreshTokenLifespan;
			RefreshToken newRefreshToken = new RefreshToken(sub, sid, issuer, aud, iat, refreshExp, nonce, acr);
			String newRefreshTokenStr = newRefreshToken.tokenToJsonString();
			String newRefreshJwt = jwtBuilder.generateJWT(newRefreshTokenStr);
			subAuthSession.setRefreshJwt(newRefreshJwt);

			resJson.put("refresh_token", newRefreshJwt);
			resJson.put("refresh_expires_in", Integer.toString(refreshTokenLifespan));

			resJson.put("access_token", newAccessJwt);
			resJson.put("token_type", "Bearer");
			resJson.put("expires_in", Integer.toString(tokenLifespan));

			int sessionLifespan = SSOConfig.getInstance().getInt("oidc.session.validtime", 24);
			DateTime rootAuthSessionExpDate = new DateTime().plusHours(sessionLifespan);
			rootAuthSession.setExpDate(rootAuthSessionExpDate);

			result = new JSONObject();
			result.put("code", String.valueOf(MStatus.SUCCESS));
			result.put("message", "SUCCESS");
			result.put("data", resJson);

			SyncMonitor.startMonitor();
			SyncMonitor.registOidcTokenRefreshEvent(rootAuthSession);
		}
		catch (Exception e) {
			result = new JSONObject();
			resJson = new JSONObject();
			result.put("code", String.valueOf(MStatus.ERR_SERVER_EXCEPTION));
			result.put("message", "refreshTokenGrant() Exception: " + e.getMessage());
			resJson.put("error", "server_error");
			resJson.put("error_description", "unexpected server error");
			resJson.put("error_code", String.valueOf(MStatus.ERR_SERVER_EXCEPTION));
			resJson.put("http_status_code", 500);
			result.put("data", resJson);
		}

		return result;
	}

	public JSONObject tokenIntrospect(HttpServletRequest request)
	{
		JSONObject result = null;
		JSONObject resJson = null;

		try {
			String headerAuthorization = request.getHeader("Authorization");
			String reqToken = request.getParameter("token") == null ? "" : request.getParameter("token");
			String tokenTypeHint = "";
			String authType = "";
			String client_id = "";
			String client_secret = "";
			String accessToken = "";
			Map<String, String[]> formParams = request.getParameterMap();
			JWTBuilder jwtBuilder = JWTBuilder.getInstance();

			for (String key : formParams.keySet()) {
				if (formParams.get(key).length != 1) {
					result = new JSONObject();
					resJson = new JSONObject();
					result.put("code", String.valueOf(MStatus.ERR_DUPLICATE_PARAMETER));
					result.put("message", "tokenIntrospect() invalid_request duplicated parameter " + key);
					resJson.put("error", "invalid_request");
					resJson.put("error_description", "duplicated parameter " + key);
					resJson.put("error_code", String.valueOf(MStatus.ERR_DUPLICATE_PARAMETER));
					resJson.put("http_status_code", 400);
					result.put("data", resJson);
					return result;
				}
			}

			if (Util.isEmpty(headerAuthorization)) {
				result = new JSONObject();
				resJson = new JSONObject();
				result.put("code", String.valueOf(MStatus.ERR_AUTHORIZATION_HEADER_EMPTY));
				result.put("message", "tokenIntrospect() invalid_client Authorization null");
				resJson.put("error", "invalid_client");
				resJson.put("error_description", "header Authorization null");
				resJson.put("http_status_code", 401);
				resJson.put("error_code", String.valueOf(MStatus.ERR_AUTHORIZATION_HEADER_EMPTY));
				result.put("data", resJson);
				return result;
			}

			String[] authorizationParse = headerAuthorization.split(" ");

			if (authorizationParse.length != 2) {
				result = new JSONObject();
				resJson = new JSONObject();
				result.put("code", String.valueOf(MStatus.ERR_AUTHORIZATION_HEADER_PARSE_FAIL));
				result.put("message", "tokenIntrospect() invalid_client Authorization parse fail");
				resJson.put("error", "invalid_client");
				resJson.put("error_description", "Authorization parse fail");
				resJson.put("error_code", String.valueOf(MStatus.ERR_AUTHORIZATION_HEADER_PARSE_FAIL));
				resJson.put("http_status_code", 401);
				result.put("data", resJson);
				return result;
			}

			if (authorizationParse[0].equals(MStatus.AUTHORIZATION_HEADER_TYPE_BASIC)) {
				authType = MStatus.AUTHORIZATION_HEADER_TYPE_BASIC;
				SSOCryptoApi cryptoApi;
				cryptoApi = SSOCryptoApi.getInstance();
				String credentials = null;
				tokenTypeHint = request.getParameter("token_type_hint") == null ? "" : request.getParameter("token_type_hint");
				try {
					credentials = new String(cryptoApi.decode64(authorizationParse[1]));
				}
				catch (CryptoApiException e) {
					result = new JSONObject();
					resJson = new JSONObject();
					result.put("code", String.valueOf(MStatus.ERR_DECODE_AUTHORIZATION_HEADER));
					result.put("message", "tokenIntrospect() invalid_client introspect header decode fail");
					resJson.put("error", "invalid_client");
					resJson.put("error_description", "introspect header decode fail");
					resJson.put("error_code", String.valueOf(MStatus.ERR_DECODE_AUTHORIZATION_HEADER));
					resJson.put("http_status_code", 401);
					result.put("data", resJson);
					return result;
				}

				String[] credentialsParse = credentials.split("\\:");

				if (credentialsParse.length != 2) {
					result = new JSONObject();
					resJson = new JSONObject();
					result.put("code", String.valueOf(MStatus.ERR_AUTHORIZATION_HEADER_CREDENTIALS_PARSE_FAIL));
					result.put("message", "tokenIntrospect() invalid_client credentials parse fail");
					resJson.put("error", "invalid_client");
					resJson.put("error_description", "credentials parse fail");
					resJson.put("error_code", String.valueOf(MStatus.ERR_AUTHORIZATION_HEADER_CREDENTIALS_PARSE_FAIL));
					resJson.put("http_status_code", 401);
					result.put("data", resJson);
					return result;
				}

				client_id = credentialsParse[0];
				client_secret = credentialsParse[1];
			} else if (authorizationParse[0].equals(MStatus.AUTHORIZATION_HEADER_TYPE_BEARER)) {
				authType = MStatus.AUTHORIZATION_HEADER_TYPE_BEARER;
				accessToken = authorizationParse[1];
				if (Util.isEmpty(accessToken)) {
					result = new JSONObject();
					resJson = new JSONObject();
					result.put("code", String.valueOf(MStatus.ERR_AUTHORIZATION_HEADER_CREDENTIALS_PARSE_FAIL));
					result.put("message", "tokenIntrospect() invalid_request null credential access_token");
					resJson.put("error", "invalid_request");
					resJson.put("error_description", "null credential access_token");
					resJson.put("error_code", String.valueOf(MStatus.ERR_AUTHORIZATION_HEADER_CREDENTIALS_PARSE_FAIL));
					resJson.put("http_status_code", 400);
					result.put("data", resJson);
					return result;
				} else {
					String accessTokenStr = jwtBuilder.getTokenString(accessToken);
					if (Util.isEmpty(accessTokenStr)) {
						result = new JSONObject();
						resJson = new JSONObject();
						result.put("code", String.valueOf(MStatus.ERR_ACCESS_TOKEN_ERROR_FORMAT));
						result.put("message", "tokenIntrospect() invalid_grant error format access_token");

						resJson.put("error", "invalid_grant");
						resJson.put("error_description", "error format access_token");
						resJson.put("error_code", String.valueOf(MStatus.ERR_ACCESS_TOKEN_ERROR_FORMAT));
						resJson.put("http_status_code", 400);

						result.put("data", resJson);
						return result;
					} else {
						JSONParser parser = new JSONParser();
						JSONObject accessTokenJson = (JSONObject) parser.parse(accessTokenStr);
						client_id = (String) accessTokenJson.get("aud");
					}
				}
			} else {
				result = new JSONObject();
				resJson = new JSONObject();
				result.put("code", String.valueOf(MStatus.ERR_MISMATCH_AUTHORIZATION_HEADER_TYPE));
				result.put("message", "tokenIntrospect() invalid_client not supported this type");
				resJson.put("error", "invalid_client");
				resJson.put("error_description", "not supported this type");
				resJson.put("error_code", String.valueOf(MStatus.ERR_MISMATCH_AUTHORIZATION_HEADER_TYPE));
				resJson.put("http_status_code", 401);
				result.put("data", resJson);
				return result;
			}

			// parameter null check
			if (Util.isEmpty(reqToken)) {
				result = new JSONObject();
				resJson = new JSONObject();
				result.put("code", String.valueOf(MStatus.ERR_REQ_PARAMETER_EMPTY));
				result.put("message", "tokenIntrospect() invalid_request null parameter token");
				resJson.put("error", "invalid_request");
				resJson.put("error_description", "null parameter token");
				resJson.put("error_code", String.valueOf(MStatus.ERR_REQ_PARAMETER_EMPTY));
				resJson.put("http_status_code", 400);
				result.put("data", resJson);
				return result;
			}

			ClientRepository clientRepository = ClientRepository.getInstance();
			ClientModel clientModel = clientRepository.getClient(client_id);

			if (clientModel == null) {
				result = new JSONObject();
				resJson = new JSONObject();
				result.put("code", String.valueOf(MStatus.ERR_CLIENT_NOT_EXIST));
				result.put("message", "tokenIntrospect() invalid_client not found clientModel");
				resJson.put("error", "invalid_client");
				resJson.put("error_description", "not found clientModel");
				resJson.put("error_code", String.valueOf(MStatus.ERR_CLIENT_NOT_EXIST));
				resJson.put("http_status_code", 401);
				result.put("data", resJson);
				return result;
			}

			List<Object> allowScopeList = (List<Object>) clientModel.getScopes();

			ClientVO clientInfo = clientModel.getClientInfo();

			if (clientInfo == null) {
				result = new JSONObject();
				resJson = new JSONObject();
				result.put("code", String.valueOf(MStatus.ERR_CLIENT_NOT_EXIST));
				result.put("message", "tokenIntrospect() invalid_client not found clientInfo");
				resJson.put("error", "invalid_client");
				resJson.put("error_description", "not found clientInfo");
				resJson.put("error_code", String.valueOf(MStatus.ERR_CLIENT_NOT_EXIST));
				resJson.put("http_status_code", 401);
				result.put("data", resJson);
				return result;
			}

			if (clientInfo.getEnabled().equals("0")) {
				result = new JSONObject();
				resJson = new JSONObject();
				result.put("code", String.valueOf(MStatus.ERR_CLIENT_DISABLED));
				result.put("message", "tokenIntrospect() invalid_grant disable client");
				resJson.put("error", "invalid_grant");
				resJson.put("error_description", "disable client");
				resJson.put("error_code", String.valueOf(MStatus.ERR_CLIENT_DISABLED));
				resJson.put("http_status_code", 401);
				result.put("data", resJson);
				return result;
			}

			if (authType.equals(MStatus.AUTHORIZATION_HEADER_TYPE_BASIC)) {
				if (!clientInfo.getSecret().equals(client_secret)) {
					result = new JSONObject();
					resJson = new JSONObject();
					result.put("code", String.valueOf(MStatus.ERR_MISMATCH_CLIENT_SECRET));
					result.put("message", "tokenIntrospect() invalid_grant Invalid client secret");
					resJson.put("error", "invalid_grant");
					resJson.put("error_description", "Invalid client secret");
					resJson.put("error_code", String.valueOf(MStatus.ERR_MISMATCH_CLIENT_SECRET));
					resJson.put("http_status_code", 401);
					result.put("data", resJson);
					return result;
				}
			}
			
			String issuer = OIDCUtil.generateBaseUrl(request);

			if (authType.equals(MStatus.AUTHORIZATION_HEADER_TYPE_BEARER)) {
				if (jwtBuilder.verifyJWT(accessToken) == false) {
					result = new JSONObject();
					resJson = new JSONObject();
					result.put("code", String.valueOf(MStatus.ERR_TOKEN_VERIFY_FAIL));
					result.put("message", "tokenIntrospect() invalid_grant verify fail accessToken");
					resJson.put("active", "false");
					resJson.put("msg", "failed verify token");
					resJson.put("http_status_code", 200);
					result.put("data", resJson);
					return result;
				}
				result = jwtBuilder.accessTokenValid(accessToken, client_id, issuer, allowScopeList, true);
				
				if (Integer.parseInt((String) result.get("code")) != MStatus.SUCCESS) {
					return result;
				}
			}

			if (jwtBuilder.verifyJWT(reqToken) == false) {
				result = new JSONObject();
				resJson = new JSONObject();
				result.put("code", String.valueOf(MStatus.ERR_TOKEN_VERIFY_FAIL));
				result.put("message", "tokenIntrospect() invalid_grant verify fail token");
				resJson.put("active", "false");
				resJson.put("msg", "failed verify token");
				resJson.put("http_status_code", 200);
				result.put("data", resJson);
				return result;
			}

			String tokenType = "";
			result = jwtBuilder.getTokenType(reqToken, tokenTypeHint, true);

			if (Integer.parseInt((String) result.get("code")) != MStatus.SUCCESS) {
				return result;
			}

			tokenType = (String) result.get("data");

			if (tokenType.equals(MStatus.ACCESS_TOKEN_TYPE)) {
				result = jwtBuilder.accessTokenValid(reqToken, client_id, issuer, allowScopeList, true);
			}
			else if (tokenType.equals(MStatus.ID_TOKEN_TYPE)) {
				result = jwtBuilder.idTokenValid(reqToken, client_id, issuer, allowScopeList, true);
			}
			else if (tokenType.equals(MStatus.REFRESH_TOKEN_TYPE)) {
				result = jwtBuilder.refreshTokenValid(reqToken, client_id, issuer, clientInfo.getRefreshTokenUse(), true);
			}
			else {
				result = new JSONObject();
				resJson = new JSONObject();
				result.put("code", String.valueOf(MStatus.ERR_UNKNOWN_TOKEN_TYPE));
				result.put("message", "tokenIntrospect() invalid_grant unknown token type");
				resJson.put("active", "false");
				resJson.put("msg", "unknown token type");
				resJson.put("http_status_code", 200);
				result.put("data", resJson);
				return result;
			}

			if (Integer.parseInt((String) result.get("code")) != MStatus.SUCCESS) {
				return result;
			}

			JSONObject sessionIds = (JSONObject) result.get("data");
			String rootAuthSessionId = (String) sessionIds.get("rootAuthSessionId");
			String subAuthSessionId = (String) sessionIds.get("subAuthSessionId");

			RootAuthSession rootAuthSession = null;
			SubAuthSession subAuthSession = null;

			rootAuthSession = OidcSessionManager.getInstance().getRootAuthSession(rootAuthSessionId);
			subAuthSession = rootAuthSession.getSubAuthSession(subAuthSessionId);

			String identityJwt = rootAuthSession.getIdentityJwt();

			if (Util.isEmpty(identityJwt)) {
				result = new JSONObject();
				resJson = new JSONObject();
				result.put("code", String.valueOf(MStatus.ERR_LOGIN_TOKEN_NOT_EXIST));
				result.put("message", "tokenIntrospect() invalid_grant not found login Token");
				resJson.put("active", "false");
				resJson.put("msg", "not found login Token");
				resJson.put("http_status_code", 200);
				result.put("data", resJson);
				return result;
			}

			boolean validSession = jwtBuilder.verifyJWT(identityJwt);

			if (validSession == false) {
				result = new JSONObject();
				resJson = new JSONObject();
				result.put("code", String.valueOf(MStatus.ERR_AUTH_SESSION_INVALID));
				result.put("message", "tokenIntrospect() invalid_grant auth session invalid");
				resJson.put("active", "false");
				resJson.put("msg", "auth session invalid");
				resJson.put("http_status_code", 200);
				result.put("data", resJson);
				return result;
			}

			if (!client_id.equals(subAuthSession.attributes.get("client_id"))) {
				result = new JSONObject();
				resJson = new JSONObject();
				result.put("code", String.valueOf(MStatus.ERR_MISMATCH_CLIENT_ID_CUR_SESSION));
				result.put("message", "tokenIntrospect() invalid_client not match client_id in session");
				resJson.put("error", "invalid_client");
				resJson.put("error_description", "not match client_id in session");
				resJson.put("error_code", String.valueOf(MStatus.ERR_MISMATCH_CLIENT_ID_CUR_SESSION));
				resJson.put("http_status_code", 401);
				result.put("data", resJson);
				return result;
			}

			resJson = new JSONObject();
			resJson.put("active", "true");
			result = new JSONObject();
			result.put("code", String.valueOf(MStatus.SUCCESS));
			result.put("message", "SUCCESS");
			result.put("data", resJson);
		}
		catch (Exception e) {
			result = new JSONObject();
			resJson = new JSONObject();
			result.put("code", String.valueOf(MStatus.ERR_SERVER_EXCEPTION));
			result.put("message", "refreshTokenGrant() Exception: " + e.getMessage());
			resJson.put("error", "server_error");
			resJson.put("error_description", "unexpected server error");
			resJson.put("error_code", String.valueOf(MStatus.ERR_SERVER_EXCEPTION));
			resJson.put("http_status_code", 500);
			result.put("data", resJson);
		}

		return result;
	}

	public JSONObject issueUserInfo(HttpServletRequest request)
	{
		JSONObject result = null;
		JSONObject resJson = null;

		try {
			String headerAuthorization = request.getHeader("Authorization");
			String access_token = "";
			String client_id = "";

			if (Util.isEmpty(headerAuthorization)) {
				result = new JSONObject();
				resJson = new JSONObject();
				result.put("code", String.valueOf(MStatus.ERR_AUTHORIZATION_HEADER_EMPTY));
				result.put("message", "issueUserInfo() invalid_client Authorization null");
				resJson.put("error", "invalid_client");
				resJson.put("error_description", "header Authorization null");
				resJson.put("http_status_code", 401);
				resJson.put("error_code", String.valueOf(MStatus.ERR_AUTHORIZATION_HEADER_EMPTY));
				result.put("data", resJson);
				return result;
			}

			String[] authorizationParse = headerAuthorization.split(" ");

			if (authorizationParse.length != 2) {
				result = new JSONObject();
				resJson = new JSONObject();
				result.put("code", String.valueOf(MStatus.ERR_AUTHORIZATION_HEADER_PARSE_FAIL));
				result.put("message", "issueUserInfo() invalid_client Authorization parse fail");
				resJson.put("error", "invalid_client");
				resJson.put("error_description", "Authorization parse fail");
				resJson.put("error_code", String.valueOf(MStatus.ERR_AUTHORIZATION_HEADER_PARSE_FAIL));
				resJson.put("http_status_code", 401);
				result.put("data", resJson);
				return result;
			}

			if (authorizationParse[0].equals(MStatus.AUTHORIZATION_HEADER_TYPE_BEARER)) {
				access_token = authorizationParse[1];
			} else {
				result = new JSONObject();
				resJson = new JSONObject();
				result.put("code", String.valueOf(MStatus.ERR_MISMATCH_AUTHORIZATION_HEADER_TYPE));
				result.put("message", "issueUserInfo() invalid_client not supported this type");
				resJson.put("error", "invalid_client");
				resJson.put("error_description", "not supported this type");
				resJson.put("error_code", String.valueOf(MStatus.ERR_MISMATCH_AUTHORIZATION_HEADER_TYPE));
				resJson.put("http_status_code", 401);
				result.put("data", resJson);
				return result;
			}

			if (Util.isEmpty(access_token)) {
				result = new JSONObject();
				resJson = new JSONObject();
				result.put("code", String.valueOf(MStatus.ERR_REQ_PARAMETER_EMPTY));
				result.put("message", "issueUserInfo() invalid_request null parameter access_token");
				resJson.put("error", "invalid_request");
				resJson.put("error_description", "null parameter access_token");
				resJson.put("error_code", String.valueOf(MStatus.ERR_REQ_PARAMETER_EMPTY));
				resJson.put("http_status_code", 400);
				result.put("data", resJson);
				return result;
			}
			
			JWTBuilder jwtBuilder = JWTBuilder.getInstance();
			
			String accessTokenStr = jwtBuilder.getTokenString(access_token);

			if (Util.isEmpty(accessTokenStr)) {
				result = new JSONObject();
				resJson = new JSONObject();
				result.put("code", String.valueOf(MStatus.ERR_ACCESS_TOKEN_ERROR_FORMAT));
				result.put("message", "issueUserInfo() invalid_grant error format access_token");

				resJson.put("error", "invalid_grant");
				resJson.put("error_description", "error format access_token");
				resJson.put("error_code", String.valueOf(MStatus.ERR_ACCESS_TOKEN_ERROR_FORMAT));
				resJson.put("http_status_code", 400);

				result.put("data", resJson);
				return result;
			} else {
				JSONParser parser = new JSONParser();
				JSONObject accessTokenJson = (JSONObject) parser.parse(accessTokenStr);
				client_id = (String) accessTokenJson.get("aud");
			}

			ClientRepository clientRepository = ClientRepository.getInstance();
			ClientModel clientModel = clientRepository.getClient(client_id);

			if (clientModel == null) {
				result = new JSONObject();
				resJson = new JSONObject();
				result.put("code", String.valueOf(MStatus.ERR_CLIENT_NOT_EXIST));
				result.put("message", "issueUserInfo() invalid_client not found clientModel");
				resJson.put("error", "invalid_client");
				resJson.put("error_description", "not found clientModel");
				resJson.put("error_code", String.valueOf(MStatus.ERR_CLIENT_NOT_EXIST));
				resJson.put("http_status_code", 401);
				result.put("data", resJson);
				return result;
			}

			List<Object> allowScopeList = (List<Object>) clientModel.getScopes();

			ClientVO clientInfo = clientModel.getClientInfo();

			if (clientInfo == null) {
				result = new JSONObject();
				resJson = new JSONObject();
				result.put("code", String.valueOf(MStatus.ERR_CLIENT_NOT_EXIST));
				result.put("message", "issueUserInfo() invalid_client not found clientInfo");
				resJson.put("error", "invalid_client");
				resJson.put("error_description", "not found clientInfo");
				resJson.put("error_code", String.valueOf(MStatus.ERR_CLIENT_NOT_EXIST));
				resJson.put("http_status_code", 401);
				result.put("data", resJson);
				return result;
			}

			if (clientInfo.getEnabled().equals("0")) {
				result = new JSONObject();
				resJson = new JSONObject();
				result.put("code", String.valueOf(MStatus.ERR_CLIENT_DISABLED));
				result.put("message", "issueUserInfo() invalid_grant disable client");
				resJson.put("error", "invalid_grant");
				resJson.put("error_description", "disable client");
				resJson.put("error_code", String.valueOf(MStatus.ERR_CLIENT_DISABLED));
				resJson.put("http_status_code", 401);
				result.put("data", resJson);
				return result;
			}

			if (jwtBuilder.verifyJWT(access_token) == false) {
				result = new JSONObject();
				resJson = new JSONObject();
				result.put("code", String.valueOf(MStatus.ERR_TOKEN_VERIFY_FAIL));
				result.put("message", "issueUserInfo() invalid_grant verify fail access_token");
				resJson.put("error", "invalid_grant");
				resJson.put("error_description", "verify fail access_token");
				resJson.put("error_code", String.valueOf(MStatus.ERR_TOKEN_VERIFY_FAIL));
				resJson.put("http_status_code", 400);
				result.put("data", resJson);
				return result;
			}

			String issuer = OIDCUtil.generateBaseUrl(request);
			result = jwtBuilder.accessTokenValid(access_token, client_id, issuer, allowScopeList, false);

			if (Integer.parseInt((String) result.get("code")) != MStatus.SUCCESS) {
				return result;
			}

			JSONObject sessionIds = (JSONObject) result.get("data");
			String rootAuthSessionId = (String) sessionIds.get("rootAuthSessionId");
			String subAuthSessionId = (String) sessionIds.get("subAuthSessionId");

			RootAuthSession rootAuthSession = null;
			SubAuthSession subAuthSession = null;

			rootAuthSession = OidcSessionManager.getInstance().getRootAuthSession(rootAuthSessionId);
			subAuthSession = rootAuthSession.getSubAuthSession(subAuthSessionId);

			if (!client_id.equals(subAuthSession.attributes.get("client_id"))) {
				result = new JSONObject();
				resJson = new JSONObject();
				result.put("code", String.valueOf(MStatus.ERR_MISMATCH_CLIENT_ID_CUR_SESSION));
				result.put("message", "issueUserInfo() invalid_client not match client_id in session");
				resJson.put("error", "invalid_client");
				resJson.put("error_description", "not match client_id in session");
				resJson.put("error_code", String.valueOf(MStatus.ERR_MISMATCH_CLIENT_ID_CUR_SESSION));
				resJson.put("http_status_code", 401);
				result.put("data", resJson);
				return result;
			}

			String identityJwt = rootAuthSession.getIdentityJwt();

			if (Util.isEmpty(identityJwt)) {
				result = new JSONObject();
				resJson = new JSONObject();
				result.put("code", String.valueOf(MStatus.ERR_LOGIN_TOKEN_NOT_EXIST));
				result.put("message", "issueUserInfo() invalid_grant not found login Token");
				resJson.put("error", "invalid_grant");
				resJson.put("error_description", "not found login Token");
				resJson.put("error_code", String.valueOf(MStatus.ERR_LOGIN_TOKEN_NOT_EXIST));
				resJson.put("http_status_code", 400);
				result.put("data", resJson);
				return result;
			}

			boolean validSession = jwtBuilder.verifyJWT(identityJwt);

			if (validSession == false) {
				result = new JSONObject();
				resJson = new JSONObject();
				result.put("code", String.valueOf(MStatus.ERR_AUTH_SESSION_INVALID));
				result.put("message", "issueUserInfo() invalid_grant auth session invalid");
				resJson.put("error", "invalid_grant");
				resJson.put("error_description", "auth session invalid");
				resJson.put("error_code", String.valueOf(MStatus.ERR_AUTH_SESSION_INVALID));
				resJson.put("http_status_code", 400);
				result.put("data", resJson);
				return result;
			}

			String identityTokenStr = jwtBuilder.getTokenString(identityJwt);

			if (Util.isEmpty(identityTokenStr)) {
				result = new JSONObject();
				resJson = new JSONObject();
				result.put("code", String.valueOf(MStatus.ERR_LOGIN_TOKEN_ERROR_FORMAT));
				result.put("message", "issueUserInfo() invalid_grant error format login Token");
				resJson.put("error", "invalid_grant");
				resJson.put("error_description", "error format login Token");
				resJson.put("error_code", String.valueOf(MStatus.ERR_LOGIN_TOKEN_ERROR_FORMAT));
				resJson.put("http_status_code", 400);
				result.put("data", resJson);
				return result;
			}

			resJson = new JSONObject();
			JSONParser parser = new JSONParser();
			JSONObject identityTokenJson = (JSONObject) parser.parse(identityTokenStr);
			String sub = (String) identityTokenJson.get("sub");

			// scope
			String scope = subAuthSession.attributes.get("scope");
			List<String> scopeList = new ArrayList<String>(Arrays.asList(scope.split("\\+")));
			
			if (scopeList.contains("profile")) {
				scopeList.remove("profile");
				scopeList.add("name");
				scopeList.add("phone");
			}
			
			if (scopeList.contains("openid")) {
				scopeList.remove("openid");
				
			} 

			String[] scopes = scopeList.toArray(new String[scopeList.size()]);
			resJson.put("sub", sub);

			if (scopes != null && scopes.length > 0) {
				UserController userApi = new UserController();
				result = userApi.getOidcUserInfo(sub, scopes);
				
				if (Integer.parseInt((String) result.get("code")) != MStatus.SUCCESS) {
					return result;
				}
				Map<String, String> resultMap = (Map<String, String>) result.get("data");
				
				if (resultMap != null) {
					for (Iterator iterator = resultMap.keySet().iterator(); iterator.hasNext();) {
						String key = (String) iterator.next();
						String value = (String) resultMap.get(key);
						resJson.put(key.toLowerCase(), value);
					}
				}
			}

			result = new JSONObject();
			result.put("code", String.valueOf(MStatus.SUCCESS));
			result.put("message", "SUCCESS");
			result.put("data", resJson);
		}
		catch (Exception e) {
			result = new JSONObject();
			resJson = new JSONObject();
			result.put("code", String.valueOf(MStatus.ERR_SERVER_EXCEPTION));
			result.put("message", "issueUserInfo() Exception: " + e.getMessage());
			resJson.put("error", "server_error");
			resJson.put("error_description", "unexpected server error");
			resJson.put("error_code", String.valueOf(MStatus.ERR_SERVER_EXCEPTION));
			resJson.put("http_status_code", 500);
			result.put("data", resJson);
		}

		return result;
	}

	public RootAuthSession getRootAuthSessionByEvent(String rootAuthSessionId)
	{
		SyncMonitor.startMonitor();
		SyncMonitor.requestRootAuthSessionEvent(rootAuthSessionId);

		int waitCount = 3;

		while (waitCount != 0) {
			try {
				Thread.sleep(200);
			}
			catch (InterruptedException e) {
				e.printStackTrace();
				return null;
			}

			RootAuthSession rootAuthSession = OidcSessionManager.getInstance().getRootAuthSession(rootAuthSessionId);

			if (rootAuthSession == null) {
				waitCount--;
				continue;
			}
			else {
				return rootAuthSession;
			}
		}

		return null;
	}

	public JSONObject getJwksInfo()
	{
		JSONObject result = null;
		JSONObject resJson = null;

		try {			
			JSONObject signCert = new JSONObject();
			JSONArray jwk = new JSONArray();

			Credential idpCert = CredentialRepository.getCredential(SSOConfig.getInstance().getServerName(), MStatus.SIGN_CERT);
			
			byte[] certBytes = ((BasicX509Credential) idpCert).getEntityCertificate().getEncoded();

			String x509CertStr = SSOCryptoApi.encode64(certBytes);
			
			List<String> x5c = new ArrayList();
			x5c.add(x509CertStr);

			signCert.put("kty", "RSA");
			signCert.put("alg", "RS256");
			signCert.put("use", "sig");
			signCert.put("x5c", x5c);
			
			jwk.add(signCert);
			
			resJson = new JSONObject();
			resJson.put("keys",jwk);			

			result = new JSONObject();
			result.put("code", String.valueOf(MStatus.SUCCESS));
			result.put("message", "SUCCESS");
			result.put("data", resJson);
		}
		catch (Exception e) {
			result = new JSONObject();
			resJson = new JSONObject();
			result.put("code", String.valueOf(MStatus.ERR_SERVER_EXCEPTION));
			result.put("message", "getJwksInfo() Exception: " + e.getMessage());
			resJson.put("error", "server_error");
			resJson.put("error_description", "unexpected server error");
			resJson.put("error_code", String.valueOf(MStatus.ERR_SERVER_EXCEPTION));
			resJson.put("http_status_code", 500);
			result.put("data", resJson);
		}
		return result;
	}

	public JSONObject getOidcCfg(HttpServletRequest request)
	{
		JSONObject result = null;
		JSONObject resJson = null;

		SSOConfig config = SSOConfig.getInstance();

		if (config.getAuthStatus() != 0) {
			log.error("### 인증 비활성화 상태");
			resJson = new JSONObject();
			resJson.put("error", "server_error");
			resJson.put("error_description", "Authentication disabled status");
			resJson.put("error_code", String.valueOf(MStatus.AUTH_NON_ACTIVE));
			resJson.put("http_status_code", 400);
			result = new JSONObject();
			result.put("code", String.valueOf(MStatus.AUTH_NON_ACTIVE));
			result.put("message", "인증 비활성화 상태");
			result.put("data", resJson);
			return result;
		}

		try {
			String baseUrl = OIDCUtil.generateBaseUrl(request);
			String authorization_endpoint = baseUrl + config.getString("oidc.endpoint.auth", "/oidc/auth");
			String token_endpoint = baseUrl + config.getString("oidc.endpoint.token", "/oidc/token");
			String introspection_endpoint = baseUrl + config.getString("oidc.endpoint.introspect", "/oidc/introspect");
			String userinfo_endpoint = baseUrl + config.getString("oidc.endpoint.userinfo", "/oidc/userinfo");
			String cert_endpoint = baseUrl + config.getString("oidc.endpoint.cert", "/oidc/cert");

			List<String> idTokenSigAlgSup = new ArrayList();
			List<String> responseTypesSup = new ArrayList();
			List<String> subjectTypesSup = new ArrayList();
			idTokenSigAlgSup.add("RS256");
			responseTypesSup.add("code");
			subjectTypesSup.add("public");

			resJson = new JSONObject();

			resJson.put("issuer", baseUrl);
			resJson.put("authorization_endpoint", authorization_endpoint);
			resJson.put("token_endpoint", token_endpoint);
			resJson.put("introspection_endpoint", introspection_endpoint);
			resJson.put("userinfo_endpoint", userinfo_endpoint);
			resJson.put("jwks_uri", cert_endpoint);
			resJson.put("response_types_supported", responseTypesSup);
			resJson.put("subject_types_supported", subjectTypesSup);
			resJson.put("id_token_signing_alg_values_supported", idTokenSigAlgSup);

			result = new JSONObject();
			result.put("code", String.valueOf(MStatus.SUCCESS));
			result.put("message", "SUCCESS");
			result.put("data", resJson);
		}
		catch (Exception e) {
			result = new JSONObject();
			resJson = new JSONObject();
			result.put("code", String.valueOf(MStatus.ERR_SERVER_EXCEPTION));
			result.put("message", "getOidcCfg() Exception: " + e.getMessage());
			resJson.put("error", "server_error");
			resJson.put("error_description", "unexpected server error");
			resJson.put("error_code", String.valueOf(MStatus.ERR_SERVER_EXCEPTION));
			resJson.put("http_status_code", 500);
			result.put("data", resJson);
		}
		return result;
	}
}