package com.dreamsecurity.sso.server.api.user;

import java.util.Date;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

import com.dreamsecurity.sso.lib.dss.s2.core.AuthnContext;
import com.dreamsecurity.sso.lib.jsn.JSONObject;
import com.dreamsecurity.sso.lib.jtm.DateTime;
import com.dreamsecurity.sso.lib.jtm.DateTimeZone;
import com.dreamsecurity.sso.lib.slf.Logger;
import com.dreamsecurity.sso.lib.slf.LoggerFactory;
import com.dreamsecurity.sso.server.api.UserApi;
import com.dreamsecurity.sso.server.api.user.service.UserService;
import com.dreamsecurity.sso.server.common.MStatus;
import com.dreamsecurity.sso.server.config.SSOConfig;
import com.dreamsecurity.sso.server.crypto.SSOCryptoApi;
import com.dreamsecurity.sso.server.jwt.JWTBuilder;
import com.dreamsecurity.sso.server.provider.CommonProvider;
import com.dreamsecurity.sso.server.session.AuthSession;
import com.dreamsecurity.sso.server.session.RootAuthSession;
import com.dreamsecurity.sso.server.session.SessionManager;
import com.dreamsecurity.sso.server.token.IdentityToken;
import com.dreamsecurity.sso.server.token.SSOToken;
import com.dreamsecurity.sso.server.util.OIDCUtil;
import com.dreamsecurity.sso.server.util.Util;

public class UserController implements UserApi
{
	private static Logger log = LoggerFactory.getLogger(UserController.class);

	public static int RET_SUCCESS = 0;
	public static int RET_FAIL = 1;
	public static int RET_EMPTY = 2;

	private UserService service = null;

	public UserController()
	{
		service = new UserService();
	}

	public int connectTest()
	{
		return service.connectTest();
	}

	public JSONObject login(HttpServletRequest request)
	{
		JSONObject result = null;

		try {
			HttpSession session = request.getSession(false);

			String id = Util.getAttribute(request, "id");
			String pw = Util.getAttribute(request, "pw");
			String spname = Util.getAttribute(request, "spname");
			String logintype = Util.getAttribute(request, "logintype");
			String applcode = Util.getAttribute(request, "applcode");
			String browser = Util.getAttribute(request, "loginBr");

			if (Util.isEmpty(browser)) {
				browser = "NN";
			}

			String ip = Util.getClientIP(request);

//			log.debug("request id        : {}", id);
//			log.debug("request spname    : {}", spname);
//			log.debug("request logintype : {}", logintype);
//			log.debug("request applcode  : {}", applcode);
//			log.debug("request browser   : {}", browser);
//			log.debug("request ip        : {}", ip);

			result = service.login(id, pw, ip, browser, spname, logintype);

			if (Integer.parseInt((String) result.get("code")) != MStatus.SUCCESS) {
				return result;
			}

			SSOToken ssoToken = new SSOToken((StringBuilder) result.get("data"));

			if (ssoToken == null) {
				result.put("code", String.valueOf(MStatus.AUTH_TOKEN_NULL));
				result.put("message", "Token String Invalid");
				result.put("data", "");
				return result;
			}

			// encrypt Token
			int returnSetToken = SSOCryptoApi.getInstance().encryptToken(session, id, ip, spname, (StringBuilder) result.get("data"));

			if (returnSetToken != 0) {
				service.setAuditInfo(SSOConfig.getInstance().getServerName(), "BA", "1", id + ", " + ip);

				result.put("code", String.valueOf(MStatus.AUTH_TOKEN_ENCRYPT));
				result.put("message", "Token Encrypt Failure");
				result.put("data", "");
				return result;
			}

			service.setAuditInfo(SSOConfig.getInstance().getServerName(), "BA", "0", id + ", " + ip);

			result.put("data", "");
		}
		catch (Throwable e) {
			log.error("### login() Throwable: {}", e.getMessage());

			result.put("code", String.valueOf(MStatus.ETC_AUTH_FAIL));
			result.put("message", "login() Throwable: " + e.getMessage());
			result.put("data", "");
			return result;
		}

		return result;
	}

	public JSONObject login(HttpServletRequest request, RootAuthSession rootAuthSession)
	{
		JSONObject result = null;

		try {
			HttpSession session = request.getSession(false);

			String id = Util.getAttribute(request, "id");
			String pw = Util.getAttribute(request, "pw");
			String spname = Util.getAttribute(request, "spname");
			String logintype = Util.getAttribute(request, "logintype");
			String applcode = Util.getAttribute(request, "applcode");
			String browser = Util.getAttribute(request, "loginBr");

			if (Util.isEmpty(browser)) {
				browser = "NN";
			}

			String ip = Util.getClientIP(request);

//			log.debug("request id        : {}", id);
//			log.debug("request spname    : {}", spname);
//			log.debug("request logintype : {}", logintype);
//			log.debug("request applcode  : {}", applcode);
//			log.debug("request browser   : {}", browser);
//			log.debug("request ip        : {}", ip);

			result = service.login(id, pw, ip, browser, spname, logintype);

			if (Integer.parseInt((String) result.get("code")) != MStatus.SUCCESS) {
				return result;
			}

			SSOToken ssoToken = new SSOToken((StringBuilder) result.get("data"));

			if (ssoToken == null) {
				result.put("code", String.valueOf(MStatus.AUTH_TOKEN_NULL));
				result.put("message", "Token String Invalid");
				result.put("data", "");
				return result;
			}

			// encrypt Token
			int returnSetToken = SSOCryptoApi.getInstance().encryptToken(session, id, ip, spname, (StringBuilder) result.get("data"));

			if (returnSetToken != 0) {
				service.setAuditInfo(SSOConfig.getInstance().getServerName(), "BA", "1", id + ", " + ip);

				result.put("code", String.valueOf(MStatus.AUTH_TOKEN_ENCRYPT));
				result.put("message", "Token Encrypt Failure");
				result.put("data", "");
				return result;
			}

			String issuer = OIDCUtil.generateBaseUrl(request);
			Date curDate = new Date(System.currentTimeMillis());
			long auth_time = (curDate.getTime() / 1000);
			rootAuthSession.attributes.put("auth_time", Long.toString(auth_time));
			JWTBuilder jwtBuilder = JWTBuilder.getInstance();
			IdentityToken identityToken = new IdentityToken(ssoToken.getProperty("ID"), rootAuthSession.getSessionId(), ssoToken.getProperty("NAME"), ssoToken.getProperty("EMAIL"), issuer, curDate);
			String identityTokenStr = identityToken.tokenToJsonString();
			String identityJwt = jwtBuilder.generateJWT(identityTokenStr);
			rootAuthSession.setIdentityJwt(identityJwt);

			service.setAuditInfo(SSOConfig.getInstance().getServerName(), "BA", "0", id + ", " + ip);
			result.put("data", "");
		}
		catch (Throwable e) {
			log.error("### login() Throwable: {}", e.getMessage());

			result.put("code", String.valueOf(MStatus.ETC_AUTH_FAIL));
			result.put("message", "login() Throwable: " + e.getMessage());
			result.put("data", "");
			return result;
		}

		return result;
	}

	public JSONObject loginCert(HttpServletRequest request)
	{
		JSONObject result = null;

		try {
			HttpSession session = request.getSession(false);

			String signedData = Util.getAttribute(request, "signed");
			String spname = Util.getAttribute(request, "spname");
			String logintype = Util.getAttribute(request, "logintype");
			String applcode = Util.getAttribute(request, "applcode");
			String browser = Util.getAttribute(request, "loginBr");

			if (Util.isEmpty(browser)) {
				browser = "NN";
			}

			String ip = Util.getClientIP(request);

//			log.debug("request signed    : {}", signed);
//			log.debug("request spname    : {}", spname);
//			log.debug("request logintype : {}", logintype);
//			log.debug("request applcode  : {}", applcode);
//			log.debug("request browser   : {}", browser);
//			log.debug("request ip        : {}", ip);

			result = service.loginCert(signedData, ip, browser, spname, logintype);

			if (Integer.parseInt((String) result.get("code")) != MStatus.SUCCESS) {
				return result;
			}

			SSOToken ssoToken = new SSOToken((StringBuilder) result.get("data"));

			if (ssoToken == null) {
				result.put("code", String.valueOf(MStatus.AUTH_TOKEN_NULL));
				result.put("message", "Token String Invalid");
				result.put("data", "");
				return result;
			}

			String id = ssoToken.getId();

			// encrypt Token
			int returnSetToken = SSOCryptoApi.getInstance().encryptToken(session, id, ip, spname, (StringBuilder) result.get("data"));

			if (returnSetToken != 0) {
				service.setAuditInfo(SSOConfig.getInstance().getServerName(), "BA", "1", id + ", " + ip);

				result.put("code", String.valueOf(MStatus.AUTH_TOKEN_ENCRYPT));
				result.put("message", "Token Encrypt Failure");
				result.put("data", "");
				return result;
			}

			service.setAuditInfo(SSOConfig.getInstance().getServerName(), "BA", "0", id + ", " + ip);

			result.put("data", "");
		}
		catch (Throwable e) {
			log.error("### loginCert() Throwable: {}", e.getMessage());

			result.put("code", String.valueOf(MStatus.ETC_AUTH_FAIL));
			result.put("message", "loginCert() Throwable: " + e.getMessage());
			result.put("data", "");
			return result;
		}

		return result;
	}

	public JSONObject smartLogin(HttpServletRequest request)
	{
		JSONObject result = null;

		try {
			HttpSession session = request.getSession(false);

			String id = Util.getAttribute(request, "id");
			String pw = Util.getAttribute(request, "pw");
			String device = Util.getAttribute(request, "device");
			String spname = Util.getAttribute(request, "spname");
			String logintype = Util.getAttribute(request, "logintype");
			String applcode = Util.getAttribute(request, "applcode");
			String br = Util.getAttribute(request, "br");

//			log.debug("request id        : {}", id);
//			log.debug("request device    : {}", device);
//			log.debug("request spname    : {}", spname);
//			log.debug("request logintype : {}", logintype);
//			log.debug("request applcode  : {}", applcode);

			result = service.smartLogin(id, pw, device, br, spname, logintype);

			if (Integer.parseInt((String) result.get("code")) != MStatus.SUCCESS) {
				return result;
			}

			if (br.equals("MB")) {
				SSOToken ssoToken = new SSOToken((StringBuilder) result.get("data"));

				if (ssoToken == null) {
					result.put("code", String.valueOf(MStatus.AUTH_TOKEN_NULL));
					result.put("message", "Token String Invalid");
					result.put("data", "");
					return result;
				}

				// encrypt Token
				int returnSetToken = SSOCryptoApi.getInstance().encryptToken(request, id, device, spname, (StringBuilder) result.get("data"));

				if (returnSetToken != 0) {
					service.setAuditInfo(SSOConfig.getInstance().getServerName(), "BA", "1", id + ", " + device);
	
					result.put("code", String.valueOf(MStatus.AUTH_TOKEN_ENCRYPT));
					result.put("message", "Token Encrypt Failure");
					result.put("data", "");
					return result;
				}

				service.setAuditInfo(SSOConfig.getInstance().getServerName(), "BA", "0", id + ", " + device);

				result.put("data", "");
			}
			else {
				request.setAttribute(CommonProvider.SESSION_TOKEN, (StringBuilder) result.get("data"));

				service.setAuditInfo(SSOConfig.getInstance().getServerName(), "BA", "0", id + ", " + device);
			}
		}
		catch (Throwable e) {
			log.error("### login() Throwable: {}", e.getMessage());

			result.put("code", String.valueOf(MStatus.ETC_AUTH_FAIL));
			result.put("message", "login() Throwable: " + e.getMessage());
			result.put("data", "");
			return result;
		}

		return result;
	}

	public JSONObject smartLogin2FA(HttpServletRequest request)
	{
		JSONObject result = null;

		try {
			String id = Util.getAttribute(request, "id");
			String pw = Util.getAttribute(request, "pw");
			String device = Util.getAttribute(request, "device");
			String spname = Util.getAttribute(request, "spname");
			String logintype = Util.getAttribute(request, "logintype");
			String br = Util.getAttribute(request, "br");
			String authstep = Util.getAttribute(request, "authstep");
			String mfatype = Util.getAttribute(request, "mfatype");

			result = service.smartLogin2FA(id, pw, device, br, spname, logintype, authstep, mfatype);

			if (Integer.parseInt((String) result.get("code")) != MStatus.SUCCESS) {
				return result;
			}

			if (authstep.equals("2nd")) {
				request.setAttribute(CommonProvider.SESSION_TOKEN, (StringBuilder) result.get("data"));
				service.setAuditInfo(SSOConfig.getInstance().getServerName(), "BA", "0", id + ", " + device);
			}

			result.put("data", "");
		}
		catch (Throwable e) {
			log.error("### smartLogin2FA() Throwable: {}", e.getMessage());

			result.put("code", String.valueOf(MStatus.ETC_AUTH_FAIL));
			result.put("message", "smartLogin2FA() Throwable: " + e.getMessage());
			result.put("data", "");
			return result;
		}

		return result;
	}

	public JSONObject oidcLogin(HttpServletRequest request, RootAuthSession rootAuthSession)
	{
		JSONObject result = null;

		try {
			HttpSession session = request.getSession(false);
			String id = Util.getAttribute(request, "id");
			String pw = Util.getAttribute(request, "pw");
			String spname = Util.getAttribute(request, "spname");
			String logintype = Util.getAttribute(request, "logintype");
			String browser = Util.getAttribute(request, "loginBr");

			if (Util.isEmpty(browser)) {
				browser = "NN";
			}

			String ip = Util.getClientIP(request);

			result = service.oidcLogin(id, pw, ip, browser, spname, logintype);
			
			if (Integer.parseInt((String) result.get("code")) != MStatus.SUCCESS) {
				return result;
			}

			SSOToken ssoToken = new SSOToken((StringBuilder) result.get("data"));

			if (ssoToken == null) {
				result.put("code", String.valueOf(MStatus.AUTH_TOKEN_NULL));
				result.put("message", "Token String Invalid");
				result.put("data", "");
				return result;
			}

			// encrypt Token
			int returnSetToken = SSOCryptoApi.getInstance().encryptToken(session, id, ip, spname, (StringBuilder) result.get("data"));

			if (returnSetToken != 0) {
				service.setAuditInfo(SSOConfig.getInstance().getServerName(), "BA", "1", id + ", " + ip);

				result.put("code", String.valueOf(MStatus.AUTH_TOKEN_ENCRYPT));
				result.put("message", "Token Encrypt Failure");
				result.put("data", "");
				return result;
			}
			
			String issuer = OIDCUtil.generateBaseUrl(request);
			Date curDate = new Date(System.currentTimeMillis());
			long auth_time = (curDate.getTime() / 1000);
			rootAuthSession.attributes.put("auth_time", Long.toString(auth_time));
			JWTBuilder jwtBuilder = JWTBuilder.getInstance();
			IdentityToken identityToken = new IdentityToken(ssoToken.getProperty("ID"), rootAuthSession.getSessionId(), ssoToken.getProperty("NAME"), ssoToken.getProperty("EMAIL"), issuer, curDate);
			String identityTokenStr = identityToken.tokenToJsonString();
			String identityJwt = jwtBuilder.generateJWT(identityTokenStr);
			rootAuthSession.setIdentityJwt(identityJwt);

			AuthSession authSession = SessionManager.getInstance().getSession(ssoToken.getProperty("ID"));
			authSession.addRemoteSessionByOidc(ssoToken.getProperty("ID"), spname, new DateTime(DateTimeZone.UTC), AuthnContext.PASSWORD_AUTHN_CTX, rootAuthSession.getSessionId());

			// 연계정보: 연계 시 사용
			session.setAttribute("AuthSession", SessionManager.getInstance().getSession(ssoToken.getId()));

			service.setAuditInfo(SSOConfig.getInstance().getServerName(), "BA", "0", id + ", " + ip);
			result.put("data", "");
		}
		catch (Throwable e) {
			log.error("### oidcLogin() Throwable: {}", e.getMessage());
			result = new JSONObject();
			result.put("code", String.valueOf(MStatus.ERR_OIDC_LOGIN_FAIL));
			result.put("message", "oidcLogin() Throwable: " + e.getMessage());
			result.put("data", "");
		}

		return result;
	}

	public void clearLoginIP(String userId, String userIp, String userBr)
	{
		service.clearLoginIP(userId, userIp, userBr);
	}

	public void clearIpInfo(String userId, String userIp, String userBr)
	{
		service.clearIpInfo(userId, userIp, userBr);
	}

	public void setConnectLog(String userId, String userIp, String userBr, String spName)
	{
		service.setConnectLog(userId, userIp, userBr, spName);
	}

	public void setLogoutLog(String userId, String userIp, String userBr, String loginType, String spName)
	{
		service.setLogoutLog(userId, userIp, userBr, loginType, spName);
	}

	public String setUserPwd(String id, String curPwd, String newPwd)
	{
		String pString = "";

		try {
			int cnt = service.setUserPwd(id, curPwd, newPwd);

			if (cnt > 0) {
				pString = "{\"page\":1,\"total\":1,\"records\":1,\"rows\":[{\"resultstatus\":1,\"resultdata\":\"\"}]}";
			}
			else {
				pString = "{\"page\":1,\"total\":1,\"records\":1,\"rows\":[{\"resultstatus\":-1,\"resultdata\":\"\"}]}";
			}
		}
		catch (Exception e) {
			pString = "Error : 비밀번호 변경 오류";
		}

		return pString;
	}

	public String setUserInfo(String encData)
	{
		JSONObject result = null;

		if (Util.isEmpty(encData)) {
			result = new JSONObject();
			result.put("code", String.valueOf(MStatus.API_EMPTY_DATA));
			result.put("message", "Empty Data");
			result.put("data", "");
			return result.toJSONString();
		}

		try {
			JSONObject jsonData = SSOCryptoApi.getInstance().decryptJsonObject(encData);

			String cmd = (String) jsonData.get("cmd");

			if (Util.isEmpty(cmd)) {
				result = new JSONObject();
				result.put("code", String.valueOf(MStatus.API_EMPTY_COMMAND));
				result.put("message", "Empty Command");
				result.put("data", "");
			}
			else if (cmd.equals("checkfirst")) {
				String id = (String) jsonData.get("id");

				if (Util.isEmpty(id)) {
					result = new JSONObject();
					result.put("code", String.valueOf(MStatus.API_EMPTY_COMMAND_DATA));
					result.put("message", "Empty Command Data");
					result.put("data", "");
				}
				else {
					result = service.checkFirstLogin(id);
				}
			}
			else if (cmd.equals("initpw")) {
				String id = (String) jsonData.get("id");
				String newPw = (String) jsonData.get("npw");

				if (Util.isEmpty(id) || Util.isEmpty(newPw)) {
					result = new JSONObject();
					result.put("code", String.valueOf(MStatus.API_EMPTY_COMMAND_DATA));
					result.put("message", "Empty Command Data");
					result.put("data", "");
				}
				else {
					result = service.setInitPw(id, newPw);
				}
			}
			else if (cmd.equals("changepw")) {
				String id = (String) jsonData.get("id");
				String curPw = (String) jsonData.get("cpw");
				String newPw = (String) jsonData.get("npw");

				if (Util.isEmpty(id) || Util.isEmpty(curPw) || Util.isEmpty(newPw)) {
					result = new JSONObject();
					result.put("code", String.valueOf(MStatus.API_EMPTY_COMMAND_DATA));
					result.put("message", "Empty Command Data");
					result.put("data", "");
				}
				else {
					result = service.setChangePw(id, curPw, newPw);
				}
			}
			else if (cmd.equals("unlockuser")) {
				String id = (String) jsonData.get("id");

				if (Util.isEmpty(id)) {
					result = new JSONObject();
					result.put("code", String.valueOf(MStatus.API_EMPTY_COMMAND_DATA));
					result.put("message", "Empty Command Data");
					result.put("data", "");
				}
				else {
					result = service.setUnlockUser(id);
				}
			}
			else if (cmd.equals("checkpw")) {
				String id = (String) jsonData.get("id");
				String pw = (String) jsonData.get("pw");

				if (Util.isEmpty(id) || Util.isEmpty(pw)) {
					result = new JSONObject();
					result.put("code", String.valueOf(MStatus.API_EMPTY_COMMAND_DATA));
					result.put("message", "Empty Command Data");
					result.put("data", "");
				}
				else {
					result = service.checkPw(id, pw);
				}
			}
			else {
				result = new JSONObject();
				result.put("code", String.valueOf(MStatus.API_INVALID_COMMAND));
				result.put("message", "Invalid Command: " + cmd);
				result.put("data", "");
			}
		}
		catch (Exception e) {
			log.error("### setUserInfo() Exception: {}", e.getMessage());

			result = new JSONObject();
			result.put("code", String.valueOf(MStatus.API_EXCEPTION));
			result.put("message", "setUserInfo() Exception: " + e.getMessage());
			result.put("data", "");
		}

		return result.toJSONString();
	}

	public String getCSLoginTime(String id)
	{
		return service.getCSLoginTime(id);
	}

	public void setCSLoginTime(String id)
	{
		service.setCSLoginTime(id);
	}

	public void clearCSLoginTime(String id, String ip)
	{
		service.clearCSLoginTime(id, ip);
	}

	public JSONObject getOidcUserInfo(String id, String[] scopeList)
	{
		JSONObject result = null;
		JSONObject resJson = null;

		try {
			Map<String, String> resultMap = service.getOidcUserInfo(id, scopeList);

			if (resultMap == null || resultMap.size() == 0) {
				result = new JSONObject();
				resJson = new JSONObject();
				result.put("code", String.valueOf(MStatus.ERR_USER_NOT_EXIST));
				result.put("message", "getOidcUserInfo() invalid_client not found userInfo");
				resJson.put("error", "invalid_client");
				resJson.put("error_description", "not found userInfo");
				resJson.put("http_status_code", 401);
				result.put("data", resJson);
				return result;
			}

			result = new JSONObject();
			result.put("code", String.valueOf(MStatus.SUCCESS));
			result.put("message", "SUCCESS");
			result.put("data", resultMap);
		}
		catch (Throwable e) {
			log.error("### getOidcUserInfo() Throwable: {}", e.getMessage());
			result = new JSONObject();
			resJson = new JSONObject();
			result.put("code", String.valueOf(MStatus.ERR_SERVER_EXCEPTION));
			result.put("message", "getUserInfo() Exception: " + e.getMessage());
			resJson.put("error", "server_error");
			resJson.put("error_description", "unexpected server error");
			resJson.put("http_status_code", 500);
			result.put("data", resJson);
			return result;
		}

		return result;
	}
}