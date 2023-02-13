package com.dreamsecurity.sso.server.controller;

import java.io.IOException;
import java.io.PrintWriter;
import java.rmi.ServerException;
import java.util.Enumeration;
import java.util.Map;

import javax.servlet.RequestDispatcher;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import com.dreamsecurity.sso.lib.jsn.JSONObject;
import com.dreamsecurity.sso.lib.slf.Logger;
import com.dreamsecurity.sso.lib.slf.LoggerFactory;
import com.dreamsecurity.sso.server.common.MStatus;
import com.dreamsecurity.sso.server.config.SSOConfig;
import com.dreamsecurity.sso.server.exception.SSOException;
import com.dreamsecurity.sso.server.provider.IdentificationProvider;
import com.dreamsecurity.sso.server.provider.OidcIdentificationProvider;
import com.dreamsecurity.sso.server.session.OidcSessionManager;
import com.dreamsecurity.sso.server.session.SessionManager;
import com.dreamsecurity.sso.server.util.Util;

@WebServlet(urlPatterns = "/oidc/*")
public class OidcController extends HttpServlet
{
	private static final long serialVersionUID = 1L;

	private static Logger log = LoggerFactory.getLogger(OidcController.class);

	@Override
	protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServerException, IOException
	{
		response.setHeader("Cache-Control", "no-cache");

		SSOConfig.setHomeDir(this.getServletConfig().getServletContext(), "/WEB-INF/classes");
		request.setAttribute("loginBr", Util.getBrowserType(request));

		if (request.getRequestURI().indexOf("/oidc/") != 0) {
			response.setStatus(404);
			return;
		}

		String subpath = request.getRequestURI().substring("/oidc/".length());

		if ("auth".equals(subpath)) {
			oidcAuth(request, response);
		}
		else if ("userinfo".equals(subpath)) {
			oidcUserInfo(request, response);
		}
		else if (".well-known/openid-configuration".equals(subpath)) {
			oidcCfg(request, response);
		}
		else if ("cert".equals(subpath)) {
			oidcCert(request, response);
		}
		else {
			log.error("### service: {}, {}", String.valueOf(MStatus.ERR_UNKNOWN_ENDPOINT), "unknown_endpoint");
			JSONObject resJson = new JSONObject();
			resJson.put("error", "invalid_request");
			resJson.put("error_description", "unknown_endpoint");
			resJson.put("error_code", String.valueOf(MStatus.ERR_UNKNOWN_ENDPOINT));
			resJson.put("http_status_code", 404);
			sendErrorResponse(response, resJson);
			return;
		}
	}

	@Override
	protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServerException, IOException
	{
		response.setHeader("Cache-Control", "no-cache");

		SSOConfig.setHomeDir(this.getServletConfig().getServletContext(), "/WEB-INF/classes");
		request.setAttribute("loginBr", Util.getBrowserType(request));

		if (request.getRequestURI().indexOf("/oidc/") != 0) {
			response.setStatus(404);
			return;
		}

		String subpath = request.getRequestURI().substring("/oidc/".length());

		if ("authenticate".equals(subpath)) {
			oidcAuthenticate(request, response);
		}
		else if ("token".equals(subpath)) {
			oidcToken(request, response);
		}
		else if ("introspect".equals(subpath)) {
			oidcIntrospect(request, response);
		}
		else if ("logout".equals(subpath)) {
			oidcLogout(request, response);
		}
		else {
			log.error("### service: {}, {}", String.valueOf(MStatus.ERR_UNKNOWN_ENDPOINT), "unknown_endpoint");
			JSONObject resJson = new JSONObject();
			resJson.put("error", "invalid_request");
			resJson.put("error_description", "unknown_endpoint");
			resJson.put("error_code", String.valueOf(MStatus.ERR_UNKNOWN_ENDPOINT));
			resJson.put("http_status_code", 404);
			sendErrorResponse(response, resJson);
			return;
		}
	}

	private void oidcAuth(HttpServletRequest request, HttpServletResponse response)
	{
		JSONObject result = null;
		OidcIdentificationProvider idp = null;

		try {
			idp = OidcIdentificationProvider.getInstance();
			result = idp.checkValidParamsAuth(request);

			if (Integer.parseInt((String) result.get("code")) != MStatus.SUCCESS) {
				log.error("### oidcAuth: {}, {}", (String) result.get("code"), (String) result.get("message"));
				JSONObject resJson = (JSONObject) result.get("data");
				sendErrorResponse(response, resJson);
				return;
			}
		}
		catch (SSOException e) {
			log.error("### oidcAuth: {}, {}", String.valueOf(e.getErrorCode()), e.getMessage());
			sendErrorResponse(response, null);
			return;
		}

		try {
			String id = (String) result.get("data");
			result = idp.authCodeAuthorizationResponse(request, response, id);

			if (Integer.parseInt((String) result.get("code")) != MStatus.SUCCESS) {
				JSONObject resJson = (JSONObject) result.get("data");
				sendErrorResponse(response, resJson);
				return;
			}
		}
		catch (Exception e) {
			log.error("### oidcAuth: {}", e.getMessage());
			sendErrorResponse(response, null);
			return;
		}

		JSONObject resJson = (JSONObject) result.get("data");
		boolean validSession = (Boolean) resJson.get("validSession");

		if (validSession) {
			String url = (String) resJson.get("url");

			try {
				response.sendRedirect(url);
			}
			catch (IOException e) {
				log.error("### oidcAuth: {}", e.getMessage());
				sendErrorResponse(response, null);
			}
		}
		else {
			String subAuthSessionId = (String) resJson.get("subAuthSessionId");
			request.setAttribute("SubAuthSessionId", subAuthSessionId);

			RequestDispatcher requestDispatcher = request.getRequestDispatcher("/WEB-INF/jsp/oidcLogin.jsp");

			try {
				requestDispatcher.forward(request, response);
			}
			catch (Exception e) {
				e.printStackTrace();
			}
		}

		return;
	}

	private void oidcAuthenticate(HttpServletRequest request, HttpServletResponse response)
	{
		JSONObject result = null;
		OidcIdentificationProvider idp = null;

		String subAuthSessionId = request.getParameter("SubAuthSessionId") == null ? "" : request.getParameter("SubAuthSessionId");

		if (Util.isEmpty(subAuthSessionId)) {
			sendErrorResponse(response, null);
			return;
		}

		try {
			idp = OidcIdentificationProvider.getInstance();
			result = idp.checkValidSessionAuthenticate(request);

			if (Integer.parseInt((String) result.get("code")) != MStatus.SUCCESS) {
				log.error("### oidcAuthenticate: checkValidSessionAuthenticate: {}, {}", (String) result.get("code"), (String) result.get("message"));
				JSONObject resJson = (JSONObject) result.get("data");
				sendErrorResponse(response, resJson);
				return;
			}
		}
		catch (SSOException e) {
			log.error("### oidcAuthenticate: checkValidSessionAuthenticate: {}, {}", String.valueOf(e.getErrorCode()), e.getMessage());
			sendErrorResponse(response, null);
			return;
		}

		try {
			result = idp.oidcLogin(request);

			if (Integer.parseInt((String) result.get("code")) != MStatus.SUCCESS) {
				log.error("### oidcAuthenticate: oidcLogin: {}, {}", (String) result.get("code"), (String) result.get("message"));

				request.setAttribute("SubAuthSessionId", subAuthSessionId);
				request.setAttribute("ErrorMessage", " 사용자 인증 실패");
				RequestDispatcher requestDispatcher = request.getRequestDispatcher("/WEB-INF/jsp/oidcLogin.jsp");

				try {
					requestDispatcher.forward(request, response);
				}
				catch (Exception e) {
					e.printStackTrace();
				}

				return;
			}
		}
		catch (Exception e) {
			log.error("### oidcAuthenticate: oidcLogin: {}", e.getMessage());
			sendErrorResponse(response, null);
			return;
		}

		try {
			result = idp.authCodeRedirect(request);

			if (Integer.parseInt((String) result.get("code")) != MStatus.SUCCESS) {
				log.error("### oidcAuthenticate: authCodeRedirect: {}, {}", (String) result.get("code"), (String) result.get("message"));
				JSONObject resJson = (JSONObject) result.get("data");
				sendErrorResponse(response, resJson);
				return;
			}
		}
		catch (Exception e) {
			log.error("### oidcAuthenticate: authCodeRedirect: {}", e.getMessage());
			sendErrorResponse(response, null);
			return;
		}

		try {
			String url = (String) result.get("data");
			response.sendRedirect(url);
		}
		catch (IOException e) {
			log.error("### oidcAuthenticate: redirect: {}", e.getMessage());
			sendErrorResponse(response, null);
		}

		return;
	}

	private void oidcToken(HttpServletRequest request, HttpServletResponse response)
	{
		JSONObject result = null;
		OidcIdentificationProvider idp = null;

		try {
			idp = OidcIdentificationProvider.getInstance();
			result = idp.checkGrantType(request);

			if (Integer.parseInt((String) result.get("code")) != MStatus.SUCCESS) {
				log.error("### oidcToken: {}, {}", (String) result.get("code"), (String) result.get("message"));
				JSONObject resJson = (JSONObject) result.get("data");
				sendErrorResponse(response, resJson);
				return;
			}
		}
		catch (SSOException e) {
			log.error("### oidcToken: {}, {}", String.valueOf(e.getErrorCode()), e.getMessage());
			sendErrorResponse(response, null);
			return;
		}

		try {
			int grant_type = (Integer) result.get("data");

			if (grant_type == MStatus.REFRESH_TOKEN_GRANT_TYPE) {
				result = idp.refreshTokenGrant(request);
			}
			else if (grant_type == MStatus.AUTHORIZATION_CODE_GRANT_TYPE) {
				result = idp.codeToToken(request);
			}
			else {
			}

			if (Integer.parseInt((String) result.get("code")) != MStatus.SUCCESS) {
				log.error("### oidcToken: {}, {}", (String) result.get("code"), (String) result.get("message"));
				JSONObject resJson = (JSONObject) result.get("data");
				sendErrorResponse(response, resJson);
				return;
			}
		}
		catch (Exception e) {
			log.error("### oidcToken: {}", e.getMessage());
			sendErrorResponse(response, null);
			return;
		}

		JSONObject resJson = (JSONObject) result.get("data");
		sendResponse(response, resJson);
		return;
	}

	private void oidcIntrospect(HttpServletRequest request, HttpServletResponse response)
	{
		JSONObject result = null;
		OidcIdentificationProvider idp = null;

		try {
			idp = OidcIdentificationProvider.getInstance();
			result = idp.tokenIntrospect(request);

			if (Integer.parseInt((String) result.get("code")) != MStatus.SUCCESS) {
				log.error("### oidcIntrospect: {}, {}", (String) result.get("code"), (String) result.get("message"));
				JSONObject resJson = (JSONObject) result.get("data");
				sendErrorResponse(response, resJson);
				return;
			}
		}
		catch (SSOException e) {
			log.error("### oidcIntrospect: {}, {}", String.valueOf(e.getErrorCode()), e.getMessage());
			sendErrorResponse(response, null);
			return;
		}

		JSONObject resJson = (JSONObject) result.get("data");
		sendResponse(response, resJson);
		return;
	}

	private void oidcUserInfo(HttpServletRequest request, HttpServletResponse response)
	{
		JSONObject result = null;
		OidcIdentificationProvider idp = null;

		try {
			idp = OidcIdentificationProvider.getInstance();
			result = idp.issueUserInfo(request);

			if (Integer.parseInt((String) result.get("code")) != MStatus.SUCCESS) {
				log.error("### oidcUserInfo: {}, {}", (String) result.get("code"), (String) result.get("message"));
				JSONObject resJson = (JSONObject) result.get("data");
				sendErrorResponse(response, resJson);
				return;
			}
		}
		catch (SSOException e) {
			log.error("### oidcUserInfo: {}, {}", String.valueOf(e.getErrorCode()), e.getMessage());
			sendErrorResponse(response, null);
			return;
		}

		JSONObject resJson = (JSONObject) result.get("data");
		sendResponse(response, resJson);
		return;
	}

	private void oidcLogout(HttpServletRequest request, HttpServletResponse response)
	{
		try {
			String clientId = request.getParameter("ClientId") == null ? "" : request.getParameter("ClientId");
			String relayState = request.getParameter("RelayState") == null ? "" : request.getParameter("RelayState");
			String dupinfo = request.getParameter("dup") == null ? "" : request.getParameter("dup");
			String brclose = request.getParameter("cl") == null ? "" : (String) request.getParameter("cl");

			HttpSession session = request.getSession(false);

			if (Util.isEmpty(clientId) || Util.isEmpty(relayState)) {
				JSONObject resJson = new JSONObject();
				resJson.put("error", "invalid_request");
				resJson.put("error_description", "null parameter RelayState");
				resJson.put("http_status_code", 400);
				resJson.put("error_code", String.valueOf(MStatus.ERR_RELAY_STATE_NOT_EXIST));

				log.error("### oidcLogout: {}, {}", (String) resJson.get("error"), (String) resJson.get("error_description"));
				sendErrorResponse(response, resJson);
				return;
			}

			if (session == null) {
				sendURLGet(response, relayState);
				return;
			}

			IdentificationProvider idp = null;
			try {
				idp = IdentificationProvider.getInstance();
			} catch (SSOException e) {
				log.error("### oidcLogout: {}, {}", String.valueOf(e.getErrorCode()), e.getMessage());
				sendErrorResponse(response, null);
				return;
			}

			String ssoId = (String) session.getAttribute(IdentificationProvider.SESSION_SSO_ID);

			if (Util.isEmpty(ssoId)) {
				sendURLGet(response, relayState);
				return;
			}

			String spLogoutInfo = idp.getSPLogoutInfo(request);

			idp.setLogoutInfo(request, clientId, Util.getBrowserType(request), dupinfo);

			if (SSOConfig.getInstance().getDupLoginType() == 1) {
				String authCode = (String) session.getAttribute(IdentificationProvider.SESSION_AUTHCODE);
				SessionManager.getInstance().logoutSession(ssoId, authCode);
			}

			String rootAuthSessionId = (String) session.getAttribute("DS_SESSION_ID");
			OidcSessionManager.getInstance().removeAuthSession(rootAuthSessionId);

			Map<?, ?> adminMap = (Map<?, ?>) session.getAttribute("SSO_ADMIN_INFO");
			if (adminMap == null) {
				session.invalidate();
			} else {
				Enumeration<?> em = session.getAttributeNames();
				while (em.hasMoreElements()) {
					String skey = (String) em.nextElement();
					if (skey.equals("SSO_ADMIN_ID") || skey.equals("SSO_ADMIN_INFO") || skey.equals("APCHLG")
							|| skey.equals("APTIME")) {
						continue;
					} else {
						session.removeAttribute(skey);
					}
				}
			}

			if (Util.isEmpty(spLogoutInfo)) {
				if (!Util.isEmpty(brclose) && brclose.equalsIgnoreCase("y")) {
					Util.closeURL(response);
				} else {
					sendURLGet(response, relayState);
				}
				return;
			}
			sendSPLogoutURL(response, spLogoutInfo, relayState);
		} catch (Exception e) {
			sendErrorResponse(response, null);
		}
	}

	private void oidcCfg(HttpServletRequest request, HttpServletResponse response)
	{
		JSONObject result = new JSONObject();
		OidcIdentificationProvider idp = null;

		try {
			idp = OidcIdentificationProvider.getInstance();
			result = idp.getOidcCfg(request);

			if (Integer.parseInt((String) result.get("code")) != MStatus.SUCCESS) {
				log.error("### oidcCfg: {}, {}", (String) result.get("code"), (String) result.get("message"));
				JSONObject resJson = (JSONObject) result.get("data");
				sendErrorResponse(response, resJson);
				return;
			}
		}
		catch (SSOException e) {
			log.error("### oidcCfg: {}, {}", String.valueOf(e.getErrorCode()), e.getMessage());
			sendErrorResponse(response, null);
			return;
		}

		JSONObject resJson = (JSONObject) result.get("data");
		sendInfoResponse(response, resJson);
		return;
	}

	private void oidcCert(HttpServletRequest request, HttpServletResponse response)
	{
		JSONObject result = new JSONObject();
		OidcIdentificationProvider idp = null;

		try {
			idp = OidcIdentificationProvider.getInstance();
			result = idp.getJwksInfo();

			if (Integer.parseInt((String) result.get("code")) != MStatus.SUCCESS) {
				log.error("### oidcCert: {}, {}", (String) result.get("code"), (String) result.get("message"));
				JSONObject resJson = (JSONObject) result.get("data");
				sendErrorResponse(response, resJson);
				return;
			}
		}
		catch (SSOException e) {
			log.error("### oidcCert: {}, {}", String.valueOf(e.getErrorCode()), e.getMessage());
			sendErrorResponse(response, null);
			return;
		}

		JSONObject resJson = (JSONObject) result.get("data");
		sendInfoResponse(response, resJson);
		return;
	}

	public void sendURLGet(HttpServletResponse response, String target)
	{
		try {
			StringBuffer str = new StringBuffer();
			str.append("<html>\n");
			str.append("<head>\n");
			str.append("<meta charset=\"UTF-8\">\n");
			str.append("<meta http-equiv=\"refresh\" content=\"0; url=").append(target).append("\">\n");
			str.append("<title></title>\n");
			str.append("<script type=\"text/javascript\">\n");
			str.append("</script>\n");
			str.append("</head>\n");
			str.append("<body\">\n");
			str.append("</body>\n");
			str.append("</html>");

			response.setHeader("Content-Type", "text/html; charset=UTF-8");
			response.setStatus(200);

			PrintWriter out = response.getWriter();
			out.write(str.toString());
			out.flush();
		}
		catch (Exception e) {
			e.printStackTrace();
		}
		return;
	}

	public void sendSPLogoutURL(HttpServletResponse response, String spLogoutInfo, String relayState)
	{
		try {
			String target = "";
			String others = "";
			String[] div = spLogoutInfo.split("\\^");

			if (div.length > 1) {
				int idx = spLogoutInfo.indexOf("^");
				target = spLogoutInfo.substring(0, idx);
				others = spLogoutInfo.substring(idx + 1);
			}
			else {
				target = spLogoutInfo;
				others = "";
			}

			StringBuffer str = new StringBuffer();
			str.append("<html>\n");
			str.append("<head>\n");
			str.append("<meta http-equiv=\"Content-Type\" content=\"text/html; charset=UTF-8\">\n");
			str.append("<title></title>\n");
			str.append("<script type=\"text/javascript\" defer=\"defer\">\n");
			str.append("function goNext() {\n");
			str.append("    var frm = document.getElementById(\"ssoForm\");\n");
			str.append("    frm.action = \"").append(target).append("\";\n");
			str.append("    frm.submit();\n");
			str.append("}\n");
			str.append("</script>\n");
			str.append("</head>\n");
			str.append("<body onload=\"goNext(); return false;\">\n");
			str.append("<form id=\"ssoForm\" name=\"ssoForm\" method=\"post\">\n");
			str.append("    <input type=\"hidden\" id=\"others\" name=\"others\" value=\"").append(others).append("\"/>\n");
			str.append("    <input type=\"hidden\" id=\"RelayState\" name=\"RelayState\" value=\"").append(relayState).append("\"/>\n");
			str.append("</form>\n");
			str.append("</body>\n");
			str.append("</html>");

			response.setHeader("Content-Type", "text/html; charset=UTF-8");

			PrintWriter out = response.getWriter();
			out.write(str.toString());
			out.flush();
		}
		catch (Exception e) {
			e.printStackTrace();
		}
		return;
	}

	public void sendResponse(HttpServletResponse response, JSONObject resJson)
	{
		try {
			response.setStatus(200);
			response.setHeader("Content-Type", "application/json; charset=UTF-8");

			PrintWriter out = response.getWriter();
			out.write(resJson.toString());
			out.flush();
		}
		catch (Exception e) {
			e.printStackTrace();
		}
		return;
	}

	public void sendErrorResponse(HttpServletResponse response, JSONObject resJson)
	{
		try {
			int httpStatusCode = 0;

			if (resJson == null) {
				resJson = new JSONObject();
				httpStatusCode = 500;
				resJson.put("error", "server_error");
				resJson.put("error_description", "unexpected server error");
				resJson.put("error_code", String.valueOf(MStatus.ERR_SERVER_EXCEPTION));
				response.setStatus(httpStatusCode);
			}
			else {
				httpStatusCode = (Integer) resJson.get("http_status_code");
				resJson.remove("http_status_code");
			}

			String redirectUrl = (String) resJson.get("redirectUrl");

			if (Util.isEmpty(redirectUrl)) {
				response.setHeader("Content-Type", "application/json; charset=UTF-8");
				response.setStatus(httpStatusCode);

				PrintWriter out = response.getWriter();
				out.write(resJson.toString());
				out.flush();
			}
			else {
				response.sendRedirect(redirectUrl);
			}
		}
		catch (Exception e) {
			e.printStackTrace();
		}
		return;
	}

	public void sendInfoResponse(HttpServletResponse response, JSONObject resJson)
	{
		try {
			response.setStatus(200);
			response.setHeader("Content-Type", "application/json; charset=UTF-8");

			PrintWriter out = response.getWriter();
			out.write(resJson.toString().replace("\\", ""));
			out.flush();
		}
		catch (Exception e) {
			e.printStackTrace();
		}
		return;
	}
}