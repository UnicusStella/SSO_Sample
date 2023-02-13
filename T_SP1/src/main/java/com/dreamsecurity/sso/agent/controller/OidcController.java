package com.dreamsecurity.sso.agent.controller;

import java.io.IOException;
import java.io.PrintWriter;
import java.rmi.ServerException;

import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import com.dreamsecurity.sso.agent.api.OidcService;
import com.dreamsecurity.sso.agent.client.ClientRepository;
import com.dreamsecurity.sso.agent.common.MStatus;
import com.dreamsecurity.sso.agent.config.SSOConfig;
import com.dreamsecurity.sso.agent.exception.SSOException;
import com.dreamsecurity.sso.agent.provider.OidcServiceProvider;
import com.dreamsecurity.sso.agent.util.Util;
import com.dreamsecurity.sso.lib.jsn.JSONObject;
import com.dreamsecurity.sso.lib.slf.Logger;
import com.dreamsecurity.sso.lib.slf.LoggerFactory;

@WebServlet(urlPatterns = "/oidc/*")
public class OidcController extends HttpServlet
{
	private static final long serialVersionUID = 1L;

	private static Logger log = LoggerFactory.getLogger(OidcController.class);

	@Override
	protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServerException, IOException
	{
		response.setHeader("Cache-Control", "no-cache");

		SSOConfig.setHomeDir(this.getServletConfig().getServletContext(), "/WEB-INF/dreamsso");
		request.setAttribute("loginBr", Util.getBrowserType(request));

		if (request.getRequestURI().indexOf("/oidc/") != 0) {
			response.setStatus(404);
			return;
		}

		String subpath = request.getRequestURI().substring("/oidc/".length());

		if ("auth".equals(subpath)) {
			oidcAuthRequest(request, response);
		}
		else if ("redirectAuthcode".equals(subpath)) {
			oidcTokenRequest(request, response);
		}
		else if ("logout".equals(subpath)) {
			oidcLogoutRequest(request, response);
		}
		else if ("refreshtoken".equals(subpath)) {
			oidcRefreshTokenRequest(request, response);
		}
		else if ("verifytoken".equals(subpath)) {
			oidcVerifyTokenRequest(request, response);
		}
		else if ("userinfo".equals(subpath)) {
			oidcUserInfoRequest(request, response);
		}
		else {
			response.setStatus(404);
			return;
		}
	}

	@Override
	protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServerException, IOException
	{
		response.setHeader("Cache-Control", "no-cache");

		SSOConfig.setHomeDir(this.getServletConfig().getServletContext(), "/WEB-INF/dreamsso");
		request.setAttribute("loginBr", Util.getBrowserType(request));

		if (request.getRequestURI().indexOf("/oidc/") != 0) {
			response.setStatus(404);
			return;
		}

		String subpath = request.getRequestURI().substring("/oidc/".length());

		if ("auth".equals(subpath)) {
			oidcAuthRequest(request, response);
		}
		else if ("logoutEx".equals(subpath)) {
			oidcLogoutSlo(request, response);
		}
		else {
			response.setStatus(404);
			return;
		}
	}

	private void oidcAuthRequest(HttpServletRequest request, HttpServletResponse response)
	{
		JSONObject result = null;
		OidcServiceProvider sp = null;
		String url = "";

		try {
			sp = OidcServiceProvider.getInstance();
			result = sp.generateOidcAuthRequest(request);

			if (Integer.parseInt((String) result.get("code")) != MStatus.SUCCESS) {
				log.error("### oidcAuthRequest: {}, {}", (String) result.get("code"), (String) result.get("message"));
				sendErrorURL(response);
				return;
			}
		}
		catch (SSOException e) {
			log.error("### oidcAuthRequest: {}, {}", String.valueOf(e.getErrorCode()), e.getMessage());
			sendErrorURL(response);
			return;
		}

		url = (String) result.get("data");

		sendURLGet(response, url);
		return;
	}

	private void oidcTokenRequest(HttpServletRequest request, HttpServletResponse response)
	{
		JSONObject result = null;
		OidcServiceProvider sp = null;

		try {
			sp = OidcServiceProvider.getInstance();
			result = sp.generateOidcTokenRequest(request);
			if (Integer.parseInt((String) result.get("code")) != MStatus.SUCCESS) {
				log.error("### oidcTokenRequest: {}, {}", (String) result.get("code"), (String) result.get("message"));
				sendErrorURL(response);
				return;
			}
		}
		catch (SSOException e) {
			log.error("### oidcTokenRequest: {}, {}", String.valueOf(e.getErrorCode()), e.getMessage());
			sendErrorURL(response);
			return;
		}

		try {
			JSONObject reqTokenInfo = (JSONObject) result.get("data");
			String parameter = (String) reqTokenInfo.get("parameter");
			String url = (String) reqTokenInfo.get("url");

			result = sp.sendHttpRequest(url, parameter, "POST", null, null);

			if (Integer.parseInt((String) result.get("code")) != MStatus.SUCCESS) {
				log.error("### oidcTokenRequest: {}, {}", (String) result.get("code"), (String) result.get("message"));
				sendErrorURL(response);
				return;
			}
		}
		catch (Exception e) {
			log.error("### oidcTokenRequest: {} ", e.getMessage());
			sendErrorURL(response);
			return;
		}

		try {
			JSONObject resTokenInfo = (JSONObject) result.get("data");
			result = sp.checkValidTokenResponse(request, resTokenInfo);

			if (Integer.parseInt((String) result.get("code")) != MStatus.SUCCESS) {
				log.error("### oidcTokenRequest: {}, {}", (String) result.get("code"), (String) result.get("message"));
				sendErrorURL(response);
				return;
			}
		}
		catch (Exception e) {
			log.error("### oidcTokenRequest: {} ", e.getMessage());
			sendErrorURL(response);
			return;
		}

		String relay = request.getParameter("relay");
		sendURLGet(response, relay);
	}

	private void oidcRefreshTokenRequest(HttpServletRequest request, HttpServletResponse response)
	{
		JSONObject result = null;

		try {
			String refreshToken = null;
			JSONObject token = null;
			String nonce = null;

			HttpSession session = request.getSession(false);

			if (session != null) {
				token = (JSONObject) session.getAttribute("SSO_Token");
				nonce = (String) session.getAttribute("nonce");
			}
			else {
				result = new JSONObject();
				result.put("code", String.valueOf(MStatus.ERR_CLIENT_SESSION_INVALID));
				result.put("message", "oidcRefreshTokenRequest: Session Invalid");

				sendResponse(response, result);
				return;
			}

			if (token != null) {
				refreshToken = (String) token.get("refresh_token");
			}
			else {
				result = new JSONObject();
				result.put("code", String.valueOf(MStatus.ERR_CLIENT_OIDC_TOKEN_NULL));
				result.put("message", "oidcRefreshTokenRequest: Token Null");

				sendResponse(response, result);
				return;
			}

			OidcService oidcApi = new OidcService();
			result = oidcApi.getRefreshToken(refreshToken, nonce);

			if (Integer.parseInt((String) result.get("code")) != MStatus.SUCCESS) {
				sendResponse(response, result);
				return;
			}

			JSONObject resToken = (JSONObject) result.get("data");
			session.setAttribute("SSO_Token", resToken);
		}
		catch (Exception e) {
			result = null;
			result = new JSONObject();
			result.put("code", String.valueOf(MStatus.FAIL));
			result.put("message", "oidcRefreshTokenRequest: Exception: " + e.getMessage());

			sendResponse(response, result);
			return;
		}

		String relay = request.getParameter("relay") == null ? "" : request.getParameter("relay");
		sendURLGet(response, relay);
	}

	private void oidcVerifyTokenRequest(HttpServletRequest request, HttpServletResponse response)
	{
		JSONObject result = null;

		try {
			JSONObject token = null;

			HttpSession session = request.getSession(false);

			if (session != null) {
				token = (JSONObject) session.getAttribute("SSO_Token");
			}
			else {
				result = new JSONObject();
				result.put("code", String.valueOf(MStatus.ERR_CLIENT_SESSION_INVALID));
				result.put("message", "oidcVerifyTokenRequest: Session Invalid");

				sendResponse(response, result);
				return;
			}

			if (token == null) {
				result = new JSONObject();
				result.put("code", String.valueOf(MStatus.ERR_CLIENT_OIDC_TOKEN_NULL));
				result.put("message", "oidcVerifyTokenRequest: Token Null");

				sendResponse(response, result);
				return;
			}

			String jwtToken = null;
			String accessToken = null;
			String type = request.getParameter("type") == null ? "id" : request.getParameter("type");

			if (type.equals("id")) {
				jwtToken = (String) token.get("id_token");
				type = MStatus.ID_TOKEN_TYPE;
			}
			else if (type.equals("access")) {
				jwtToken = (String) token.get("access_token");
				type = MStatus.ACCESS_TOKEN_TYPE;
			}
			else if (type.equals("refresh")) {
				jwtToken = (String) token.get("refresh_token");
				type = MStatus.REFRESH_TOKEN_TYPE;
			}
			else {
				result = new JSONObject();
				result.put("code", String.valueOf(MStatus.ERR_UNKNOWN_TOKEN_TYPE));
				result.put("message", "oidcVerifyTokenRequest: Unknown Token Type");

				sendResponse(response, result);
				return;
			}

			String authType = MStatus.AUTHORIZATION_HEADER_TYPE_BEARER;

			if (authType.equals(MStatus.AUTHORIZATION_HEADER_TYPE_BASIC)) {
				accessToken = null;
			}
			else if (authType.equals(MStatus.AUTHORIZATION_HEADER_TYPE_BEARER)) {
				accessToken = (String) token.get("access_token");
			}

			OidcService oidcApi = new OidcService();
			result = oidcApi.verifyToken(accessToken ,jwtToken, type);

			if (Integer.parseInt((String) result.get("code")) != MStatus.SUCCESS) {
				sendResponse(response, result);
				return;
			}
		}
		catch (Exception e) {
			result = null;
			result = new JSONObject();
			result.put("code", String.valueOf(MStatus.FAIL));
			result.put("message", "oidcVerifyTokenRequest: Exception: " + e.getMessage());

			sendResponse(response, result);
			return;
		}

		JSONObject resJson = (JSONObject) result.get("data");
		sendResponse(response, resJson);
		return;
	}

	private void oidcUserInfoRequest(HttpServletRequest request, HttpServletResponse response)
	{
		JSONObject result = null;

		try {
			JSONObject token = null;
			String accessToken = null;

			HttpSession session = request.getSession(false);

			if (session != null) {
				token = (JSONObject) session.getAttribute("SSO_Token");
			}
			else {
				result = new JSONObject();
				result.put("code", String.valueOf(MStatus.ERR_CLIENT_SESSION_INVALID));
				result.put("message", "oidcUserInfoRequest: Session Invalid");

				sendResponse(response, result);
				return;
			}

			if (token != null) {
				accessToken = (String) token.get("access_token");
			}
			else {
				result = new JSONObject();
				result.put("code", String.valueOf(MStatus.ERR_CLIENT_OIDC_TOKEN_NULL));
				result.put("message", "oidcUserInfoRequest: Token Null");

				sendResponse(response, result);
				return;
			}

			OidcService oidcApi = new OidcService();
			result = oidcApi.getUserInfo(accessToken);

			if (Integer.parseInt((String) result.get("code")) != MStatus.SUCCESS) {
				sendErrorURL(response);
				return;
			}
		}
		catch (Exception e) {
			result = null;
			result = new JSONObject();
			result.put("code", String.valueOf(MStatus.FAIL));
			result.put("message", "oidcUserInfoRequest: Exception: " + e.getMessage());

			sendResponse(response, result);
			return;
		}

		JSONObject resJson = (JSONObject) result.get("data");
		sendResponse(response, resJson);
		return;
	}

	private void oidcLogoutRequest(HttpServletRequest request, HttpServletResponse response)
	{
		String logoutUrl = ClientRepository.getInstance().getClientModel().getLogoutEndpoint();
		String clientId = ClientRepository.getInstance().getClientModel().getId();

		String relayState = (String) SSOConfig.getInstance().getProperty("oidc.url.base");
		String baseUrl = (String) SSOConfig.getInstance().getProperty("oidc.url.base");

		relayState = Util.getURL(request, relayState);

		HttpSession session = request.getSession(false);

		if (session != null) {
			session.removeAttribute("SSO_Token");
			session.removeAttribute("nonce");
		}

		String slo = request.getParameter("slo") == null ? "y" : request.getParameter("slo");
		
		if (slo.equalsIgnoreCase("n")) {
			sendURLGet(response, baseUrl);
		}
		else {
			sendIDPLogout(response, logoutUrl, clientId, relayState);
		}

		return;
	}

	private void oidcLogoutSlo(HttpServletRequest request, HttpServletResponse response)
	{
		String others = request.getParameter("others") == null ? "" : (String) request.getParameter("others");
		String relayState = request.getParameter("RelayState") == null ? "" : (String) request.getParameter("RelayState");

		HttpSession session = request.getSession(false);

		if (session == null) {
			sendURLGet(response, relayState);
			return;
		}
		else {
			session.removeAttribute("SSO_Token");
			session.removeAttribute("nonce");
		}

		if (Util.isEmpty(others)) {
			sendURLGet(response, relayState);
			return;
		}

		sendSPLogoutURL(response, others, relayState);
		return;
	}

	public void sendErrorURL(HttpServletResponse response)
	{
		try {
			String baseUrl = (String) SSOConfig.getInstance().getProperty("oidc.url.base");

			response.setStatus(200);
			response.setHeader("Content-Type", "text/html; charset=UTF-8");

			PrintWriter out = response.getWriter();
			out.println("<html>");
			out.println("<head>");
			out.println("<meta http-equiv=\"Content-Type\" content=\"text/html; charset=UTF-8\">");
			out.println("<title>Error</title>");
			out.println("<script type=\"text/javascript\">");
			out.println("    alert(\" 사용자 인증 실패\");");
			out.println("    location.href = \"" + baseUrl + "\"");
			out.println("</script>");
			out.println("</html>");
			out.flush();
		}
		catch (Exception e) {
			e.printStackTrace();
		}
	}

	public static void sendURLGet(HttpServletResponse response, String target)
	{
		try {
			if (Util.isEmpty(target)) {
				response.setStatus(404);
				return;
			}
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

			PrintWriter out = response.getWriter();
			out.write(str.toString());
			out.flush();
		}
		catch (Exception e) {
			e.printStackTrace();
		}
	}

	public static void sendSPLogoutURL(HttpServletResponse response, String spLogoutInfo, String relaystate)
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
			str.append("<script type=\"text/javascript\">\n");
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
			str.append("    <input type=\"hidden\" id=\"RelayState\" name=\"RelayState\" value=\"").append(relaystate).append("\"/>\n");
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
	}

	public static void sendIDPLogout(HttpServletResponse response, String target, String clientId, String relayState)
	{
		try {
			StringBuffer str = new StringBuffer();
			str.append("<html>\n");
			str.append("<head>\n");
			str.append("<meta http-equiv=\"Content-Type\" content=\"text/html; charset=UTF-8\">\n");
			str.append("<title></title>\n");
			str.append("<script type=\"text/javascript\">\n");
			str.append("function goNext() {\n");
			str.append("    var frm = document.getElementById(\"ssoForm\");\n");
			str.append("    frm.action = \"").append(target).append("\";\n");
			str.append("    frm.submit();\n");
			str.append("}\n");
			str.append("</script>\n");
			str.append("</head>\n");
			str.append("<body onload=\"goNext(); return false;\">\n");
			str.append("<form id=\"ssoForm\" name=\"ssoForm\" method=\"post\">\n");
			str.append("<input type=\"hidden\" id=\"ClientId\" name=\"ClientId\" value=\"" + clientId + "\"/>\n");
			str.append("<input type=\"hidden\" id=\"RelayState\" name=\"RelayState\" value=\"");
			if (relayState != null) {
				str.append(relayState);
			}
			str.append("\"/>\n");
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
	}

	public void sendResponse(HttpServletResponse response, JSONObject resJson)
	{
		try {
			response.setStatus(200);
			response.setHeader("Content-Type", "text/html; charset=UTF-8");

			PrintWriter out = response.getWriter();
			out.write(resJson.toString());
			out.flush();
		}
		catch (Exception e) {
			e.printStackTrace();
		}
		return;
	}
}