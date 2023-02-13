<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<%@ page import="java.util.Enumeration"%>
<%@ page import="java.util.Map"%>
<%@ page import="com.dreamsecurity.sso.server.config.SSOConfig"%>
<%@ page import="com.dreamsecurity.sso.server.exception.SSOException"%>
<%@ page import="com.dreamsecurity.sso.server.provider.IdentificationProvider"%>
<%@ page import="com.dreamsecurity.sso.server.session.SessionManager"%>
<%@ page import="com.dreamsecurity.sso.server.session.OidcSessionManager"%>
<%@ page import="com.dreamsecurity.sso.server.util.Util"%>
<%@ include file="./common.jsp"%>
<%
	out.clear();

	String dupinfo = request.getParameter("dup") == null ? "" : (String) request.getParameter("dup");
	String brclose = request.getParameter("cl") == null ? "" : (String) request.getParameter("cl");
	String spName = request.getParameter("SPName") == null ? "IDP" : (String) request.getParameter("SPName");
	String relaystate = request.getParameter(TEMPLETE_PARAM_RELAYSTATE);

	if (Util.isEmpty(relaystate)) {
		relaystate = DEFAULT_BASE_URL;
	}

	String ssoId = (String) session.getAttribute(IdentificationProvider.SESSION_SSO_ID);

	if (Util.isEmpty(ssoId)) {
		if (!Util.isEmpty(brclose) && brclose.equalsIgnoreCase("y")) {
			Util.closeURL(response);
		}
		else {
			Util.sendURL(response, relaystate, dupinfo);
		}

		return;
	}

	String baseURL = Util.getBaseURL(request);

	IdentificationProvider idp = null;

	try {
		idp = IdentificationProvider.getInstance();
	}
	catch (SSOException e) {
		Util.sendErrorURL(response, ERROR_PAGE, String.valueOf(e.getErrorCode()), e.getMessage());
		return;
	}

	String spLogoutInfo = idp.getSPLogoutInfo(request);

	idp.setLogoutInfo(request, spName, getBrowserType(request), dupinfo);

	if (SSOConfig.getInstance().getDupLoginType() == 1) {
		String authCode = (String) session.getAttribute(IdentificationProvider.SESSION_AUTHCODE);
		SessionManager.getInstance().logoutSession(ssoId, authCode);
	}
	
	String rootAuthSessionId = (String) session.getAttribute("DS_SESSION_ID");
	OidcSessionManager.getInstance().removeAuthSession(rootAuthSessionId);

	Map<?,?> adminMap = (Map<?,?>) session.getAttribute("SSO_ADMIN_INFO");
	if (adminMap == null) {
		session.invalidate();
	}
	else {
		Enumeration<?> em = session.getAttributeNames();
		while (em.hasMoreElements()) {
			String skey = (String) em.nextElement();
			if (skey.equals("SSO_ADMIN_ID") || skey.equals("SSO_ADMIN_INFO") ||
					skey.equals("APCHLG") || skey.equals("APTIME")) {
				continue;
			}
			else {
				session.removeAttribute(skey);
			}
		}
	}

	if (Util.isEmpty(spLogoutInfo)) {
		if (!Util.isEmpty(brclose) && brclose.equalsIgnoreCase("y")) {
			Util.closeURL(response);
		}
		else {
			Util.sendURL(response, relaystate, dupinfo);
		}

		return;
	}

	Util.sendSPLogoutURL(response, spLogoutInfo, dupinfo, brclose, relaystate);
%>