<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<%@ page import="com.dreamsecurity.sso.agent.config.*"%>
<%@ page import="com.dreamsecurity.sso.agent.util.SAMLUtil"%>
<%@ include file="./common.jsp"%>
<%
	out.clear();
	out = pageContext.pushBody();

	SSOConfig.setHomeDir(this.getServletConfig().getServletContext(), DEFAULT_SET_PATH);
	SSOInit.initialize();

	String relaystate = request.getParameter(PARAM_RELAYSTATE);
	if (Util.isEmpty(relaystate)) {
		relaystate = DEFAULT_BASE_URL;
	}

	relaystate = Util.getURL(request, relaystate);

	String slo = request.getParameter("slo") == null ? "" : request.getParameter("slo");
	String dupinfo = request.getParameter("dup") == null ? "" : request.getParameter("dup");
	String brclose = request.getParameter("cl") == null ? "" : (String) request.getParameter("cl");

	// multi-IdP
	String idp = request.getParameter("idp") == null ? "" : (String) request.getParameter("idp");

	//session.invalidate();
	session.removeAttribute(SESSION_SSO_ID);
	session.removeAttribute(SESSION_SSO_TOKEN);
	session.removeAttribute("IDP_Session");
	session.removeAttribute("POLLING_TIME");
	session.removeAttribute("SSO_INACTIVE");
	session.removeAttribute("SSO_SESSTIME");

	// EAM ROLE
	session.removeAttribute(SESSION_ROLE);

	if (slo.equalsIgnoreCase("n")) {
		// SP only Logout
		Util.sendURL(response, relaystate, dupinfo);
	}
	else {
		// SLO
		SAMLUtil.sendIDPLogout(response, relaystate, dupinfo, brclose, idp);
	}
%>