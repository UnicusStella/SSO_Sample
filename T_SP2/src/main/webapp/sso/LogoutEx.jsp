<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<%@ page import="com.dreamsecurity.sso.agent.config.*"%>
<%@ page import="com.dreamsecurity.sso.agent.util.Util"%>
<%@ include file="./common.jsp"%>
<%
	out.clear();
	out = pageContext.pushBody();

	SSOConfig.setHomeDir(this.getServletConfig().getServletContext(), DEFAULT_SET_PATH);
	SSOInit.initialize();

	String others = request.getParameter("others") == null ? "" : (String) request.getParameter("others");
	String dupinfo = request.getParameter("dup") == null ? "" : (String) request.getParameter("dup");
	String brclose = request.getParameter("cl") == null ? "" : (String) request.getParameter("cl");
	String relaystate = request.getParameter(PARAM_RELAYSTATE) == null ? "" : (String) request.getParameter(PARAM_RELAYSTATE);

	//session.invalidate();
	session.removeAttribute(SESSION_SSO_ID);
	session.removeAttribute(SESSION_SSO_TOKEN);
	session.removeAttribute("IDP_Session");
	session.removeAttribute("POLLING_TIME");
	session.removeAttribute("SSO_INACTIVE");
	session.removeAttribute("SSO_SESSTIME");

	Util.sendSPLogoutURL(response, others, dupinfo, brclose, relaystate);
%>