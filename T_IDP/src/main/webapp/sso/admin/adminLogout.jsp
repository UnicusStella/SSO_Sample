<%@ page language="java" contentType="text/html; charset=utf-8" pageEncoding="utf-8"%>
<%@ page import="java.util.Map"%>
<%@ page import="com.dreamsecurity.sso.server.api.admin.AdminController"%>
<%@ page import="com.dreamsecurity.sso.server.util.Util"%>
<%@ include file="adminCommon.jsp"%>
<%
	out.clear();
	out = pageContext.pushBody();

	String dt = request.getParameter("dt") == null ? "" : request.getParameter("dt");

	Map<?,?> adminMap = (Map<?,?>) session.getAttribute("SSO_ADMIN_INFO");
	if (adminMap != null) {
		String id = (String) adminMap.get("id");
		String ip = (String) adminMap.get("admnIp");
		String tp = (String) adminMap.get("admnType");

		AdminController adminApi = new AdminController();
		adminApi.setAdminLogoutInfo(id, ip, tp, dt);

		session.removeAttribute("SSO_ADMIN_ID");
		session.removeAttribute("SSO_ADMIN_INFO");
	}

	session.removeAttribute("APCHLG");
	session.removeAttribute("APTIME");

	Util.sendURL(response, LOGIN_PAGE);
%>