<%@ page language="java" contentType="text/html; charset=utf-8"  pageEncoding="utf-8"%>
<%@ page import="com.dreamsecurity.sso.server.api.admin.AdminController"%>
<%@ page import="com.dreamsecurity.sso.server.util.Util"%>
<%@ include file="./subCommon.jsp"%>
<%@ include file="./checkAdmin.jsp"%>
<%
	String newflag = request.getParameter("newflag") == null ? "" : request.getParameter("newflag");
	String name = request.getParameter("name") == null ? "" : request.getParameter("name");
	String id = request.getParameter("id") == null ? "" : request.getParameter("id");
	String protocol = request.getParameter("protocol") == null ? "" : request.getParameter("protocol");
	String enabled = request.getParameter("enabled") == null ? "" : request.getParameter("enabled");
	String secret = request.getParameter("secret") == null ? "" : request.getParameter("secret");
	String nonce = request.getParameter("nonce") == null ? "" : request.getParameter("nonce");
	String pkce = request.getParameter("pkce") == null ? "" : request.getParameter("pkce");
	String refresh = request.getParameter("refresh") == null ? "" : request.getParameter("refresh");
	String codeLife = request.getParameter("codeLife") == null ? "" : request.getParameter("codeLife");
	String tokenLife = request.getParameter("tokenLife") == null ? "" : request.getParameter("tokenLife");
	String refreshLife = request.getParameter("refreshLife") == null ? "" : request.getParameter("refreshLife");
	String responseType = request.getParameter("responseType") == null ? "" : request.getParameter("responseType");
	String grantType = request.getParameter("grantType") == null ? "" : request.getParameter("grantType");

	String[] redirectUriList = request.getParameterValues("redirectUriList");
	String[] scopeList = request.getParameterValues("scopeList");
	
	String result = checkAdmin(adminid, admintype, adminmenu, "0501");
	
	if (!result.equals("")) {
		response.getWriter().write(result);
		return;
	}

	if (Util.isEmpty(id) || Util.isEmpty(name)) {
		result = "Error : 처리 조건을 입력하세요.";
	}
	else {
		AdminController adminApi = new AdminController();

		if (checkAdminCSRFToken(request)) {
			result = adminApi.setClientInfo(newflag, adminid, id, name, protocol, enabled, nonce, pkce, refresh, secret, tokenLife,
					refreshLife, codeLife, grantType, responseType, scopeList, redirectUriList);
		}
		else {
			result = "Error : 유효하지 않은 페이지입니다.\n\n해당 페이지를 다시 호출하세요.";
		}
	}

	response.getWriter().write(result);
%>