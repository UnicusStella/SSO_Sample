<%@page import="com.dreamsecurity.sso.lib.lcr.net.SyslogOutputStream"%>
<%@ page language="java" contentType="text/html; charset=utf-8"  pageEncoding="utf-8"%>
<%@ page import="com.dreamsecurity.sso.server.api.admin.AdminController"%>
<%@ page import="com.dreamsecurity.sso.server.util.Util"%>
<%@ include file="./subCommon.jsp"%>
<%@ include file="./checkAdmin.jsp"%>
<%
	String id = request.getParameter("id") == null ? "" : request.getParameter("id");

	String result = checkAdmin(adminid, admintype, adminmenu, "0502");
	
	if (!result.equals("")) {
		response.getWriter().write(result);
		return;
	}

	if (Util.isEmpty(id)) {
		result = "Error : 처리 조건을 입력하세요.";
	}
	else {
		AdminController adminApi = new AdminController();

		if (checkAdminCSRFToken(request)) {
			result = adminApi.setScope(adminid, id);
		}
		else {
			result = "Error : 유효하지 않은 페이지입니다.\n\n해당 페이지를 다시 호출하세요.";
		}
	}
	
	response.getWriter().write(result);
%>