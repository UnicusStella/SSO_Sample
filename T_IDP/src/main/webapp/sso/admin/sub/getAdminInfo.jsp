<%@ page language="java" contentType="text/html; charset=utf-8"  pageEncoding="utf-8"%>
<%@ page import="com.dreamsecurity.sso.server.api.admin.AdminController"%>
<%@ page import="com.dreamsecurity.sso.server.util.Util"%>
<%@ include file="./subCommon.jsp"%>
<%@ include file="./checkAdmin.jsp"%>
<%
	String uid = request.getParameter("uid") == null ? "" : request.getParameter("uid");

	String result = checkAdmin(adminid, admintype, adminmenu, "0401");
	if (!result.equals("")) {
		response.getWriter().write(result);
		return;
	}

	if (Util.isEmpty(uid)) {
		result = "Error : 처리 조건을 입력하세요.";
	}
	else {
		AdminController adminApi = new AdminController();
		result = adminApi.getAdminInfo(uid);
	}

	response.getWriter().write(result);
%>