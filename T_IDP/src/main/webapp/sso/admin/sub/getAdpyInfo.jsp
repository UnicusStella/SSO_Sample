<%@ page language="java" contentType="text/html; charset=utf-8"  pageEncoding="utf-8"%>
<%@ page import="com.dreamsecurity.sso.server.api.admin.AdminController"%>
<%@ page import="com.dreamsecurity.sso.server.util.Util"%>
<%@ include file="./subCommon.jsp"%>
<%
	String code = request.getParameter("code") == null ? "" : request.getParameter("code");
	String result = "";

	if (Util.isEmpty(code)) {
		result = "Error : 처리 조건을 입력하세요.";
	}
	else {
		AdminController adminApi = new AdminController();
		result = adminApi.getAdpyInfo(code);
	}

	response.getWriter().write(result);
%>