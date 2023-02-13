<%@ page language="java" contentType="text/html; charset=utf-8"  pageEncoding="utf-8"%>
<%@ page import="com.dreamsecurity.sso.server.api.admin.AdminController"%>
<%@ page import="com.dreamsecurity.sso.server.util.Util"%>
<%@ include file="./subCommon.jsp"%>
<%
	String code = request.getParameter("urpycode") == null ? "" : request.getParameter("urpycode");
	String result = "";

	if (Util.isEmpty(code)) {
		result = "Error : 처리 조건을 입력하세요.";
	}
	else {
		AdminController adminApi = new AdminController();
		result = adminApi.getUrpyInfo(code);
	}

	response.getWriter().write(result);
%>