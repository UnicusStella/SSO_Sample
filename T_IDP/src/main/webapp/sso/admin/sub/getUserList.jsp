<%@ page language="java" contentType="text/html; charset=utf-8"  pageEncoding="utf-8"%>
<%@ page import="com.dreamsecurity.sso.server.api.admin.AdminController"%>
<%@ page import="com.dreamsecurity.sso.server.util.Util"%>
<%@ include file="./subCommon.jsp"%>
<%
	String pageno = request.getParameter("pageno") == null ? "" : request.getParameter("pageno");
	String pagerow = request.getParameter("pagerow") == null ? "" : request.getParameter("pagerow");
	String result = "";

	if (Util.isEmpty(pageno) || Util.isEmpty(pagerow)) {
		result = "Error : 처리 조건을 입력하세요.";
	}
	else {
		int npageno = Integer.parseInt(pageno);
		int npagerow = Integer.parseInt(pagerow);

		AdminController adminApi = new AdminController();
		result = adminApi.getUserList(npageno, npagerow);
	}

	response.getWriter().write(result);
%>