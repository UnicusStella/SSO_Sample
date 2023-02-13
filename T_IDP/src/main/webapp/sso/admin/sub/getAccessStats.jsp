<%@ page language="java" contentType="text/html; charset=utf-8"  pageEncoding="utf-8"%>
<%@ page import="com.dreamsecurity.sso.server.api.admin.AdminController"%>
<%@ page import="com.dreamsecurity.sso.server.util.Util"%>
<%@ include file="./subCommon.jsp"%>
<%@ include file="./checkAdmin.jsp"%>
<%
	String stype = request.getParameter("stype") == null ? "" : request.getParameter("stype");
	String sdate = request.getParameter("sdate") == null ? "" : request.getParameter("sdate");

	String result = checkAdmin(adminid, admintype, adminmenu, "0105");
	if (!result.equals("")) {
		response.getWriter().write(result);
		return;
	}

	if (Util.isEmpty(stype) || Util.isEmpty(sdate)) {
		result = "Error : 처리 조건을 입력하세요.";
	}
	else {
		AdminController adminApi = new AdminController();
		result = adminApi.getStatsAccessInfo(stype, sdate);
	}

	response.getWriter().write(result);
%>