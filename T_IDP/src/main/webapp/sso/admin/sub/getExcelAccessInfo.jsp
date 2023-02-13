<%@ page language="java" contentType="text/html; charset=utf-8"  pageEncoding="utf-8"%>
<%@ page import="com.dreamsecurity.sso.server.api.admin.AdminController"%>
<%@ page import="com.dreamsecurity.sso.server.util.Util"%>
<%@ include file="./subCommon.jsp"%>
<%@ include file="./checkAdmin.jsp"%>
<%
	String uid = request.getParameter("uid") == null ? "" : request.getParameter("uid");
	String fdate = request.getParameter("fdate") == null ? "" : request.getParameter("fdate");
	String tdate = request.getParameter("tdate") == null ? "" : request.getParameter("tdate");
	String stype = request.getParameter("stype") == null ? "" : request.getParameter("stype");

	String result = checkAdmin(adminid, admintype, adminmenu, "0104");
	if (!result.equals("")) {
		response.getWriter().write(result);
		return;
	}

	if (Util.isEmpty(fdate) || Util.isEmpty(tdate) || Util.isEmpty(stype)) {
		result = "Error : 처리 조건을 입력하세요.";
	}
	else {
		AdminController adminApi = new AdminController();
		result = adminApi.getExcelAccessInfo(uid, fdate, tdate, stype, adminid);
	}

	response.getWriter().write(result);
%>