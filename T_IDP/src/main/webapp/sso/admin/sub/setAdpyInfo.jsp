<%@ page language="java" contentType="text/html; charset=utf-8"  pageEncoding="utf-8"%>
<%@ page import="com.dreamsecurity.sso.server.api.admin.AdminController"%>
<%@ page import="com.dreamsecurity.sso.server.util.Util"%>
<%@ include file="./subCommon.jsp"%>
<%@ include file="./checkAdmin.jsp"%>
<%
	String code = request.getParameter("code") == null ? "" : request.getParameter("code");
	String pwallow = request.getParameter("pwallow") == null ? "" : request.getParameter("pwallow");
	String locktime = request.getParameter("locktime") == null ? "" : request.getParameter("locktime");
	String sesstime = request.getParameter("sesstime") == null ? "" : request.getParameter("sesstime");
	String ipcnt = request.getParameter("ipcnt") == null ? "" : request.getParameter("ipcnt");

	String result = checkAdmin(adminid, admintype, adminmenu, "0402");
	if (!result.equals("")) {
		response.getWriter().write(result);
		return;
	}

	if (Util.isEmpty(code) || Util.isEmpty(pwallow) || Util.isEmpty(locktime) || Util.isEmpty(sesstime) || Util.isEmpty(ipcnt)) {
		result = "Error : 처리 조건을 입력하세요.";
	}
	else {
		AdminController adminApi = new AdminController();

		if (checkAdminCSRFToken(request)) {
			result = adminApi.setAdpyInfo(adminid, code, pwallow, locktime, sesstime, ipcnt);
		}
		else {
			result = "Error : 유효하지 않은 페이지입니다.\n\n해당 페이지를 다시 호출하세요.";
		}
	}

	response.getWriter().write(result);
%>