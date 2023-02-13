<%@ page language="java" contentType="text/html; charset=utf-8"  pageEncoding="utf-8"%>
<%@ page import="com.dreamsecurity.sso.server.api.audit.AuditController"%>
<%@ page import="com.dreamsecurity.sso.server.util.Util"%>
<%@ include file="./subCommon.jsp"%>
<%@ include file="./checkAdmin.jsp"%>
<%
	String warnlimit = request.getParameter("warnlimit") == null ? "" : request.getParameter("warnlimit");
	String verifycycle = request.getParameter("verifycycle") == null ? "" : request.getParameter("verifycycle");
	String verifypoint = request.getParameter("verifypoint") == null ? "" : request.getParameter("verifypoint");

	String result = checkAdmin(adminid, admintype, adminmenu, "0201");
	if (!result.equals("")) {
		response.getWriter().write(result);
		return;
	}

	if (Util.isEmpty(warnlimit) || Util.isEmpty(verifycycle) || Util.isEmpty(verifypoint)) {
		result = "Error : 처리 조건을 입력하세요.";
	}
	else {
		AuditController auditApi = new AuditController();

		if (checkAdminCSRFToken(request)) {
			result = auditApi.setAupyInfo(adminid, warnlimit, verifycycle, verifypoint);
		}
		else {
			result = "Error : 유효하지 않은 페이지입니다.\n\n해당 페이지를 다시 호출하세요.";
		}
	}

	response.getWriter().write(result);
%>