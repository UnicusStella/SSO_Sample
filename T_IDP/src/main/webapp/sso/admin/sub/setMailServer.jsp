<%@ page language="java" contentType="text/html; charset=utf-8"  pageEncoding="utf-8"%>
<%@ page import="com.dreamsecurity.sso.server.api.audit.AuditController"%>
<%@ include file="./subCommon.jsp"%>
<%@ include file="./checkAdmin.jsp"%>
<%
	String smtphost = request.getParameter("smtphost") == null ? "" : request.getParameter("smtphost");
	String smtpport = request.getParameter("smtpport") == null ? "" : request.getParameter("smtpport");
	String smtpchnl = request.getParameter("smtpchnl") == null ? "" : request.getParameter("smtpchnl");
	String smtpauth = request.getParameter("smtpauth") == null ? "" : request.getParameter("smtpauth");
	String authid = request.getParameter("authid") == null ? "" : request.getParameter("authid");
	String authpw = request.getParameter("authpw") == null ? "" : request.getParameter("authpw");

	String result = checkAdmin(adminid, admintype, adminmenu, "0202");
	if (!result.equals("")) {
		response.getWriter().write(result);
		return;
	}

	AuditController auditApi = new AuditController();

	if (checkAdminCSRFToken(request)) {
		result = auditApi.setMailServer(adminid, smtphost, smtpport, smtpchnl, smtpauth, authid, authpw);
	}
	else {
		result = "Error : 유효하지 않은 페이지입니다.\n\n해당 페이지를 다시 호출하세요.";
	}

	response.getWriter().write(result);
%>