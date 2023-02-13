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
	result = auditApi.mailServerTest(smtphost, smtpport, smtpchnl, smtpauth, authid, authpw);

	response.getWriter().write(result);
%>