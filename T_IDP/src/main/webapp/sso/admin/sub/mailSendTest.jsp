<%@ page language="java" contentType="text/html; charset=utf-8"  pageEncoding="utf-8"%>
<%@ page import="com.dreamsecurity.sso.server.api.audit.AuditController"%>
<%@ include file="./subCommon.jsp"%>
<%@ include file="./checkAdmin.jsp"%>
<%
	String referrer = request.getParameter("referrer") == null ? "" : request.getParameter("referrer");
	String subject = request.getParameter("subject") == null ? "" : request.getParameter("subject");
	String content = request.getParameter("content") == null ? "" : request.getParameter("content");

	String result = checkAdmin(adminid, admintype, adminmenu, "0202");
	if (!result.equals("")) {
		response.getWriter().write(result);
		return;
	}

	AuditController auditApi = new AuditController();
	result = auditApi.mailSendTest(referrer, subject, content);

	response.getWriter().write(result);
%>