<%@ page language="java" contentType="text/html; charset=utf-8"  pageEncoding="utf-8"%>
<%@ page import="com.dreamsecurity.sso.server.api.audit.AuditController"%>
<%@ include file="./subCommon.jsp"%>
<%
	String result = "";

	AuditController auditApi = new AuditController();
	result = auditApi.getMailServer();

	response.getWriter().write(result);
%>