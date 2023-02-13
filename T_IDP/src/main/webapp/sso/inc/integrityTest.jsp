<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<%@ page import="com.dreamsecurity.sso.server.api.audit.AuditController"%>
<%
	String selftest = request.getParameter("ST") == null ? "" : request.getParameter("ST");

	AuditController auditApi = new AuditController();

	if (selftest.equals("1")) {
		auditApi.integritySelfTestSync();
	}
%>