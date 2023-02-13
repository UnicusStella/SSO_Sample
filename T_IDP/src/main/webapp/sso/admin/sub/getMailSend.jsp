<%@ page language="java" contentType="text/html; charset=utf-8"  pageEncoding="utf-8"%>
<%@ page import="com.dreamsecurity.sso.server.api.audit.AuditController"%>
<%@ page import="com.dreamsecurity.sso.server.util.Util"%>
<%@ include file="./subCommon.jsp"%>
<%
	String code = request.getParameter("code") == null ? "" : request.getParameter("code");
	String result = "";

	if (Util.isEmpty(code)) {
		result = "Error : 처리 조건을 입력하세요.";
	}
	else {
		AuditController auditApi = new AuditController();
		result = auditApi.getMailSend(code);
	}

	response.getWriter().write(result);
%>