<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<%@ page import="com.dreamsecurity.sso.server.api.audit.AuditController"%>
<%
	String result = "";

	AuditController auditApi = new AuditController();
	int rtn = auditApi.resetIntegrityFile();

	if (rtn == 0) {
		result = "{\"page\":1,\"total\":1,\"records\":1,\"rows\":[{\"resultstatus\":1,\"resultdata\":\"\"}]}";
	}
	else {
		result = "{\"page\":1,\"total\":1,\"records\":1,\"rows\":[{\"resultstatus\":-1,\"resultdata\":\"Exception Error.\"}]}";
	}

	response.getWriter().write(result);
%>