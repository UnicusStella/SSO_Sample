<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<%@ page import="com.dreamsecurity.sso.agent.api.AuditService"%>
<%
	String result = "";

	AuditService auditApi = new AuditService();
	int rtn = auditApi.resetIntegrityFile();

	if (rtn == 0) {
		result = "{\"page\":1,\"total\":1,\"records\":1,\"rows\":[{\"resultstatus\":1,\"resultdata\":\"\"}]}";
	}
	else {
		result = "{\"page\":1,\"total\":1,\"records\":1,\"rows\":[{\"resultstatus\":-1,\"resultdata\":\"Exception Error.\"}]}";
	}

	response.getWriter().write(result);
%>