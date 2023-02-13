<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<%@ page import="com.dreamsecurity.sso.agent.config.*"%>
<%@ page import="com.dreamsecurity.sso.agent.api.AuditService"%>
<%@ include file="./common.jsp"%>
<%
	String selftest = request.getParameter("ST") == null ? "" : request.getParameter("ST");
	String encData = request.getParameter("ED") == null ? "" : request.getParameter("ED");

	SSOConfig.setHomeDir(this.getServletConfig().getServletContext(), DEFAULT_SET_PATH);
	SSOInit.initialize();

	AuditService auditApi = new AuditService();

	if (!encData.equals("")) {
		auditApi.integrityTestSync(encData);
	}
	else if (selftest.equals("1")) {
		auditApi.integritySelfTest();
	}
%>