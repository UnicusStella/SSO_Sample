<%@ page language="java" contentType="text/html; charset=utf-8"  pageEncoding="utf-8"%>
<%@ page import="com.dreamsecurity.sso.server.util.Util"%>
<%
	String encData = request.getParameter("ED") == null ? "" : request.getParameter("ED");
	String ejnData = request.getParameter("EN") == null ? "" : request.getParameter("EN");

	if (!encData.equals("")) {
		Util.setAuditInfo("XM", encData);
	}
	else if (!ejnData.equals("")) {
		Util.setAuditInfo("JN", ejnData);
	}
%>