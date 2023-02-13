<%@ page language="java" contentType="text/html; charset=utf-8"  pageEncoding="utf-8"%>
<%@ page import="com.dreamsecurity.sso.server.api.audit.AuditController"%>
<%@ page import="com.dreamsecurity.sso.server.util.Util"%>
<%@ include file="./subCommon.jsp"%>
<%@ include file="./checkAdmin.jsp"%>
<%
	String fdate = request.getParameter("fdate") == null ? "" : request.getParameter("fdate");
	String tdate = request.getParameter("tdate") == null ? "" : request.getParameter("tdate");
	String stype = request.getParameter("stype") == null ? "" : request.getParameter("stype");
	String srslt = request.getParameter("srslt") == null ? "" : request.getParameter("srslt");

	String result = checkAdmin(adminid, admintype, adminmenu, "0101");
	if (!result.equals("")) {
		response.getWriter().write(result);
		return;
	}

	if (Util.isEmpty(fdate) || Util.isEmpty(tdate) || Util.isEmpty(stype)) {
		result = "Error : 처리 조건을 입력하세요.";
	}
	else {
		AuditController auditApi = new AuditController();
		result = auditApi.getExcelAuditInfo(fdate, tdate, stype, srslt, adminid);
	}

	response.getWriter().write(result);
%>