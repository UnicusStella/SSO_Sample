<%@ page language="java" contentType="text/html; charset=utf-8"  pageEncoding="utf-8"%>
<%@ page import="com.dreamsecurity.sso.server.api.audit.AuditController"%>
<%@ page import="com.dreamsecurity.sso.server.util.Util"%>
<%@ include file="./subCommon.jsp"%>
<%@ include file="./checkAdmin.jsp"%>
<%
	String spid = request.getParameter("spid") == null ? "" : request.getParameter("spid");
	String stype = request.getParameter("stype") == null ? "" : request.getParameter("stype");
	String surl = request.getParameter("surl") == null ? "" : request.getParameter("surl");

	String result = checkAdmin(adminid, admintype, adminmenu, "0102");
	if (!result.equals("")) {
		response.getWriter().write(result);
		return;
	}

	if (Util.isEmpty(stype)) {
		result = "Error : 처리 조건을 입력하세요.";
	}
	else {
		AuditController auditApi = new AuditController();

		if (stype.equals("서버")) {
			result = auditApi.integrityIDPTestSync(adminid, "관리자 테스트");
		}
		else {
			result = auditApi.integritySPTest(spid, surl, adminid, "관리자 테스트");
		}
	}

	response.getWriter().write(result);
%>