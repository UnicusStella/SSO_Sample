<%@ page language="java" contentType="text/html; charset=utf-8"  pageEncoding="utf-8"%>
<%@ page import="com.dreamsecurity.sso.server.api.audit.AuditController"%>
<%@ page import="com.dreamsecurity.sso.server.util.Util"%>
<%@ include file="./subCommon.jsp"%>
<%@ include file="./checkAdmin.jsp"%>
<%
	String code = request.getParameter("code") == null ? "" : request.getParameter("code");
	String referrer = request.getParameter("referrer") == null ? "" : request.getParameter("referrer");
	String subject = request.getParameter("subject") == null ? "" : request.getParameter("subject");
	String content = request.getParameter("content") == null ? "" : request.getParameter("content");

	String result = checkAdmin(adminid, admintype, adminmenu, "0202");
	if (!result.equals("")) {
		response.getWriter().write(result);
		return;
	}

	if (Util.isEmpty(code) || Util.isEmpty(subject) || Util.isEmpty(content)) {
		result = "Error : 처리 조건을 입력하세요.";
	}
	else {
		AuditController auditApi = new AuditController();

		if (checkAdminCSRFToken(request)) {
			result = auditApi.setMailSend(adminid, code, referrer, subject, content);
		}
		else {
			result = "Error : 유효하지 않은 페이지입니다.\n\n해당 페이지를 다시 호출하세요.";
		}
	}

	response.getWriter().write(result);
%>