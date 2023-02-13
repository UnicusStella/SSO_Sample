<%@ page language="java" contentType="text/html; charset=utf-8"  pageEncoding="utf-8"%>
<%@ page import="com.dreamsecurity.sso.server.api.audit.AuditController"%>
<%@ page import="com.dreamsecurity.sso.server.util.Util"%>
<%@ include file="./subCommon.jsp"%>
<%
	String spage = request.getParameter("spage") == null ? "1" : request.getParameter("spage");
	String pagerow = request.getParameter("pagerow") == null ? "" : request.getParameter("pagerow");
	String result = "";

	if (Util.isEmpty(spage) || Util.isEmpty(pagerow) ) {
		result = "Error : 처리 조건을 입력하세요.";
	}
	else {
		int fnum = 1;
		int tnum = 10000;

		if (!spage.equals("A")) {
			int nPage = Integer.parseInt(spage);
			fnum = (nPage - 1) * Integer.parseInt(pagerow) + 1;
			tnum = nPage * Integer.parseInt(pagerow);
		}

		AuditController auditApi = new AuditController();
		result = auditApi.getServerList(fnum, tnum);
	}

	response.getWriter().write(result);
%>