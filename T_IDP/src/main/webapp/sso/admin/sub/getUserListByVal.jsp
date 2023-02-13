<%@ page language="java" contentType="text/html; charset=utf-8"  pageEncoding="utf-8"%>
<%@ page import="com.dreamsecurity.sso.server.api.admin.AdminController"%>
<%@ page import="com.dreamsecurity.sso.server.util.Util"%>
<%@ include file="./subCommon.jsp"%>
<%
	String sType = request.getParameter("stype") == null ? "" : request.getParameter("stype");
	String sValue = request.getParameter("svalue") == null ? "" : request.getParameter("svalue");
	String spage = request.getParameter("spage") == null ? "" : request.getParameter("spage");
	String pagerow = request.getParameter("pagerow") == null ? "" : request.getParameter("pagerow");
	String result = "";

	if (Util.isEmpty(spage) || Util.isEmpty(pagerow)) {
		result = "Error : 처리 조건을 입력하세요.";
	}
	else {
		int nPage = Integer.parseInt(spage);
		int fnum = (nPage - 1) * Integer.parseInt(pagerow) + 1;
		int tnum = nPage * Integer.parseInt(pagerow);

		AdminController adminApi = new AdminController();
		result = adminApi.getUserListByVal(sType, sValue, fnum, tnum);
	}

	response.getWriter().write(result);
%>