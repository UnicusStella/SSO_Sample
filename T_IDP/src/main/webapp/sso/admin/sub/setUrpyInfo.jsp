<%@ page language="java" contentType="text/html; charset=utf-8"  pageEncoding="utf-8"%>
<%@ page import="com.dreamsecurity.sso.server.api.admin.AdminController"%>
<%@ page import="com.dreamsecurity.sso.server.util.Util"%>
<%@ include file="./subCommon.jsp"%>
<%@ include file="./checkAdmin.jsp"%>
<%
	String ucode = request.getParameter("urpycode") == null ? "" : request.getParameter("urpycode");
	String pwcnt = request.getParameter("pwcnt") == null ? "" : request.getParameter("pwcnt");
	String pwwarn = request.getParameter("pwwarn") == null ? "" : request.getParameter("pwwarn");
	String pwvalid = request.getParameter("pwvalid") == null ? "" : request.getParameter("pwvalid");
	String polltime = request.getParameter("polltime") == null ? "" : request.getParameter("polltime");
	String sesstime = request.getParameter("sesstime") == null ? "" : request.getParameter("sesstime");

	String result = checkAdmin(adminid, admintype, adminmenu, "0301");
	if (!result.equals("")) {
		response.getWriter().write(result);
		return;
	}

	if (Util.isEmpty(ucode) || Util.isEmpty(pwcnt) || Util.isEmpty(pwwarn) ||
			Util.isEmpty(pwvalid) || Util.isEmpty(polltime) || Util.isEmpty(sesstime)) {
		result = "Error : 처리 조건을 입력하세요.";
	}
	else {
		AdminController adminApi = new AdminController();

		if (checkAdminCSRFToken(request)) {
			result = adminApi.setUrpyInfo(adminid, ucode, pwcnt, pwwarn, pwvalid, polltime, sesstime);
		}
		else {
			result = "Error : 유효하지 않은 페이지입니다.\n\n해당 페이지를 다시 호출하세요.";
		}

// 		if (result.indexOf("Error :") == -1)
// 			MemConfig.getInstance().setDupLoginType(duptype);
	}

	response.getWriter().write(result);
%>