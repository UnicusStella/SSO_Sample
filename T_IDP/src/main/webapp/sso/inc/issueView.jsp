<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<%@ page import="java.util.*"%>
<%@ page import="java.util.Map.*"%>
<%@ page import="com.dreamsecurity.sso.lib.jtm.DateTime"%>
<%@ page import="com.dreamsecurity.sso.server.session.*"%>
<%
	String gubun = request.getParameter("gubun") == null ? "1" : (String) request.getParameter("gubun");
	String authCode = "";
	String userId = "";
	String deviceId = "";

	if (gubun.equals("1")) {
		authCode = request.getParameter("authcode") == null ? "" : (String) request.getParameter("authcode");
	}
	else if (gubun.equals("2")) {
		userId = request.getParameter("userid") == null ? "" : (String) request.getParameter("userid");
	}
	else if (gubun.equals("3")) {
		deviceId = request.getParameter("deviceid") == null ? "" : (String) request.getParameter("deviceid");
	}
%>
<!DOCTYPE html PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd">
<html>
<head>
<meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
<title></title>
<script type="text/javascript">
function search(gubun)
{
	document.ssoSearchForm.gubun.value = gubun;
	document.ssoSearchForm.action = "./issueView.jsp";
	document.ssoSearchForm.submit();
}
</script>
</head>
<body>
<form name="ssoSearchForm" method="post">
	<br>
	<input type="hidden" name="gubun" value="1"/>
	authCode&nbsp;&nbsp;=&nbsp;&nbsp;<input type='text' name='authcode' style='width:500px; height:18px; margin-bottom:10px; padding-left:3px;' size='20' value='<%=authCode%>'/>&nbsp;
	<input type='button' value='조 회' onClick='search(1);'>
	<br>
	userId&nbsp;&nbsp;=&nbsp;&nbsp;<input type='text' name='userid' style='width:200px; height:18px; margin-bottom:10px; padding-left:3px;' size='20' value='<%=userId%>'/>&nbsp;
	<input type='button' value='조 회' onClick='search(2);'>
	<br>
	deviceId&nbsp;&nbsp;=&nbsp;&nbsp;<input type='text' name='deviceid' style='width:500px; height:18px; margin-bottom:10px; padding-left:3px;' size='20' value='<%=deviceId%>'/>&nbsp;
	<input type='button' value='조 회' onClick='search(3);'>
	<br>
	<input type='button' value='맵 초기화' onClick='search(4);'>
	<input type='button' value='맵 정리' onClick='search(5);'>
	<br>
</form>
<%
	String tab = "&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;";

	Map authcodeMap = SessionManager.getInstance().getAuthcodeMap();

	if (gubun.equals("4")) {
		authcodeMap.clear();
	}
	else if (gubun.equals("5")) {
		Iterator iterator = authcodeMap.keySet().iterator();

		while(iterator.hasNext()) {
			String authcode = (String) iterator.next();
			AuthnIssue issue = (AuthnIssue) authcodeMap.get(authcode);

			DateTime validTime = issue.getIssueTime().plusHours(24);
			DateTime curTime = new DateTime();

			if (validTime.compareTo(curTime) < 0) {
				authcodeMap.remove(authcode);
			}
		}
	}

	out.println("<br>Authcode_map Size = " + authcodeMap.size() + "<br>");

	if (gubun.equals("1") && !authCode.equals("")) {
		AuthnIssue authnIssue =
				authcodeMap.get(authCode) == null ? null : (AuthnIssue) authcodeMap.get(authCode);

		if (authnIssue != null) {
			out.println("<br>Authcode_map<br>");
			out.println(tab + "key (authCode) = " + authCode + "<br>");
			out.println(tab + "value (AuthnIssue) = <br>");
			out.println(tab + tab + "userId = " + authnIssue.getUserId() + "<br>");
			out.println(tab + tab + "providerName = " + authnIssue.getProviderName() + "<br>");
			out.println(tab + tab + "deviceId = " + authnIssue.getDeviceId() + "<br>");
			out.println(tab + tab + "blockId = " + authnIssue.getBlockId() + "<br>");
			out.println(tab + tab + "authnInfo = " + authnIssue.getAuthnInfo().substring(0, 64) + ".....<br>");
			out.println(tab + tab + "issueTime = " + authnIssue.getIssueTime() + "<br>");
		}
		else {
			return;
		}
	}
	else if (gubun.equals("2") && !userId.equals("")) {
		Iterator iterator = authcodeMap.keySet().iterator();

		int ii = 1;
		while(iterator.hasNext()) {
			String code = (String) iterator.next();
			AuthnIssue authnIssue = (AuthnIssue) authcodeMap.get(code);

			if (userId.equals(authnIssue.getUserId())) {
				out.println("<br>Authcode_map [" + ii + "]<br>");
				out.println(tab + "key (authCode) = " + code + "<br>");
				out.println(tab + "value (AuthnIssue) = <br>");
				out.println(tab + tab + "userId = " + authnIssue.getUserId() + "<br>");
				out.println(tab + tab + "providerName = " + authnIssue.getProviderName() + "<br>");
				out.println(tab + tab + "deviceId = " + authnIssue.getDeviceId() + "<br>");
				out.println(tab + tab + "blockId = " + authnIssue.getBlockId() + "<br>");
				out.println(tab + tab + "authnInfo = " + authnIssue.getAuthnInfo().substring(0, 64) + ".....<br>");
				out.println(tab + tab + "issueTime = " + authnIssue.getIssueTime() + "<br>");
				ii++;
			}
        }
	}
	else if (gubun.equals("3") && !deviceId.equals("")) {
		Iterator iterator = authcodeMap.keySet().iterator();

		int ii = 1;
		while(iterator.hasNext()) {
			String code = (String) iterator.next();
			AuthnIssue authnIssue = (AuthnIssue) authcodeMap.get(code);

			if (deviceId.equals(authnIssue.getDeviceId())) {
				out.println("<br>Authcode_map [" + ii + "]<br>");
				out.println(tab + "key (authCode) = " + code + "<br>");
				out.println(tab + "value (AuthnIssue) = <br>");
				out.println(tab + tab + "userId = " + authnIssue.getUserId() + "<br>");
				out.println(tab + tab + "providerName = " + authnIssue.getProviderName() + "<br>");
				out.println(tab + tab + "deviceId = " + authnIssue.getDeviceId() + "<br>");
				out.println(tab + tab + "blockId = " + authnIssue.getBlockId() + "<br>");
				out.println(tab + tab + "authnInfo = " + authnIssue.getAuthnInfo().substring(0, 64) + ".....<br>");
				out.println(tab + tab + "issueTime = " + authnIssue.getIssueTime() + "<br>");
				ii++;
			}
        }
	}
%>
</body>
</html>