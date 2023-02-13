<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<%
	String ecode = request.getParameter("ecode") == null ? "" : request.getParameter("ecode");
	String emessage = request.getParameter("emessage") == null ? "" : request.getParameter("emessage");
	String nexturl = request.getParameter("nexturl") == null ? "" : request.getParameter("nexturl");
%>
<html>
<head>
<title>MagicSSO Error Page</title>
</head>
<script type="text/javascript">
    var code = "<%=ecode%>";
    var message = "<%=emessage%>";

 	if (message == '') {
 		alert_msg = ' ' + code;
 	}
 	else {
 		alert_msg = ' ' + message + " (" + code + ")";
 	}

 	alert(alert_msg);
    location.href = "<%=nexturl%>"
</script>
</html>