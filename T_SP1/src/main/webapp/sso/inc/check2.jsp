<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<%@ page import="java.net.URL"%>
<html>
<head>
<meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
<script type="text/javascript">
	function txtcls()
	{
		parent.document.getElementById("dumcon").innerText = "";
	}
</script>
</head>
<body onload="txtcls(); return false;">
<%!
	String tab = "&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp";
	String rn = "<br/>";

	public String htmlMsg(String msg)
	{
		return htmlMsg(msg, 0);
	}

	public String htmlMsg(String msg, int type)
	{
		msg = msg + rn;
		if (type == 1)
			return tab + msg + rn;
		return msg;
	}

	public String convTag(String msg)
	{
		msg = msg.replaceAll("<", "&lt;");
		msg = msg.replaceAll(">", "&gt;");
		return msg;
	}

	public String boldTag(String msg)
	{
		msg = "<b>" + msg + "</b>";
		return msg;
	}
%>
<%
	String cmd = request.getParameter("cmd");

	if (cmd.equals("LoaderTest")) {
		out.print(htmlMsg(boldTag("Class Loader Test<br/>")));
		out.print(htmlMsg(boldTag("1. com.dreamsecurity.sso.agent.config.LoaderTest Find ...")));
		String reqName = "com.dreamsecurity.sso.agent.config.LoaderTest";

		try {
			URL classUrl = this.getClass().getResource("/com/dreamsecurity/sso/agent/config/LoaderTest.class");

			if (classUrl == null) {
				out.print(htmlMsg("<font color='red'>" + reqName + " not found.</font>", 1));
			}
			else {
				out.print(htmlMsg("<font color='blue'>SUCCESS</font>", 1));
				out.print(htmlMsg("[ " + classUrl.getFile() + " ]", 1));
			}
		}
		catch (Exception e) {
			out.print(htmlMsg("<font color='red'>" + e.toString() + "</font>", 1));
		}
	}
%>
</body>
</html>