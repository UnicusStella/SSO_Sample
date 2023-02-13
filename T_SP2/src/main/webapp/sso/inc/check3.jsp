<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<%@ page import="com.dreamsecurity.sso.lib.dss.s2.core.AuthnRequest"%>
<%@ page import="com.dreamsecurity.sso.agent.config.*"%>
<%@ page import="com.dreamsecurity.sso.agent.provider.ServiceProvider"%>
<%@ page import="com.dreamsecurity.sso.agent.util.Util"%>
<%@ include file="../common.jsp"%>
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
<body onload="txtcls();return false;">
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
	String type = request.getParameter("type");
	String result = "";
	out.print(htmlMsg(boldTag("Provider Loader Test<br/>")));

	try {
		if (type.equals("SP")) {
			String ver = SSOConfig.getElementVersion();

			if (ver == null || ver.equals("")) {
				out.print(htmlMsg(boldTag("2. Magic SSO Version :&nbsp&nbsp<font color='red'>version get failure</font><br/>")));
			}
			else {
				out.print(htmlMsg(boldTag("2. Magic SSO Version :&nbsp&nbsp<font color='blue'>" + ver + "</font><br/>")));
			}

			out.print(htmlMsg(boldTag("3. com.dreamsecurity.sso.agent.provider.ServiceProvider Loding ...")));
			SSOConfig.setHomeDir(this.getServletConfig().getServletContext(), DEFAULT_SET_PATH);
			SSOInit.initialize();
			ServiceProvider sp = ServiceProvider.getInstance();

			if (sp instanceof com.dreamsecurity.sso.agent.provider.ServiceProvider) {
				out.print(htmlMsg("<font color='blue'>SUCCESS</font>", 1));
			}
			else {
				out.print(htmlMsg("<font color='red'>loding failure</font>", 1));
			}

			String str = null;
			int st = SSOConfig.getInstance().getAuthStatus();
			if (st == 0) {
				str = "<font color='blue'>Enable</font><br/>";
			}
			else {
				str = "<font color='red'>Disable</font><br/>";
			}

			out.print(htmlMsg(boldTag("4. Authentication Satus :&nbsp&nbsp" + str)));

			out.print(htmlMsg(boldTag("5. Make Sample Authentication Data ...")));
			AuthnRequest ar = sp.generateAuthRequest();
			String sampleTxt = Util.domToStr(ar.getDOM().getOwnerDocument(), false);

			if (sampleTxt == null) {
				throw new Exception("result Text is null");
			}

			out.print(htmlMsg("<font color='blue'>SUCCESS</font>", 1));
			sampleTxt = convTag(sampleTxt);
			out.print(htmlMsg("[ " + sampleTxt + " ]", 1));
		}
	}
	catch (Exception e) {
		e.printStackTrace();
		out.print(htmlMsg("<font color='red'>" + e.toString() + "</font>", 1));
	}
	finally {
		out.print(htmlMsg(boldTag("Test END")));
	}
%>
</body>
</html>