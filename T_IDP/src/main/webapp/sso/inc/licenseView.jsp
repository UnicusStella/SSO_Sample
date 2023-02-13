<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<%@ page import="java.util.*"%>
<%@ page import="java.util.Map.Entry"%>
<%@ page import="com.dreamsecurity.sso.server.config.SSOConfig"%>
<%@ page import="com.dreamsecurity.sso.server.provider.EnvironInform"%>
<%@ page import="com.dreamsecurity.sso.server.session.SessionManager" %>
<%@ include file="../common.jsp"%>
<%
	SSOConfig.setHomeDir(this.getServletConfig().getServletContext(), DEFAULT_SET_PATH);
	String lic_path = SSOConfig.getInstance().getHomePath() + "/license";

	EnvironInform environ = EnvironInform.getInstance();
	environ.licenseInit();

	Map<String, String> licMap = (Map<String, String>) SessionManager.getInstance().getLicenseMap();
	Iterator<Map.Entry<String, String>> iterator = licMap.entrySet().iterator();

	List<Object> list = new ArrayList<Object>();

	while (iterator.hasNext()) {
		Entry<String, String> entry = (Entry<String, String>) iterator.next();
		String nameId = (String) entry.getKey();

		Map<String, String> obj =  new HashMap<String, String>();
		obj.put("server", nameId);

		String status = (String) entry.getValue();

		if (status.length() == 1) {
			obj.put("ip", "");

			if ("N".equalsIgnoreCase(status))
				obj.put("status", "정상");
			else if ("A".equalsIgnoreCase(status))
				obj.put("status", "서명 검증 오류");
			else if ("B".equalsIgnoreCase(status))
				obj.put("status", "정보 추출 오류");
			else if ("C".equalsIgnoreCase(status))
				obj.put("status", "버전 오류");
			else if ("D".equalsIgnoreCase(status))
				obj.put("status", "소프트웨어 오류");
			else if ("E".equalsIgnoreCase(status))
				obj.put("status", "만료된 라이센스");
			else if ("F".equalsIgnoreCase(status))
				obj.put("status", "도메인 불일치");
			else if ("G".equalsIgnoreCase(status))
				obj.put("status", "서버 정보 없음");
			else if ("H".equalsIgnoreCase(status))
				obj.put("status", "IP 정보 오류");
			else
				obj.put("status", "알 수 없는 오류");
		}
		else if (status.length() > 1)
			obj.put("ip", status);
		else
			obj.put("ip", "Error");

		String validate = environ.getLicenseInfo(nameId, 6);
		String domain = "";

		//if (validate.equals(""))
		//	domain = environ.getLicenseInfo(nameId, 7);

		obj.put("validate", validate);
		obj.put("domain", domain);

		if (validate.equals("Error")) {
			obj.put("type", "오류");
		}
		else {
			if (validate.equals("")) {
				if ((status.length() > 1 && domain.length() > 0) || (status.length() == 1 && domain.length() == 0))
					obj.put("type", "오류");
				else
					obj.put("type", "정식");
			}
			else {
				obj.put("type", "임시");
			}
		}
		
		list.add(obj);
	}
%>
<!DOCTYPE html>
<html>
<head>
<title>Magic SSO Server License</title>
<meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
<style type="text/css">
#content { width:100%; min-width:1000px; }
#content table { width:100%; border:1px; }
#content table thead { text-align:center; background:#B3CDEE; }
#content table td { padding:.1em; border-right:1px solid #CCC; border-bottom:1px solid #CCC; word-break:break-all; }
</style>
</head>
<body>
	<div id="content">
		<h1 align="center">Magic SSO Server License</h1>
		<div>&nbsp;License Path:&nbsp;<%=lic_path%></div>
		<table>
			<thead>
				<tr>
					<td width="17%">Server</td>
					<td width="6%">Type</td>
					<td width="25%">Domain</td>
					<td width="25%">IP</td>
					<td width="12%">Expire Date</td>
					<td width="15%">Status</td>
				</tr>
			</thead>
			<tbody>
				<%
					Iterator<?> itr = list.iterator();
					while (itr.hasNext()) {
						Map<String, String> dataMap = (Map<String, String>) itr.next();
						out.println("<tr>");
						out.println("<td>" + dataMap.get("server") + "</td>");

						if ("정식".equals(dataMap.get("type")))
							out.println("<td style='text-align:center; font-weight:bold; color:#00f;'>" + dataMap.get("type") + "</td>");
						else if ("임시".equals(dataMap.get("type")))
							out.println("<td style='text-align:center;'>" + dataMap.get("type") + "</td>");
						else
							out.println("<td style='text-align:center; font-weight:bold; color:#f00;'>" + dataMap.get("type") + "</td>");

						out.println("<td style='text-align:center;'>" + dataMap.get("domain") + "</td>");
						out.println("<td style='text-align:center;'>" + dataMap.get("ip") + "</td>");
						out.println("<td style='text-align:center;'>" + dataMap.get("validate") + "</td>");

						if ("정상".equals(dataMap.get("status")))
							out.println("<td style='text-align:center;'>" + dataMap.get("status") + "</td>");
						else
							out.println("<td style='text-align:center; font-weight:bold; color:#f00;'>" + dataMap.get("status") + "</td>");

						out.println("</tr>");
					}
				%>
			</tbody>
		</table>
	</div>
</body>
</html>