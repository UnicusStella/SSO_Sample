<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<%@ page import="java.util.*"%>
<%@ page import="com.dreamsecurity.sso.agent.config.*"%>
<%@ include file="../common.jsp"%>
<%
	SSOConfig.setHomeDir(this.getServletConfig().getServletContext(), DEFAULT_SET_PATH);
	SSOInit.initialize();

	String testdata = "PD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0iVVRGLTgiPz48c2FtbDJwOkF1dGhuUmVxdWVzdCB4bWxuczpzYW1sMnA9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDpwcm90b2NvbCIgQXNzZXJ0aW9uQ29uc3VtZXJTZXJ2aWNlVVJMPSJodHRwOi8vc3AxLmRldi5jb206NDAwMDQvc3NvL1Jlc3BvbnNlLmpzcCIgRGVzdGluYXRpb249Imh0dHA6Ly9pZHAuZGV2LmNvbTo0MDAwMS9zc28vUmVxdWVzdC5qc3AiIElEPSI1V3lXRUVzeUpXWEtYdUZuTzlxcnhsVXBZbnM9IiBJc3N1ZUluc3RhbnQ9IjIwMTMtMTEtMTRUMDE6Mzc6NDUuNTM1WiIgUHJvdmlkZXJOYW1lPSJURVNUX1NQMSIgVmVyc2lvbj0iMi4wIj48c2FtbDI6SXNzdWVyIHhtbG5zOnNhbWwyPSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6YXNzZXJ0aW9uIiBTUFByb3ZpZGVkSUQ9IlRFU1RfU1AxIj5URVNUX1NQMTwvc2FtbDI6SXNzdWVyPjxkczpTaWduYXR1cmUgeG1sbnM6ZHM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvMDkveG1sZHNpZyMiPg0KPGRzOlNpZ25lZEluZm8+DQo8ZHM6Q2Fub25pY2FsaXphdGlvbk1ldGhvZCBBbGdvcml0aG09Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvMTAveG1sLWV4Yy1jMTRuIyIvPg0KPGRzOlNpZ25hdHVyZU1ldGhvZCBBbGdvcml0aG09Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvMDkveG1sZHNpZyNyc2Etc2hhMSIvPg0KPGRzOlJlZmVyZW5jZSBVUkk9IiM1V3lXRUVzeUpXWEtYdUZuTzlxcnhsVXBZbnM9Ij4NCjxkczpUcmFuc2Zvcm1zPg0KPGRzOlRyYW5zZm9ybSBBbGdvcml0aG09Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvMDkveG1sZHNpZyNlbnZlbG9wZWQtc2lnbmF0dXJlIi8+DQo8ZHM6VHJhbnNmb3JtIEFsZ29yaXRobT0iaHR0cDovL3d3dy53My5vcmcvMjAwMS8xMC94bWwtZXhjLWMxNG4jIj48ZWM6SW5jbHVzaXZlTmFtZXNwYWNlcyB4bWxuczplYz0iaHR0cDovL3d3dy53My5vcmcvMjAwMS8xMC94bWwtZXhjLWMxNG4jIiBQcmVmaXhMaXN0PSJkcyBzYW1sMiBzYW1sMnAgeHMiLz48L2RzOlRyYW5zZm9ybT4NCjwvZHM6VHJhbnNmb3Jtcz4NCjxkczpEaWdlc3RNZXRob2QgQWxnb3JpdGhtPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwLzA5L3htbGRzaWcjc2hhMSIvPg0KPGRzOkRpZ2VzdFZhbHVlPm5vNDh3aGpuNGNqa3NnNkxsem9iZ0t4TXMzVT08L2RzOkRpZ2VzdFZhbHVlPg0KPC9kczpSZWZlcmVuY2U+DQo8ZHM6UmVmZXJlbmNlIFVSST0iIzVXeVdFRXN5SldYS1h1Rm5POXFyeGxVcFlucz0iPg0KPGRzOlRyYW5zZm9ybXM+DQo8ZHM6VHJhbnNmb3JtIEFsZ29yaXRobT0iaHR0cDovL3d3dy53My5vcmcvMjAwMC8wOS94bWxkc2lnI2VudmVsb3BlZC1zaWduYXR1cmUiLz4NCjxkczpUcmFuc2Zvcm0gQWxnb3JpdGhtPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxLzEwL3htbC1leGMtYzE0biMiPjxlYzpJbmNsdXNpdmVOYW1lc3BhY2VzIHhtbG5zOmVjPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxLzEwL3htbC1leGMtYzE0biMiIFByZWZpeExpc3Q9ImRzIHNhbWwyIHNhbWwycCB4cyIvPjwvZHM6VHJhbnNmb3JtPg0KPC9kczpUcmFuc2Zvcm1zPg0KPGRzOkRpZ2VzdE1ldGhvZCBBbGdvcml0aG09Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvMDkveG1sZHNpZyNzaGExIi8+DQo8ZHM6RGlnZXN0VmFsdWUvPg0KPC9kczpSZWZlcmVuY2U+DQo8L2RzOlNpZ25lZEluZm8+DQo8ZHM6U2lnbmF0dXJlVmFsdWU+QVFydGZ6SDJKL3RueXNjb1crRnhpYTZKN1JNMEVRc1h2QzJ0Nk1xcnE2bkRBUUd5Rm8zbG9WVFNjcU15UDRWeGJENitYN2tKdTRCeg0KdkZwM2xWb2s3WHlXTmhpWndNaE5SYVpKR3Z4SGE3ZjNSakxmcFpIM3E1RGNZTkVtenp5UkJ6ZGwrem54ZnlTRkJmVkVSSnRnenFMQw0KVVRlbTZYR040VEdRRUQwMjFYST08L2RzOlNpZ25hdHVyZVZhbHVlPg0KPGRzOktleUluZm8+PGRzOlg1MDlEYXRhPjxkczpYNTA5Q2VydGlmaWNhdGU+TUlJRDZEQ0NBMUdnQXdJQkFnSUVBaDh2Q1RBTkJna3Foa2lHOXcwQkFRVUZBREJJTVFzd0NRWURWUVFHRXdKcmNqRVFNQTRHQTFVRQ0KQ2hNSGVXVnpjMmxuYmpFVE1CRUdBMVVFQ3hNS1RHbGpaVzV6WldSRFFURVNNQkFHQTFVRUF4TUplV1Z6YzJsbmJrTkJNQjRYRFRBMA0KTVRBek1URTFNREF3TUZvWERUQTFNVEV3TVRFME5Ua3dNRm93YlRFTE1Ba0dBMVVFQmhNQ2EzSXhFREFPQmdOVkJBb1RCM2xsYzNOcA0KWjI0eEVUQVBCZ05WQkFzVENIQmxjbk52Ym1Gc01Rd3dDZ1lEVlFRTEV3TlRTRUl4S3pBcEJnTlZCQU1NSXUyVm5PeUluTzJZdUNncA0KTURBeU5qQXhNekl3TURRd05qSTFNREF3TURBNE5UQXdnWjh3RFFZSktvWklodmNOQVFFQkJRQURnWTBBTUlHSkFvR0JBTVVkZW5Gbg0KZi95S21yNEE3UEh2VnVoejlNQ0V1M3Evb1U2aVYzNnBiMXBZdFN1QWRCNGlZK1hveTc5MmV1bzdWeVNONUpMYUdKM1k3U3h3bkc4SQ0KNzhnZ1lvS280Z3RWSXBRL0VPMlAxVVY0RmxZNlJtWTRHUFJ1TXh4VnV1Z3UydE1teDc2cEJ2NGhRS0FlSzNrWWVueXpncFp2c1F1aQ0KNEZtdjkzZ1dLUVBMQWdNQkFBR2pnZ0c0TUlJQnREQWZCZ05WSFNNRUdEQVdnQlRpN0cwczVYMmJ3SjZzQVZONXVwcVBtb1haQ3pBZA0KQmdOVkhRNEVGZ1FVa0l0RzNYSUdhZTJoeXIxeDdRRFVOcDdMZnBJd0RnWURWUjBQQVFIL0JBUURBZ2JBTUhrR0ExVWRJQUVCL3dSdg0KTUcwd2F3WUpLb01hakpwRkFRRUJNRjR3TGdZSUt3WUJCUVVIQWdJd0loNGd4M1FBSU1kNHlaM0JITEtVQUNDczljZDR4M2pKbmNFYw0KQUNESGhiTElzdVF3TEFZSUt3WUJCUVVIQWdFV0lHaDBkSEE2THk5M2QzY3VlV1Z6YzJsbmJpNXZjaTVyY2k5amNITXVhSFJ0TUZnRw0KQTFVZEVRUlJNRStnVFFZSktvTWFqSnBFQ2dFQm9FQXdQZ3dKN1pXYzdJaWM3Wmk0TURFd0x3WUtLb01hakpwRUNnRUJBVEFoTUFjRw0KQlNzT0F3SWFvQllFRlBDMC8xL2Z0a09lTGNndEJxTUJ2MUtRelRyVE1GTUdBMVVkSHdSTU1Fb3dTS0JHb0VTR1FteGtZWEE2THk4eQ0KTURNdU1qTXpMamt4TGpNMU9qTTRPUzl2ZFQxa2NESndNVEU0Tmpjc2IzVTlUR2xqWlc1elpXUkRRU3h2UFhsbGMzTnBaMjRzWXoxcg0KY2pBNEJnZ3JCZ0VGQlFjQkFRUXNNQ293S0FZSUt3WUJCUVVITUFHR0hHaDBkSEE2THk5dlkzTndMbmxsYzNOcFoyNHViM0puT2pRMg0KTVRJd0RRWUpLb1pJaHZjTkFRRUZCUUFEZ1lFQWszN2c3WWU3dVQ5clpBeVlvMndRREk0L1hVb0xLVHVjNjAzT1dyM1VIR1UvVTh1aA0KU3JYcFhqWnFnMGhVVnV6MUZWK2ZOcmNHV2Z1Vnh3cjYrQVplRGtuMFNKMFo5a2o3bXprdHpYaFN2WlR6SzBtQVRSaGU5ZmR5V0lXSQ0KRTdGMTVlMjRnUDU4YkdMdC9EckNYOFVveXNIci8yZUVyM0pDT0NQL3AzUW9pdlE9PC9kczpYNTA5Q2VydGlmaWNhdGU+PC9kczpYNTA5RGF0YT48L2RzOktleUluZm8+PC9kczpTaWduYXR1cmU+PHNhbWwyOlN1YmplY3QgeG1sbnM6c2FtbDI9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDphc3NlcnRpb24iPjxzYW1sMjpOYW1lSUQgRm9ybWF0PSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6bmFtZWlkLWZvcm1hdDplbnRpdHkiPl9fRU1QVFlfSUQ8L3NhbWwyOk5hbWVJRD48c2FtbDI6U3ViamVjdENvbmZpcm1hdGlvbiBNZXRob2Q9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDpjbTpzZW5kZXItdm91Y2hlcyI+PHNhbWwyOlN1YmplY3RDb25maXJtYXRpb25EYXRhPjxkczpLZXlJbmZvIHhtbG5zOmRzPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwLzA5L3htbGRzaWcjIj48ZHM6S2V5VmFsdWU+PHhzOnN0cmluZyB4bWxuczp4cz0iaHR0cDovL3d3dy53My5vcmcvMjAwMS9YTUxTY2hlbWEiPmR1bW15PC94czpzdHJpbmc+PC9kczpLZXlWYWx1ZT48ZHM6S2V5VmFsdWU+PHhzOnN0cmluZyB4bWxuczp4cz0iaHR0cDovL3d3dy53My5vcmcvMjAwMS9YTUxTY2hlbWEiPnJaUmN1Q054eE1ac1EzTG1FWmZMZHovenBsWllqRHRzL0EzRGlESk1WYVR6czRWZXA2MFJRaXdSV21jTUJJaEw8L3hzOnN0cmluZz48L2RzOktleVZhbHVlPjxkczpLZXlWYWx1ZT48eHM6c3RyaW5nIHhtbG5zOnhzPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxL1hNTFNjaGVtYSI+ajF3SUY0aThRVjlCMHBySjVDYlh0UGZhK05lNW5IOGdTb2g0by93TFlrekhJQ0VaSVBDbUlkSmF4Mjk3K1o4ekNkcGlRNVRZRGl1NA0KVmFDYmN1ZzRidytZRjlxT3ZIM25pMm1mSi96alNpRUFaLzJiL3ArQ0Q2WmZyMFg1VUIvNjEyVzlIaDVqWkNXSGZJSE5NOU5wNmtaQw0KK3Fsc1ZnUmwxc0V6TzQzZit5RT08L3hzOnN0cmluZz48L2RzOktleVZhbHVlPjwvZHM6S2V5SW5mbz48L3NhbWwyOlN1YmplY3RDb25maXJtYXRpb25EYXRhPjwvc2FtbDI6U3ViamVjdENvbmZpcm1hdGlvbj48L3NhbWwyOlN1YmplY3Q+PHNhbWwycDpSZXF1ZXN0ZWRBdXRobkNvbnRleHQgQ29tcGFyaXNvbj0iZXhhY3QiIHhtbG5zOnNhbWwycD0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOnByb3RvY29sIj48c2FtbDI6QXV0aG5Db250ZXh0Q2xhc3NSZWYgeG1sbnM6c2FtbDI9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDphc3NlcnRpb24iPnVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDphYzpjbGFzc2VzOlBhc3N3b3JkPC9zYW1sMjpBdXRobkNvbnRleHRDbGFzc1JlZj48c2FtbDI6QXV0aG5Db250ZXh0Q2xhc3NSZWYgeG1sbnM6c2FtbDI9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDphc3NlcnRpb24iPnVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDphYzpjbGFzc2VzOlg1MDk8L3NhbWwyOkF1dGhuQ29udGV4dENsYXNzUmVmPjwvc2FtbDJwOlJlcXVlc3RlZEF1dGhuQ29udGV4dD48L3NhbWwycDpBdXRoblJlcXVlc3Q+";	
%>
<!DOCTYPE html>
<html>
<head>
<title>Magic SSO Agent Install Test</title>
<meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
<link rel="shortcut icon" href="../images/ds_tab.ico">

<style type="text/css">
#content { width:100%; min-width:1000px; }
#content table { width:100%; border:1px; }
#content table thead { text-align:center; background:#B3CDEE; }
#content table td { padding:.1em; border-right:1px solid #CCC; border-bottom:1px solid #CCC; }

form table { width:100%; border:1px; }
form table thead { text-align:center; background:#B3CDEE; }
form table td { padding:.1em; border-right:1px solid #CCC; border-bottom:1px solid #CCC; }

#headkey { width:250px; word-break:break-all;}
#headval { word-break:break-all;}
</style>
<script type="text/javascript">
	var flag = false;

	function showLayer()
	{
		if (!flag) {
			document.getElementById("sysinfo_lay").style.display = "block";
			document.getElementById("showLayer").value = "환경 정보 감추기";
		}
		else {
			document.getElementById("sysinfo_lay").style.display = "none";
			document.getElementById("showLayer").value = "환경 정보 보기";
		}

		flag = !flag;
	}

	function loadingTest()
	{
		var frm1 = document.getElementById("frmAgentTest");
		frm1.target = "ifSrv1";
		frm1.cmd.value = "LoaderTest";
		frm1.action = "check2.jsp";
		frm1.submit();

		document.getElementById("dumcon").innerHTML = "<font color=red>(waiting .....)</font>";

		var frm2 = document.getElementById("frmAgentTest");
		frm2.target = "ifSrv2";
		frm2.cmd.value = "";
		frm2.action = "check3.jsp";
		frm2.submit();
	}
</script>
</head>
<body>
	<div id="content">
		<h1 align="center">Magic SSO Agent Install Test : <%=SSOConfig.getInstance().getServerName()%></h1>
		<table>
			<thead>
				<tr>
					<td id='headkey'>Header Variable</td>
					<td id='headval'>Header Value</td>
				</tr>
			</thead>
			<tbody>
<%
	Enumeration eh = request.getHeaderNames();
	while (eh.hasMoreElements()) {
		String skey = (String) eh.nextElement();
		out.println("<tr>");
		out.println("<td id='headkey'>" + skey + "</td>");
		out.println("<td id='headval'>" + request.getHeader(skey) + "</td>");
		out.println("</tr>");
	}
%>
			</tbody>
		</table>
		<table>
			<thead>
				<tr>
					<td id='headkey'>Session Variable</td>
					<td id='headval'>Session Value</td>
				</tr>
			</thead>
			<tbody>
		    <tr>
				<td id='headkey'>SP Session</td>
				<td id='headval'><%=session.getId()%></td>
			</tr>
<%
	Enumeration em = session.getAttributeNames();
	while (em.hasMoreElements()) {
		String skey = (String) em.nextElement();
		out.println("<tr>");
		out.println("<td id='headkey'>" + skey + "</td>");
		out.println("<td id='headval'>" + session.getAttribute(skey) + "</td>");
		out.println("</tr>");
	}
%>
			</tbody>
		</table>
		<p>
		<form name="frmAgentTest" id="frmAgentTest" method="post" action="">
		<input type="hidden" name="SAMLRequest" value="<%=testdata%>"/>
		<input type="hidden" name="cmd" value=""/>
		<table>
			<thead>
				<tr>
					<td id='headkey'>Server Variable</td>
					<td id='headval'>Server Test</td>
				</tr>
			</thead>
			<tbody>
				<tr>
					<td id='headkey'>Java Version</td>
					<td id='headval'>
						<%=System.getProperty("java.version") %>
					</td>
				</tr>
				<tr>
					<td id='headkey'>Java Endorsed path</td>
					<td id='headval'>
						<%=System.getProperty("java.endorsed.dirs") %>
					</td>
				</tr>
				<tr>
					<td id='headkey'> Dream home path </td>
					<td id='headval'>
<%
try{
	out.print(System.getProperty("dreamsecurity.saml.path"));
}
catch(Exception e){
	out.print(e.toString());
}
%>		
					</td>
			    </tr>
				<tr>
					<td id='headkey'> Context Root </td>
					<td id='headval'>
<%
try{
	//out.print(this.getServletContext().getRealPath(""));
}
catch(Exception e){
	out.print(e.toString());
}
%>		
					</td>
			    </tr>
				<tr>
					<td id='headkey' valign="top">
						Server Type<br/>
						<input type="radio" name="type" value="SP" checked="checked">SP　
						<input type="button" id="loadingTestBt" name="loadingTestBt" value="class loading test" onclick="loadingTest(); return false;"/>
					</td>
					<td id='headval'>
						<div id="dumcon"></div>
						<iframe name="ifSrv1" id="ifSrv1" src="" scrolling="yes" frameborder="no" width="100%" height="200"></iframe>
						<iframe name="ifSrv2" id="ifSrv2" src="" scrolling="yes" frameborder="no" width="100%" height="400"></iframe>
					</td>
			    </tr>
			</tbody>
		</table>
		</form>

		<!-- System info-->
		<input type="button"  id="showLayer" name="showLayer" value="환경 정보 보기" style="width:200px; margin:0 0 0 2;" onclick="showLayer(); return false;"/>
		<div id="sysinfo_lay"  style="display: none;">
			<table>
				<thead>
					<tr>
						<td id='headkey'>System Variable</td>
						<td id='headval'>System Value</td>
					</tr>
				</thead>
				<tbody>
<%
	Enumeration es = System.getProperties().propertyNames();
	List keyList = new ArrayList();
	while (es.hasMoreElements()) {
		keyList.add(es.nextElement());
	}
	Collections.sort(keyList);
	for (int i = 0; i < keyList.size(); i++) {
		String skey = (String) keyList.get(i);
		out.println("<tr>");
		out.println("<td id='headkey'>" + skey + "</td>");
		out.println("<td id='headval'>" + System.getProperty(skey) + "</td>");
		out.println("</tr>");
	}
%>
				</tbody>
			</table>
		</div>
	</div>
</body>
</html>