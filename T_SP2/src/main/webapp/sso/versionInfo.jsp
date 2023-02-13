<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<%@ page import="com.dreamsecurity.sso.agent.config.*"%>
<%@ include file="./common.jsp"%>
<%
	SSOConfig.setHomeDir(this.getServletConfig().getServletContext(), DEFAULT_SET_PATH);
	SSOInit.initialize();
%>
<!DOCTYPE html>
<html>
<head>
<title>Magic SSO Version</title>
<meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
<style type="text/css">
#content { width:100%; }
#content table { width:100%; border:1px; }
#content table thead { text-align:center; background:#B3CDEE; }
#content table td { padding:.1em; border-right:1px solid #CCC; border-bottom:1px solid #CCC; }
form table { width:50%; border:1px; }
form table thead { text-align:center; background:#B3CDEE; }
form table td { padding:.1em; border-right:1px solid #CCC; border-bottom:1px solid #CCC; }
</style>
</head>
<body onload="">
	<h1 align="center">Magic SSO Version Agent - <%=XSSCheck(SSOConfig.getInstance().getServerName())%></h1>
	<div id="content">
		<table>
			<thead>
				<tr>
					<td width="20%">Variable</td>
					<td>Value</td>
				</tr>
			</thead>
			<tbody>
				<tr>
					<td>&nbsp;&nbsp;제품명</td>
					<td>&nbsp;&nbsp;<%=XSSCheck(SSOConfig.getTOE())%></td>
				</tr>
				<tr>
					<td>&nbsp;&nbsp;버전</td>
					<td>&nbsp;&nbsp;<%=XSSCheck(SSOConfig.getDetailVersion())%></td>
				</tr>
				<tr>
					<td>&nbsp;&nbsp;구성요소</td>
					<td>&nbsp;&nbsp;<%=XSSCheck(SSOConfig.getElementVersion())%></td>
				</tr>
			</tbody>
		</table>
	</div>
</body>
</html>