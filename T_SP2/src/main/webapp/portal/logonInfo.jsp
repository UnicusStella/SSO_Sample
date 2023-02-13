<%@ page language="java" contentType="text/html; charset=utf-8" pageEncoding="utf-8"%>
<%@ page import="com.dreamsecurity.sso.agent.util.Util"%>

<!DOCTYPE html>
<html lang="ko">
<head>
	<meta charset="utf-8"/>
	<meta http-equiv="Content-Style-Type" content="text/css"/>
	<meta http-equiv="X-UA-Compatible" content="IE=edge"/>

	<script src="./js/jquery-3.4.1.min.js" type="text/javascript"></script>
	<link href="./css/sso-common.css?v=1" rel="stylesheet" type="text/css"/>
	<link href="./css/sso-logoninfo.css?v=3" rel="stylesheet" type="text/css"/>
</head>
<body>
	<div class="page-holder">
		<div class="page-breadcrumb">
			HOME / SSO Agent / 로그온 세션
		</div>
		<div class="page-header">
			<h4 class="title">로그온 세션</h4>
		</div>

		<div class="content-box">
			<div class="content-body">
			<table>
				<tr>
					<td id="headkey">Host</td><td id="headval"><%=request.getHeader("host")%></td>
				</tr>
				<tr>
					<td id="headkey">IDP_Session</td><td id="headval"><%=session.getAttribute("IDP_Session")%></td>
				</tr>
				<tr>
					<td id="headkey">SP_Session</td><td id="headval"><%=session.getId()%></td>
				</tr>
				<tr>
					<td id="headkey">SP_Server_IP</td><td id="headval"><%=Util.getServerIP()%></td>
				</tr>
				<tr>
					<td id="headkey">SSO_ID</td><td id="headval"><%=session.getAttribute("SSO_ID")%></td>
				</tr>
				<tr>
					<td id="headkey">_TOKEN</td><td id="headval"><%=session.getAttribute("_TOKEN")%></td>
				</tr>
				<tr>
					<td id="headkey">SSO_SESSTIME</td><td id="headval"><%=session.getAttribute("SSO_SESSTIME")%></td>
				</tr>
				<tr>
					<td id="headkey">SSO_INACTIVE</td><td id="headval"><%=session.getAttribute("SSO_INACTIVE")%></td>
				</tr>
				<tr>
					<td id="headkey_last">POLLING_TIME</td><td id="headval_last"><%=session.getAttribute("POLLING_TIME")%></td>
				</tr>
			</table>
			</div>
		</div>
	</div>
</body>
</html>