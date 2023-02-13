<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<%@ page session="true"%>
<%@ page import="com.dreamsecurity.sso.agent.config.SSOConfig"%>
<%@ include file="/sso/common.jsp"%>
<%
	String spname = SSOConfig.getInstance().getServerName();

	String polling_time = (String) session.getAttribute("POLLING_TIME");

	if (polling_time != null && !"0".equals(polling_time)) {
		polling_time = polling_time + "000";
	}
	else {
		polling_time = "0";
	}
%>
<!DOCTYPE html>
<html lang="ko">
<head>
	<title><%=XSSCheck(spname)%></title>

	<meta charset="utf-8"/>
	<meta http-equiv="Content-Style-Type" content="text/css"/>
	<meta http-equiv="X-UA-Compatible" content="IE=edge"/>

	<link rel="shortcut icon" href="./images/ds_tab.ico"/>
	<script src="/sso/js/magicsso.js" type="text/javascript"></script>
	<script src="./js/jquery-3.4.1.min.js" type="text/javascript"></script>
	<link href="./css/sso-main.css" rel="stylesheet" type="text/css"/>

<script type="text/javascript">
</script>
</head>
<body onload="checkDup();">
	<div>
		<input type="hidden" id="userid" value=""/>

		<header class="header">
			<nav class="navbar">
				<div class="site-logo"></div>
				<div class="sidebar-toggle-box" title="메뉴 토글"></div>
				<div class="main-title">Magic SSO Agent &nbsp;<span class="sub-title"><%=XSSCheck(spname)%></span></div>
				<div class="user-info">
					<img class="user-photo" src="./images/photo_default.png"/>
					<span class="user-name"></span>
					<div class="user-seperate"></div>
					<div class="user-logout" title="로그아웃"></div>
				</div>
			</nav>
		</header>
		<div class="d-flex">
			<div class="sidebar">
				<ul class="menu">
					<li class="menu-item">
						<span id="menu-rept">
							<img class="menu-icon" src="./images/icon_rept_off.png"/>
							<a href="#">SSO Agent</a>
						</span>
						<ul class="sub-menu">
							<li id="menu-rept1">&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;로그온 세션</li>
							<li id="menu-conn1">&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;SSO 연계</li>
						</ul>
					</li>
			    </ul>
			</div>
			<div class="contents" id="contents">
				<iframe src="" id="mainFrm" name="mainFrm" width="100%" height="100%" frameborder="0" scrolling="no"></iframe>
				<iframe name="ssoiframe" width="0" height="0" frameborder="0" scrolling="no" style="visibility:hidden;"></iframe>
			</div>
		</div>
	</div>

	<form id="menuForm" method="post"></form>
	<form name="ssoCheckDupForm" method="post" action="" target="ssoiframe"></form>

	<script type="text/javascript">
	var sidebar = true;

	$(document).ready(function(){
		var uid = MagicSSO.getID();
		var uname = MagicSSO.getProperty("NAME");

		$('.sub-menu').css('display', 'none');

		$('ul.menu').on('click', '.menu-item>span', function() {
			if (uid != null && uid != "") {
				$(this).parent().children('.sub-menu').stop('true','true').slideToggle('fast');
			}
		});

		$('ul.sub-menu').on('click', 'li', function() {
			if (uid != null && uid != "") {
				$('ul.sub-menu li.on').toggleClass('on');
				$(this).toggleClass('on');
			}
		});

		$('.sidebar-toggle-box').on('click', function () {
			if (sidebar) {
				$('.sidebar').stop().animate({'left' : '-200px'}, 300);
				$('.sidebar').addClass('sidebar-hide');
				sidebar = false;
			}
			else {
				$('.sidebar').stop().animate({'left' : '0px'}, {'complete' : function() {}}, 300);
				$('.sidebar').removeClass('sidebar-hide');
				sidebar = true;
			}
		});

		if (uid == null || uid == "") {
			menuForm.action = "<%=XSSCheck(DEFAULT_BASE_URL)%>";
			menuForm.target = "_self";
			menuForm.submit();
		}
		else {
			$('#userid').val(uid);
			$('.user-name').text(uname);
		}

		$("#menu-rept").parent().children('.sub-menu').stop('true','true').slideToggle('fast');
		$("#menu-rept1").toggleClass('on');

		goDirectMenu("logonInfo.jsp");
	});

	$(".user-logout").click(function() {
		if ($('#userid').val() == null || $('#userid').val() == "") {
			return;
		}

		if (!MagicSSO.isLogon()) {
			location.href = "<%=XSSCheck(DEFAULT_BASE_URL)%>";
		}

		if (!confirm(" 로그아웃 하시겠습니까?")) {
			return;
		}

		location.href = "/sso/Logout.jsp?slo=y";
	});

	$("#menu-conn1").click(function() {
		if (MagicSSO.isLogon()) {
			goDirectMenu("connect.jsp");
		}
		else {
			location.href = "<%=XSSCheck(DEFAULT_BASE_URL)%>";
		}
	});

	$("#menu-rept1").click(function() {
		if (MagicSSO.isLogon()) {
			goDirectMenu("logonInfo.jsp");
		}
		else {
			location.href = "<%=XSSCheck(DEFAULT_BASE_URL)%>";
		}
	});

	function goDirectMenu(url)
	{
		menuForm.action = url;
		menuForm.target = "mainFrm";
		menuForm.submit();
	}

	function checkDup()
	{
		if (!MagicSSO.isLogon()) {
			location.href = "<%=XSSCheck(DEFAULT_BASE_URL)%>";
			return;
		}

		var cycle = <%=XSSCheck(polling_time)%>;
		if (cycle > 0)
		{
			document.ssoCheckDupForm.action = "/sso/checkDupLogin.jsp";
			document.ssoCheckDupForm.submit();

			setTimeout("checkDup()", cycle);
		}
	}
	</script>
</body>
</html>