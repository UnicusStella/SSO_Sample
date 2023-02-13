<%@ page language="java" contentType="text/html; charset=utf-8" pageEncoding="utf-8"%>
<%@ page session="true"%>
<%@ include file="adminCommon.jsp"%>
<%@ include file="sub/checkAdmin.jsp"%>
<%
	SSOConfig ssoconfig = SSOConfig.getInstance();
	int CHANGEUPWENABLE = ssoconfig.getInt("admin.changeupw.enable", 0);
%>
<script type="text/javascript">
	if ("<%=XSSCheck(adminid)%>" == "") { top.location.href = "<%=XSSCheck(LOGIN_PAGE)%>"; }
</script>

<!DOCTYPE html>
<html lang="ko">
<head>
	<title>Magic SSO Admin</title>

	<meta charset="utf-8"/>
	<meta http-equiv="Content-Style-Type" content="text/css"/>
	<meta http-equiv="X-UA-Compatible" content="IE=Edge"/>

	<link rel="shortcut icon" href="/sso/admin/images/ds_tab.ico"/>
	<script src="./js/jquery-3.4.1.min.js" type="text/javascript"></script>
	<link href="./css/sso-main.css" rel="stylesheet" type="text/css"/>
</head>
<body>
	<div>
		<input type="hidden" id="adminid" value="<%=XSSCheck(adminid)%>"/>
		<input type="hidden" id="adminidp" value="<%=XSSCheck(adminid)%>"/>
		<input type="hidden" id="adminname" value="<%=XSSCheck(adminname)%>"/>
		<input type="hidden" id="admintype" value="<%=XSSCheck(admintype)%>"/>
		<input type="hidden" id="adminmenu" value="<%=XSSCheck(adminmenu)%>"/>
		<input type="hidden" id="adminfirst" value="<%=XSSCheck(adminfirst)%>"/>
		<input type="hidden" id="adminidle" value="<%=XSSCheck(adminidle)%>"/>

		<header class="header">
			<nav class="navbar">
				<div class="site-logo"></div>
				<div class="sidebar-toggle-box" title="메뉴 토글">≡</div>
				<div class="main-title">Magic SSO &nbsp;<span class="sub-title">Admin</span></div>
				<div class="admin-info">
					<img class="admin-photo" src="./images/photo_default.png"/>
					<span class="admin-name"></span>
					<div class="admin-seperate"></div>
					<div class="admin-logout" title="로그아웃"></div>
				</div>
			</nav>
		</header>
		<div class="d-flex">
			<div class="sidebar">
				<ul class="menu">
					<li class="menu-item">
						<span id="menu-rept">
							<img class="menu-icon" src="./images/icon_rept_off.png"/>
							<a href="#">감사 정보</a>
						</span>
						<ul class="sub-menu">
							<li id="0101">&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;감사 정보 조회</li>
							<li id="0104">&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;접속 정보 조회</li>
							<li id="0105">&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;접속 정보 통계</li>
							<li id="0102">&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;실시간 모듈 검증</li>
							<li id="0103">&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;서버 모니터링</li>
						</ul>
					</li>
					<li class="menu-item">
						<span>
							<img class="menu-icon" src="./images/icon_optn_off.png"/>
							<a href="#">감사 정책</a>
						</span>
						<ul class="sub-menu">
							<li id="0201">&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;감사 정책</li>
							<li id="0202">&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;메일 통보 설정</li>
						</ul>
					</li>
					<li class="menu-item">
						<span>
							<img class="menu-icon" src="./images/icon_user_off.png"/>
							<a href="#">사용자</a>
						</span>
						<ul class="sub-menu">
							<li id="0301">&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;사용자 정책</li>
							<li id="0302">&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;사용자 잠김 해제</li>
							<li id="0303">&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;사용자 강제 로그아웃</li>
							<%
							if (CHANGEUPWENABLE == 1) {
							%>
							<li id="0304">&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;사용자 비밀번호 변경</li>
							<%
							}
							%>
						</ul>
					</li>
					<li class="menu-item">
						<span id="menu-admin">
							<img class="menu-icon" src="./images/icon_adpy_off.png"/>
							<a href="#">관리자</a>
						</span>
						<ul class="sub-menu">
							<li id="0401">&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;관리자 관리</li>
							<li id="0402">&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;관리자 정책</li>
							<li id="0403">&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;비밀번호 변경</li>
							<li id="0404">&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;제품 버전 정보</li>
						</ul>
					</li>
					<li class="menu-item">
						<span>
							<img class="menu-icon" src="./images/icon_oidc_off.png"/>
							<a href="#">클라이언트</a>
						</span>
						<ul class="sub-menu">
							<li id="0501">&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;클라이언트 관리</li>
							<li id="0502">&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Scope 관리</li>
						</ul>
					</li>
			    </ul>
			</div>
			<div class="contents" id="contents">
				<iframe src="" id="mainFrm" name="mainFrm" width="100%" height="100%" frameborder="0" scrolling="no"></iframe>
			</div>
		</div>
	</div>
	<form method="post" id="menuForm"></form>

	<script type="text/javascript">
	var idleTime = new Date();
	var f5key = false;
	var sidebar = true;

	$(document).ready(function() {
		// Browser Close Check
		window.addEventListener("beforeunload", function(event) {
			if (!f5key && $("#adminid").val() != '') {
				location.href = "<%=XSSCheck(LOGOUT_PAGE)%>";
				return;
			}
			else {
				f5key = false;
			}
		});

		$('.sub-menu').css('display', 'none');

		$('ul.menu').on('click', '.menu-item>span', function() {
			if ($('#adminid').val() != null && $('#adminid').val() != "") {
				$(this).parent().children('.sub-menu').stop('true','true').slideToggle('fast');
			}
		});

		$('ul.sub-menu').on('click', 'li', function() {
			if ($("#adminfirst").val() == "Y")
				return;

			if ($("#admintype").val() == "N") {
				var code = $(this).attr('id');
				if ($("#adminmenu").val().indexOf(code) < 0)
					return;
			}

			if ($('#adminid').val() != null && $('#adminid').val() != "") {
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

		//alert($('#adminid').val());
		if ($('#adminid').val() == null || $('#adminid').val() == "") {
			$('#photo_img').css('visibility', 'hidden');
			$('#admin_name').css('visibility', 'hidden');
			$('#logout_img').css('visibility', 'hidden');
			$('#logout').css('cursor', 'default');

			menuForm.action = "./login.jsp";
			menuForm.target = "mainFrm";
			menuForm.submit();
		}
		else {
			$('#photo_img').css('visibility', 'visible');
			$('#admin_name').css('visibility', 'visible');
			$('#logout_img').css('visibility', 'visible');
			$('#logout').css('cursor', 'pointer');

			$('.admin-name').text($("#adminname").val());
		}

		checkIdleTime();

		if ($("#adminfirst").val() == "Y") {
			$("#menu-admin").parent().children('.sub-menu').stop('true','true').slideToggle('fast');
			$("#0403").toggleClass('on');

			goChangePwd();
		}
		else {
			$("#menu-rept").parent().children('.sub-menu').stop('true','true').slideToggle('fast');
			$("#0101").toggleClass('on');

			goMenu("auditInfo.jsp", "0101", "감사 정보 조회");
		}
	});

	function keydown(event)
	{
		idleTime = new Date(); 

		// Refresh Key Check
		var keyID = event.which ? event.which : event.keyCode;
		if (keyID == 116 || (event.ctrlKey && keyID == 82)) {  // 116=F5 82=Ctrl+r
			f5key = true;
		}
	}
	$(document).on("keydown", keydown);

	function click()
	{
		idleTime = new Date();
	}
	$(document).on("click", click);

	function checkIdleTime()
	{
		if ($("#adminidle").val() != '') {
			var validMin = parseInt($("#adminidle").val());
			var calcTime = new Date();
			calcTime.setMinutes(calcTime.getMinutes() - validMin);

			if (idleTime.getTime() < calcTime.getTime()) {
				f5key = true;
				location.href = "<%=XSSCheck(LOGOUT_PAGE)%>?dt=ss";
			}
			else {
				setTimeout("checkIdleTime()", 10000);
			}
		}
	}

	$(".admin-logout").click(function() {
		if ($('#adminid').val() == null || $('#adminid').val() == "") {
			return;
		}

		if (!confirm(" 관리자 로그아웃 하시겠습니까?")) {
			return;
		}

		f5key = true;
		location.href = "<%=XSSCheck(LOGOUT_PAGE)%>";
	});

	$("#0101").click(function() {
		goMenu("auditInfo.jsp", "0101", "감사 정보 조회");
	});
	$("#0104").click(function() {
		goMenu("accessInfo.jsp", "0104", "접속 정보 조회");
	});
	$("#0105").click(function() {
		goMenu("accessStats.jsp", "0105", "접속 정보 통계");
	});
	$("#0102").click(function() {
		goMenu("serverIntegrity.jsp", "0102", "실시간 모듈 검증");
	});
	$("#0103").click(function() {
		goMenu("serverMonitor.jsp", "0103", "서버 모니터링");
	});

	$("#0201").click(function() {
		goMenu("auditPolicy.jsp", "0201", "감사 정책");
	});
	$("#0202").click(function() {
		goMenu("auditMail.jsp", "0202", "메일 통보 설정");
	});

	$("#0301").click(function() {
		goMenu("userPolicy.jsp", "0301", "사용자 정책");
	});
	$("#0302").click(function() {
		goMenu("userUnlock.jsp", "0302", "사용자 잠김 해제");
	});
	$("#0303").click(function() {
		goMenu("userLogout.jsp", "0303", "사용자 강제 로그아웃");
	});
	$("#0304").click(function() {
		goMenu("userChangePwd.jsp", "0304", "사용자 비밀번호 변경");
	});

	$("#0401").click(function() {
		goMenu("adminInfo.jsp", "0401", "관리자 관리");
	});
	$("#0402").click(function() {
		goMenu("adminPolicy.jsp", "0402", "관리자 정책");
	});
	$("#0403").click(function() {
		goMenu("adminPwd.jsp", "0403", "비밀번호 변경");
	});
	$("#0404").click(function() {
		goMenu("versionInfo.jsp", "0404", "제품 버전 정보");
	});
	$("#0501").click(function() {
		goMenu("client.jsp", "0501", "클라이언트 관리");
	});
	$("#0502").click(function() {
		goMenu("scope.jsp", "0502", "Scopes 관리");
	});

	function checkRole(url, code, msg)
	{
		if ($("#adminfirst").val() == "Y")
			return;

		if ($("#admintype").val() == "S") {
			goDirectMenu(url);
		}
		else if ($("#admintype").val() == "N") {
			if ($("#adminmenu").val().indexOf(code) >= 0)
				goDirectMenu(url);
			else
				alert(" [" + msg + "]  권한이 없습니다.");
		}
		else {
			alert(" [" + msg + "]  권한이 없습니다.");
		}
	}

	function goMenu(url, code, msg)
	{
		if ($("#adminfirst").val() == "Y")
			return;

		if ($("#admintype").val() == "S") {
			goDirectMenu(url);
		}
		else if ($("#admintype").val() == "N") {
			if ($("#adminmenu").val().indexOf(code) >= 0)
				goDirectMenu(url);
			else
				alert(" [" + msg + "]  권한이 없습니다.");
		}
		else {
			alert(" [" + msg + "]  권한이 없습니다.");
		}
	}

	function goDirectMenu(url)
	{
		if ($("#adminfirst").val() == "Y")
			return;

		menuForm.action = url;
		menuForm.target = "mainFrm";
		menuForm.submit();
	}

	function goChangePwd()
	{
		menuForm.action = "adminPwd.jsp";
		menuForm.target = "mainFrm";
		menuForm.submit();
	}
	</script>
</body>
</html>