<%@ page language="java" contentType="text/html; charset=utf-8" pageEncoding="utf-8"%>
<%@ page session="true"%>
<%@ page import="com.dreamsecurity.sso.server.api.admin.AdminController"%>
<%@ include file="adminCommon.jsp"%>
<%@ include file="sub/checkAdmin.jsp"%>
<%
	AdminController adminApi = new AdminController();
	String challenge = adminApi.createAdminCSRFToken(request);
%>
<script type="text/javascript">
	if ("<%=XSSCheck(adminid)%>" == "") { top.location.href = "<%=XSSCheck(LOGIN_PAGE)%>"; }
	if ("<%=XSSCheck(admintype)%>" != "S") { top.location.href = "<%=XSSCheck(LOGOUT_PAGE)%>"; }
</script>

<!DOCTYPE html>
<html lang="ko">
<head>
	<meta charset="utf-8"/>
	<meta http-equiv="Content-Style-Type" content="text/css"/>
	<meta http-equiv="X-UA-Compatible" content="IE=edge"/>

	<!--jgGrid, jsTree Tags-->
	<link href="css/jquery-ui.css" type="text/css" rel="stylesheet"/>
	<link href="css/jquery-ui-1.8.21.custom.css" type="text/css" rel="stylesheet"/>
	<script src="js/jquery-3.4.1.min.js" type="text/javascript"></script>
	<script src="js/jquery-ui-1.12.1.min.js" type="text/javascript"></script>
	<script src="js/!script.js" type="text/javascript"></script>
	<link href="css/!style.css" type="text/css" rel="stylesheet"/>
	<script src="js/i18n/grid.locale-kr.js" type="text/javascript"></script> 
	<script src="js/jquery.jqGrid.src.js" type="text/javascript"></script>
	<link href="css/ui.jqgrid.css" rel="stylesheet" type="text/css"/>

	<script src="js/sso-common.js" type="text/javascript"></script>
	<link href="./css/sso-common.css" rel="stylesheet" type="text/css"/>
</head>
<body>
	<div class="page-holder">
		<input type="hidden" id="adminid" value="<%=XSSCheck(adminid)%>"/>
		<input type="hidden" id="adminip" value="<%=XSSCheck(adminip)%>"/>
		<input type="hidden" id="currip" value="<%=XSSCheck(currip)%>"/>
		<input type="hidden" id="challenge" value="<%=XSSCheck(challenge)%>"/>

		<div class="page-breadcrumb">
			HOME / 클라이언트 / Scope 관리
		</div>
		<div class="page-header">
			<h4 class="title">Scope 관리</h4>
		</div>
		
		<div class="d-flex">		
			<div class="content-box width-50p mr-10">
				<div class="content-top">
					<div class="float-left">
						<button class="subtitle-btn" type="button"></button>
						<span class="subtitle-text">Scope 리스트</span>
					</div>
					<div class="float-right">
						<input class="basic_input width-180 height-30" type="text" id="scopeId" placeholder="Scope ID"/>
						<button class="btn ml-5" type="button" id="setScope">추 가</button>
						<button class="btn ml-5" type="button" id="removeScope">삭 제</button>
					</div>
				</div>
				<div class="content-body pb-15" id="scopelist-box">
					<table id="scopeList"></table>
				</div>
			</div>
		</div>
	</div>

<script type="text/javascript">

	$(document).ready(function(){
		checkAdmin();

		$("#scopeList").jqGrid({
			url: "sub/getScopeList.jsp",
			datatype: "json",
			colNames: ['Scope'],
		    colModel: [
		          {name:'id', index:'id', width:'100%', align:'center', sortable:false}
			],
			id: 'id',
		    rowNum: 1000000,
		    gridview: true,
			scrollrows: true,
			loadonce: true,
			sortable: true,
			sortname: 'id',
		    height: 521,
		    loadtext: 'Loading...',
		    loadComplete:function(){
				$('#scopeList').setGridWidth($('#scopelist-box').width(), true);
		    },
			loadError: function(xhr, status, error) {
				ajaxerror(xhr, status, error);
			}
		}).setGridWidth($('#scopelist-box').width(), true);
	});

	$(window).resize(function(){
		$('#scopeList').setGridWidth($('#scopelist-box').width(), true);
	});

	function keydown(event)
	{
		parent.idleTime = new Date(); 

		// Refresh Key Check
		var keyID = event.which ? event.which : event.keyCode;
		if (keyID == 116 || (event.ctrlKey && keyID == 82)) {  // 116=F5 82=Ctrl+r
			parent.f5key = true;
		}
	}
	$(document).on("keydown", keydown);

	function click()
	{
		parent.idleTime = new Date();
	}
	$(document).on("click", click);

	$("#setScope").click(function() {
		this.blur();
		var ch = $("#challenge").val();
		var sid = $("#scopeId").val().trim();

		if (sid == null || sid == "") {
			alert(" [Scope] 입력하세요.");
			$("#scopeId").focus();
			return;
		}

		sid = sid.toLowerCase();
		$("#scopeId").val(sid);

		var scopeIdList = $("#scopeList").jqGrid("getCol", "id", true);

		for (var i = 0; i < scopeIdList.length; i++) {
			if (scopeIdList[i].value == sid) {
				alert(" 이미 등록된 Scope 입니다.");
				$("#scopeId").focus();
				return;
			}
		}

		if (sid == "name" || sid == "phone") {
			alert(" profile 에 등록된 Scope 입니다.");
			$("#scopeId").focus();
			return;
		}

		if (!confirm(" [" + sid +"]  저장하시겠습니까?")) {
			return;
		}

		$.ajax({
			type: "POST",
			url: "sub/setScope.jsp",
			data: {ch:ch, id:sid},
			dataType: "JSON",
			traditional : true,
			async: false,
			success: function(data) {
				var resultstatus = data.rows[0].resultstatus;
				if (resultstatus == 1) {
					$("#scopeId").val("");

					var newRowData = {'id':sid};
      				$("#scopeList").addRowData(sid, newRowData, "last");
      				$("#scopeList").setGridParam({datatype:"local"}).trigger("reloadGrid");
					alert(" 저장 완료");
				}
				else if (resultstatus == -9) {
					alert(" 로그인 후 사용하세요.");
					parent.location.href = "<%=XSSCheck(LOGIN_PAGE)%>";
				}
				else if (resultstatus == -8) {
					alert(" 처리 권한이 없습니다.");
					parent.location.href = "<%=XSSCheck(ADMIN_MAIN_PAGE)%>";
				}
				else {
					alert(" ID: " + sid + " 저장 오류 (" + resultstatus + ")\n\n" + data.rows[0].resultdata);
				}
			},
			error: function(xhr, status, error) {
				ajaxerror(xhr, status, error);
			}
		});
	});

	$("#removeScope").click(function() {
		this.blur();
		var ch = $("#challenge").val();
		var sid = $("#scopeList").getGridParam("selrow");

		if (sid == null || sid == "") {
			alert(" [Scope] 선택하세요.");
			return;
		}

		if (sid == "openid" || sid == "profile"  || sid == "email" || sid == "address") {
			alert(" 삭제할 수 없는 Scope 입니다.");
			return;
		}

		if (confirm(" [" + sid + "]  삭제하시겠습니까?")) {
			$.ajax({
				type: "POST",
				url: "sub/removeScope.jsp",
				data: {ch:ch, id:sid},
				dataType: "JSON",
				async: false,
				success: function(data) {
					var resultstatus = data.rows[0].resultstatus;

					if (resultstatus == 1) {
						$("#scopeList").delRowData(sid);
						$("#scopeList").setGridParam({datatype:"local"}).trigger("reloadGrid");
						alert(" 삭제 완료");
					}
					else if (resultstatus == -9) {
						alert(" 로그인 후 사용하세요.");
						parent.location.href = "<%=XSSCheck(LOGIN_PAGE)%>";
					}
					else if (resultstatus == -8) {
						alert(" 처리 권한이 없습니다.");
						parent.location.href = "<%=XSSCheck(ADMIN_MAIN_PAGE)%>";
					}
					else {
						alert(" ID: " + sid + " 삭제 오류 (" + resultstatus + ")\n\n" + data.rows[0].resultdata);
					}
				},
				error: function(xhr, status, error) {
					ajaxerror(xhr, status, error);
				}
			});
		}
	});
</script>
</body>
</html>