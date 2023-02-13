<%@ page language="java" contentType="text/html; charset=utf-8" pageEncoding="utf-8"%>
<%@ page session="true"%>
<%@ include file="adminCommon.jsp"%>
<%@ include file="sub/checkAdmin.jsp"%>
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
		<input type="hidden" id="pageRow" value=20>

		<div class="page-breadcrumb">
			HOME / 감사 정보 / 실시간 모듈 검증
		</div>
		<div class="page-header">
			<h4 class="title">실시간 모듈 검증</h4>
		</div>

		<div class="d-flex">
			<div class="content-box width-30p mr-10">
				<div class="content-top">
					<div class="float-left">
						<button class="subtitle-btn" type="button"></button>
						<span class="subtitle-text">서버 리스트</span>
					</div>
					<div class="float-right">
						<button class="btn" type="button" id="ssoIntegrity">모듈 검증</button>
					</div>
				</div>
				<div class="content-body pb-15" id="list-grid">
					<table id="serverList"></table>
				</div>
			</div>

			<div class="content-box width-70p ml-10">
				<div class="content-top pb-15">
					<div class="float-left">
						<button class="subtitle-btn" type="button"></button>
						<span class="subtitle-text">모듈 검증 로그</span>
					</div>
				</div>
				<div class="content-body pb-15" id="log-grid">
					<table id="reportGrid"></table>
				</div>
			</div>
		</div>
	</div>

<script type="text/javascript">
	var first_flag = 1;

	$(document).ready(function(){
		checkAdmin();
	});

	$(window).ready(function() {
	});

	$(window).resize(function(){
		$("#serverList").setGridWidth($("#list-grid").width(), true);
		$("#reportGrid").setGridWidth($("#log-grid").width(), true);
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

	$(function() {
		$("#serverList").jqGrid({
			url: "sub/getServerList.jsp",
			postData: {spage:"A", pagerow:$("#pageRow").val()},
			mtype: "post",
			datatype: "json",
			jsonReader: {
				page: "page",
				total: "total",
				root: "rows",
				records: function(obj) {return obj.length;},
				repeatitems: false,
				id: "id"
			},
			colNames: ['No', '서버 ID', '구분', '', '', ''],
		    colModel: [
				{name:'index', index:'index', width:'10%', align:'center', sortable:false},
				{name:'id', index:'id', width:'60%', align:'center', sortable:false},
				{name:'type', index:'type', width:'30%', align:'center', sortable:false},
				{name:'url', index:'url', width:0, hidden:true},
				{name:'access', index:'access', width:0, hidden:true},
				{name:'staus', index:'staus', width:0, hidden:true}
			],
			id: 'id',
		    rowNum: 10000000,
			gridview: true,
			scrollrows: true,
			loadonce: true,
		    sortable: false,
		    height: 521,
		    loadtext: 'Loading...',
		    loadComplete: function() {
		    	$("#serverList").setGridWidth($("#list-grid").width(), true);
		    },
		  	loadError: function(xhr, status, error) {
		  		ajaxerror(xhr, status, error);
		    }
		}).setGridWidth($("#list-grid").width(), true);

		$("#reportGrid").jqGrid({
			datatype: "local",
			jsonReader: {
				page: "page",
				total: "total",
				root: "rows",
				records: function(obj) {return obj.length;},
				repeatitems: false,
				id: "index"
			},
			colNames: ['No', '일시', '주체', '사건', '결과', '상세'],
		    colModel: [
				{name:'index', index:'index', width:'5%', align:'center', sortable:false},
				{name:'logDatetime', index:'logDatetime', width:'18%', align:'center', sortable:false},
				{name:'caseUser', index:'caseUser', width:'12%', align:'center', sortable:false},
				{name:'caseType', index:'caseType', width:'20%', align:'left', sortable:false},
				{name:'caseResult', index:'caseResult', width:'6%', align:'center', sortable:false},
				{name:'caseData', index:'caseData', width:'39%', align:'left', sortable:false}
			],
			id: 'index',
		    rowNum: 10000000,
			gridview: true,
		    sortable: false,
		    height: 521,
		    loadtext: 'Loading...',
		    loadComplete: function(data) {
				$("#reportGrid").setGridWidth($("#log-grid").width(), true);

				if (data.rows.length > 0) {
					var resultstatus = data.rows[0].resultstatus;
					if (resultstatus != null && resultstatus == -9) {
						alert(" 로그인 후 사용하세요.");
						parent.location.href = "<%=XSSCheck(LOGIN_PAGE)%>";
					}
					else if (resultstatus != null && resultstatus == -8) {
						alert(" 조회 권한이 없습니다.");
						parent.location.href = "<%=XSSCheck(ADMIN_MAIN_PAGE)%>";
					}
					else {
					}
				}

				if (first_flag != "1") {
					var ids = $("#reportGrid").getDataIDs();
					if (ids.length == 0) {
						alert(" 조회 자료가 없습니다.");
					}
				} else {
					first_flag = "0";
				}
		    },
		  	loadError: function(xhr, status, error) {
		  		ajaxerror(xhr, status, error);
		    }
		}).setGridWidth($("#log-grid").width(), true);
	});

	$("#ssoIntegrity").click(function(){
		var id = $("#serverList").getGridParam("selrow");
		var row = $("#serverList").getRowData(id);
		var stype = row.type;
		var surl = row.url;

		if (row.id == null || row.id == "") {
			alert(" 서버를 선택하세요.");
			return;
		}

		if (stype == "에이전트") {
			var idx = surl.indexOf("sso");
			if (idx != -1) {
				surl = surl.substring(0, idx + 3) + "/integrityTest.jsp";
			}
		}

		if (!confirm(" 서버 [ " + id + " ] 모듈 검증하시겠습니까?"))
			return;

		$.ajax({
			type: "POST",
			url: "sub/integrityTest.jsp",
			data: {spid:id, stype:stype, surl:surl},
			dataType: "JSON",
			async: false,
			success: function(data) {
				var resultstatus = data.rows[0].resultstatus;
				if (resultstatus == 1) {
					var date = getCurrentDate();
					$("#reportGrid").setGridParam({ datatype:"json" });
					$("#reportGrid").setGridParam({ url:"sub/getAuditInfo.jsp", mtype:"POST", postData:{fdate:date, tdate:date, stype:"00", srslt:"A", spage:"1", pagerow:$("#pageRow").val()} });
					$("#reportGrid").trigger("reloadGrid");

					alert(" [SSO모듈 검증]  완료");
					$("#reportGrid").setSelection("1");
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
					var date = getCurrentDate();
					$("#reportGrid").setGridParam({ datatype:"json" });
					$("#reportGrid").setGridParam({ url:"sub/getAuditInfo.jsp", mtype:"POST", postData:{fdate:date, tdate:date, stype:"00", srslt:"A", spage:"1", pagerow:$("#pageRow").val()} });
					$("#reportGrid").trigger("reloadGrid");

					alert(" [SSO모듈 검증]  오류 (" + resultstatus + ")\n\n" + data.rows[0].resultdata);
					$("#reportGrid").setSelection("1");
				}
			},
			error: function(xhr, status, error) {
				var date = getCurrentDate();
				$("#reportGrid").setGridParam({ datatype:"json" });
				$("#reportGrid").setGridParam({ url:"sub/getAuditInfo.jsp", mtype:"POST", postData:{fdate:date, tdate:date, stype:"00", srslt:"A", spage:"1", pagerow:$("#pageRow").val()} });
				$("#reportGrid").trigger("reloadGrid");

				ajaxerror(xhr, status, error);
				$("#reportGrid").setSelection("1");
			}
		});
	});

	function getCurrentDate()
	{	// YYYYMMDD
		var now = new Date();      
		var nowDate = now.getFullYear() + "";
		nowDate += now.getMonth()+1 < 10 ? "0" + (now.getMonth()+1) : now.getMonth()+1;
		nowDate += now.getDate() < 10 ? "0" + now.getDate() : now.getDate();
		return nowDate;
	}

</script>
</body>
</html>