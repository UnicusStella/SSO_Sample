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
		<input type="hidden" id="hstype" value=""/>
		<input type="hidden" id="hsvalue" value=""/>
		<input type="hidden" id="pageRow" value=20>
		<input type="hidden" id="totalCnt" value=0>
		<input type="hidden" id="curPage" value=1>

		<div class="page-breadcrumb">
			HOME / 사용자 / 사용자 잠김 해제
		</div>
		<div class="page-header">
			<h4 class="title">사용자 잠김 해제</h4>
		</div>

		<div class="content-box width-60p">
			<div class="content-top">
				<div class="float-left">
					<button class="btn" type="button" id="setUserUnlock">잠김 해제</button>
					<button class="btn ml-5" type="button" id="getLockedUser">잠김 사용자 조회</button>
				</div>
				<div class="float-right">
					<select class="search-base" id="searchtype" style="width:60px;">
					    <option value="1" selected="selected">이름</option>
					    <option value="2">아이디</option>
					</select>
					<input class="search-input ml-5" type="text" id="searchtext" style="width:200px;" maxlength="20" placeholder="검색"/>
					<input class="search-btn" type="button" id="searchBtn"/>
				</div>
			</div>
			<div class="content-body">
				<table id="user_list"></table>
			</div>
			<div class="content-bottom pt-10">
				<div class="float-left">
					<div class="total-count" id="total-tag"></div>
				</div>
				<div class="float-right" id="page-tag"></div>
			</div>
		</div>
	</div>

<script type="text/javascript">
	var first_flag = 1;

	$(document).ready(function(){
		checkAdmin();

		$('#searchtype').change(function() {
			$('#searchtext').focus();
		});

		$('#searchtext').focus();
	});

	$(window).resize(function(){
		$('#user_list').setGridWidth($('.content-body').width(), true);
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

	$("#user_list").jqGrid({
		datatype: "local",
		async: false,
		jsonReader: {
			page: "page",
			total: "total",
			root: "rows",
			records: function(obj) {return obj.length;},
			repeatitems: false,
			id: "id"
		},
		colNames: ['No', '이름', '아이디', '상태'],
		colModel: [
			{name:'index', index:'index', width:'12%', align:'center', sortable:false},
			{name:'name', index:'name', width:'37%', align:'center', sortable:false},
			{name:'id', index:'id', width:'37%', align:'center', sortable:false},
			{name:'statusNm', index:'statusNm', width:'14%', align:'center', sortable:false}
		],
		id: 'id',
		rowNum: 1000000,
		gridview: true,
		multiselect: false,
		height: 521,
		loadtext: 'Loading...',
	    beforeProcessing: function (data) {
	    	$('#totalCnt').val(data.total);
	    },
		loadComplete: function(data) {
			$('#user_list').setGridWidth($('.content-body').width(), true);

			if (first_flag != "1") {
				var ids = $("#user_list").getDataIDs();
				if (ids.length == 0) {
					$('#curPage').val(1);
					alert(" 조회 자료가 없습니다.");
				} else {
					var hstype = $("#hstype").val();
					if (hstype != "3") {
						$("#hstype").val($("#searchtype option:selected").val());
						var svalue = $("#searchtext").val().toLowerCase();
						$("#hsvalue").val($.trim(svalue));
					}
				}
			}
			else {
				first_flag = "0";
			}

			setPageTag($('#totalCnt').val(), $('#curPage').val());
		},
		loadError: function(xhr, status, error) {
			ajaxerror(xhr, status, error);
		}
	}).setGridWidth($('.content-body').width(), true);

	$("#searchBtn").click(function() {
		goSearch();
	});

	$("#searchtext").keypress(function(e) {
		if (e.which == 13) {
			goSearch();
		}
	});

	$("#getLockedUser").click(function() {
		this.blur();
		$("#searchtext").val("");
		var pagerow = $("#pageRow").val();

		$("#hstype").val("3");
		$("#curPage").val(1);

		$("#user_list").setGridParam({ datatype:"json" });
		$("#user_list").setGridParam({ url:"sub/getUserLockedList.jsp", mtype:"POST", postData:{spage:1, pagerow:pagerow} });
		$("#user_list").trigger("reloadGrid");
	});

	function goSearch()
	{
		var pagerow = $("#pageRow").val();
		var stype = $("#searchtype option:selected").val();
		var svalue = $("#searchtext").val().toLowerCase();
		$("#searchtext").val($.trim(svalue));
		svalue = $.trim(svalue);

		$("#hstype").val(stype);
		$("#curPage").val(1);

		$("#user_list").setGridParam({ datatype:"json" });
		$("#user_list").setGridParam({ url:"sub/getUserListByVal.jsp", mtype:"POST", postData:{stype:stype, svalue:svalue, spage:1, pagerow:pagerow} });
		$("#user_list").trigger("reloadGrid");
	}

	function pageSearch(pageNo)
	{
		var pagerow = $("#pageRow").val();
		var hstype = $("#hstype").val();

		if (hstype == "3") {
			$("#curPage").val(pageNo);

			$("#user_list").setGridParam({ datatype:"json" });
			$("#user_list").setGridParam({ url:"sub/getUserLockedList.jsp", mtype:"POST", postData:{spage:pageNo, pagerow:pagerow} });
			$("#user_list").trigger("reloadGrid");
		}
		else {
			var stype = $("#searchtype option:selected").val();
			var svalue = $("#searchtext").val().toLowerCase();
			svalue = $.trim(svalue);

			if (stype != $("#hstype").val()) {
				alert(" 조회 조건이 변경되었습니다.  [조회] 버튼을 클릭하세요.");
				return;
			}

			if (svalue != $("#hsvalue").val()) {
				alert(" 조회 조건이 변경되었습니다.  [조회] 버튼을 클릭하세요.");
				return;
			}

			$("#curPage").val(pageNo);

			$("#user_list").setGridParam({ datatype:"json" });
			$("#user_list").setGridParam({ url:"sub/getUserListByVal.jsp", mtype:"POST", postData:{stype:stype, svalue:svalue, spage:pageNo, pagerow:pagerow} });
			$("#user_list").trigger("reloadGrid");
		}
	}

	function setPageTag(totalCnt, curPage)
	{
		var maxRows = $("#pageRow").val();
		var maxPages = 10;
		var tagString = "";

		if (totalCnt <= 0) {
			tagString += "<a class='first paginate_button_disabled'></a>";
			tagString += "<a class='previous paginate_button_disabled'></a>";
			tagString += "<a class='paginate_active'>1</a>";
			tagString += "<a class='next paginate_button_disabled'></a>";
			tagString += "<a class='last paginate_button_disabled'></a>";
			$("#total-tag").text("전체 0 건");
			$("#page-tag").html(tagString);
			return;
		}

		var pageCnt = parseInt((totalCnt - 1) / maxRows) + 1;
		var fromPage = parseInt((curPage - 1) / maxPages) * maxPages + 1;
		var toPage = fromPage + maxPages - 1;
		if (toPage > pageCnt)
			toPage = pageCnt;

		if (curPage > maxPages) {
			tagString += "<a class='first paginate_button' href='javascript:pageSearch(1);' title='맨 앞'></a>";
			tagString += "<a class='previous paginate_button' href='javascript:pageSearch(" + (fromPage - 1) + ");' title='이전'></a>";
		}
		else {
			tagString += "<a class='first paginate_button_disabled'></a>";
			tagString += "<a class='previous paginate_button_disabled'></a>";
		}
		for (var i = fromPage; i <= toPage; i++) {
			if (i == curPage)
				tagString += "<a class='paginate_active'>" + i + "</a>";
			else
				tagString += "<a class='paginate_button' href='javascript:pageSearch(" + i + ");'>" + i + "</a>";
		}
		if (toPage < pageCnt) {
			tagString += "<a class='next paginate_button' href='javascript:pageSearch(" + (toPage + 1) + ");' title='다음'></a>";
			tagString += "<a class='last paginate_button' href='javascript:pageSearch(" + pageCnt + ");' title='맨 뒤'></a>";
		}
		else {
			tagString += "<a class='next paginate_button_disabled'></a>";
			tagString += "<a class='last paginate_button_disabled'></a>";
		}

		var cnt = totalCnt.toString().replace(/\B(?=(\d{3})+(?!\d))/g, ",");
		$("#total-tag").text("전체  " + cnt + " 건");

		$("#page-tag").html(tagString);
	}

	$("#setUserUnlock").click(function() {
		this.blur();
		var id = $("#user_list").getGridParam('selrow');
		var row = $("#user_list").getRowData(id);
		var ch = $("#challenge").val();

		if (id == "" || id == null) {
			alert(" 사용자를 선택하세요.");
			return;
		}

		if (row.statusNm != "잠김")
			return;

		if (confirm(row.name + " [" + id + "]  잠김 해제하시겠습니까?")) {
			$.ajax({
				type : "POST",
				url : "sub/setUserUnlock.jsp",
				data : {ch:ch, userid:id},
				async : false,
				dataType : "JSON",
				success : function(data) {
					var resultstatus = data.rows[0].resultstatus;
					if (resultstatus == 1) {
						$("#user_list").setCell(id, "statusNm", "정상");
						alert(" 잠김 해제 완료");
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
						alert(" ID: " + id + " 잠김 해제 오류 (" + resultstatus + ")\n\n" + data.rows[0].resultdata);
					}
				},
				error : function(xhr, status, error) {
					ajaxerror(xhr, status, error);
				}
			});
		}
	});

</script>
</body>
</html>