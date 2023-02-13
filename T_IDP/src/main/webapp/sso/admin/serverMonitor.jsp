<%@ page language="java" contentType="text/html; charset=utf-8" pageEncoding="utf-8"%>
<%@ page session="true"%>
<%@ include file="adminCommon.jsp"%>
<%@ include file="sub/checkAdmin.jsp"%>
<script type="text/javascript">
	if ("<%=XSSCheck(adminid)%>" == "") { top.location.href = "<%=XSSCheck(LOGIN_PAGE)%>"; }
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
	<link href="./css/sso-servermonitor.css?v=2" rel="stylesheet" type="text/css"/>
</head>
<body>
	<div class="page-holder">
		<input type="hidden" id="adminid" value="<%=XSSCheck(adminid)%>"/>
		<input type="hidden" id="adminip" value="<%=XSSCheck(adminip)%>"/>
		<input type="hidden" id="currip" value="<%=XSSCheck(currip)%>"/>
		<input type="hidden" id="pageRow" value=20>

		<div class="page-breadcrumb">
			HOME / 감사 정보 / 서버 모니터링
		</div>
		<div class="page-header">
			<h4 class="title">서버 모니터링</h4>
		</div>
		<div class="content-box">
			<div class="content-top">
				<div class="float-left ml-5">
					<div class="btn_submenu">
						<a class="btn_tool" title='새로고침 / 서버체크'>
							<span class="ic ic_refresh"></span>
							<span id="refresh_min_text" class="min"></span>
						</a>
						<span class="btn_func_more" id="rf" title='새로고침 주기'>
							<span class="ic ic_arrow_type3"></span>
						</span>
						<div class="array_option" style="width:90px; display:none;">
							<ul id="toolbar_refresh_flag" class="array_type">
								<li data-value="0">
									<span class="txt">사용안함</span><span class="ic_board ic_check" style="display:block;"></span>
								</li>
								<li data-value="1">
									<span class="txt">1분</span><span class="ic_board ic_check" style="display:none;"></span>
								</li>
								<li data-value="5">
									<span class="txt">5분</span><span class="ic_board ic_check" style="display:none;"></span>
								</li>
								<li data-value="10">
									<span class="txt">10분</span><span class="ic_board ic_check" style="display:none;"></span>
								</li>
							</ul>
						</div>
					</div>
				</div>
			</div>
			<div class="content-body pb-15">
				<table id="reportGrid"></table>
			</div>
		</div>
	</div>

<script type="text/javascript">
	var varTimer;
	var timer_cycle = 0;
	var timer_id = null;

	$(document).ready(function(){
		checkAdmin();
	});

	$(window).ready(function() {
	});

	$(window).resize(function(){
		$('#reportGrid').setGridWidth($('.content-body').width(), true);
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
		$("#reportGrid").jqGrid({
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
			colNames: ['No', '서버 ID', '서버 구분', '체크 URL', '체크 시간', '상태'],
		    colModel: [
				{name:'index', index:'index', width:'5%', align:'center', sortable:false},
				{name:'id', index:'id', width:'15%', align:'center', sortable:false},
				{name:'type', index:'type', width:'10%', align:'center', sortable:false},
				{name:'url', index:'url', width:'40%', align:'left', sortable:false},
				{name:'access', index:'access', width:'18%', align:'center', sortable:false},
				{name:'staus', index:'staus', width:'12%', align:'center', sortable:false}
			],
			id: 'id',
		    rowNum: 10000000,
			gridview: true,
			scrollrows: true,
			loadonce: true,
		    sortable: false,
		    multiselect: true,
		    height: 521,
		    loadtext: 'Loading...',
		    loadComplete: function() {
				$('#reportGrid').setGridWidth($('.content-body').width(), true);
		    },
		  	loadError: function(xhr, status, error) {
		  		ajaxerror(xhr, status, error);
		    }
		}).setGridWidth($('.content-body').width(), true);
	});

	function checkServer(id, url)
	{
		$.ajax({
			type: "POST",
			url: "sub/checkServer.jsp",
			data: {url:url},
			dataType: "JSON",
			async: false,
			success: function(data) {
				var resultstatus = data.rows[0].resultstatus;
				if (resultstatus == 1) {
					$("#reportGrid").setCell(id, 'staus', "<font color='blue'><B>ON</B></font>");
				}
				else {
					$("#reportGrid").setCell(id, 'staus', "<font color='red'><B>OFF</B></font>");
				}
				$("#reportGrid").setCell(id, 'access', getCurrentTime());
			},
			error: function(xhr, status, error) {
				ajaxerror(xhr, status, error);
			}
		});
	}

	function getCurrentTime()
	{	// YYYY-MM-DD HH:mm:SS
		var now = new Date();      
		var nowTime = now.getFullYear() + "-";
		nowTime += now.getMonth()+1 < 10 ? "0" + (now.getMonth()+1) : now.getMonth()+1;
		nowTime += "-";
		nowTime += now.getDate() < 10 ? "0" + now.getDate() : now.getDate();
		nowTime += "&nbsp;&nbsp;";
		nowTime += now.getHours() < 10 ? "0" + now.getHours() : now.getHours();
		nowTime += ":";
		nowTime += now.getMinutes() < 10 ? "0" + now.getMinutes() : now.getMinutes();
		nowTime += ":";
		nowTime += now.getSeconds() < 10 ? "0" + now.getSeconds() : now.getSeconds();
		return nowTime;
	}

	$('.btn_func_more').click(function() {
		var vw = $('.array_option').css('display');

		if (vw == "none")
			$('.array_option').css('display', 'block');
		else
			$('.array_option').css('display', 'none');
	});

	$('ul.array_type').on('click', 'li', function() {
		$(this).siblings().children('span.ic_board.ic_check').css('display', 'none');
		$(this).children('span.ic_board.ic_check').css('display', 'block');
		$('.array_option').css('display', 'none');

		var sCycle = $(this).attr("data-value");
		var nCycle = parseInt(sCycle);

		if (timer_cycle != nCycle) {
			if (nCycle == 0) sCycle = "";
			$('#refresh_min_text').text(sCycle);

			if (timer_id != null)
				clearTimeout(timer_id);

			timer_cycle = nCycle;

			if (nCycle == 0) {
				timer_id = null;
			}
			else {
				timer_id = setTimeout("refreshList()", nCycle * 60 * 1000);
			}
		}
	});

	$('.btn_tool').click(function() {
		if (timer_cycle == 0)
			refreshList();
	});

	function refreshList()
	{
		var ids = $("#reportGrid").getGridParam("selarrrow");

		if (ids.length == 0) {
			alert(" 체크 대상 서버를 선택하세요.");
		}

		$.each(ids, function(index, value) {
			if (value != null && value != "") {
				var row = $("#reportGrid").getRowData(value);
				checkServer(value, row.url);
			}
		});

		if (timer_cycle > 0)
			timer_id = setTimeout("refreshList()", timer_cycle * 60 * 1000);
	}

</script>
</body>
</html>