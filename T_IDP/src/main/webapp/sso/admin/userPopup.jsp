<%@ page language="java" contentType="text/html; charset=utf-8" pageEncoding="utf-8"%>

	<link href="./css/sso-selpopup.css?v=2" rel="stylesheet" type="text/css"/>

	<input type="hidden" id="pop-hstype" value=""/>
	<input type="hidden" id="pop-hsvalue" value=""/>
	<input type="hidden" id="pop-totalCnt" value=0>
	<input type="hidden" id="pop-curPage" value=1>

	<div id="seldlg-user">
		<div class="content-box">
			<div class="content-top pt-0 pb-0">
				<div class="float-left pt-5">
					<button class="subtitle-btn" type="button"></button>
					<span class="subtitle-text">사용자 리스트</span>
				</div>
				<div class="float-right">
					<div id="seldlg-user-close"></div>
				</div>
			</div>
			<div class="content-top pt-0">
				<div class="float-left">
					<select class="search-base" id="pop-searchtype" style="width:70px;">
					    <option value="1" selected="selected">이름</option>
					    <option value="2">아이디</option>
					</select>
					<input class="search-input ml-5" type="text" id="pop-searchtext" style="width:170px;" maxlength="20" placeholder="검색"/>
					<input class="search-btn" type="button" id="pop-searchBtn"/>
				</div>
				<div class="float-right">
					<button class="btn" type="button" id="goAllOK">전 체</button>
					<button class="btn ml-5" type="button" id="goUserOK">선 택</button>
				</div>
			</div>
			<div class="content-body" id="pop-content">
				<table id="user_list"></table>
			</div>
			<div class="content-bottom pt-10 pb-10">
				<div class="float-left">
					<div class="total-count" id="pop-total-tag"></div>
				</div>
				<div class="float-right" id="pop-page-tag"></div>
			</div>
		</div>
	</div>
	<div id="seldlg-user-background"></div>

<script type="text/javascript">
	var pop_first_flag = 1;

	$(document).ready(function(){
		$('#pop-searchtype').change(function() {
			$('#pop-searchtext').focus();
		});

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
			colNames: ['이름', '아이디'],
			colModel: [
				{name:'name', index:'name', width:190, align:'center', sortable:false},
				{name:'id', index:'id', width:190, align:'center', sortable:false}
			],
			id: 'id',
			rowNum: 1000000,
			gridview: true,
		    sortable: false,
			height: 339,
			loadtext: 'Loading...',
		    beforeProcessing: function (data) {
		    	$('#pop-totalCnt').val(data.total);
		    },
		    loadComplete: function(data) {
				$('#user_list').setGridWidth($('#pop-content').width(), true);

				if (pop_first_flag != 1) {
					var ids = $("#user_list").getDataIDs();
					if (ids.length == 0) {
						$('#pop-curPage').val(1);
						alert(" 조회 자료가 없습니다.");
					} else {
						$("#pop-hstype").val($("#pop-searchtype option:selected").val());
						var svalue = $("#pop-searchtext").val().toLowerCase();
						$("#pop-hsvalue").val($.trim(svalue));
					}
				}
				else {
					pop_first_flag = 0;
				}

				setPopPageTag($('#pop-totalCnt').val(), $('#pop-curPage').val());
		    },
			ondblClickRow: function (rowid, iRow, iCol, e) {
				var row = $("#user_list").getRowData(rowid);
				$("#userid").val(row.id);
				$("#sel-user").val(row.name + " (" + row.id + ")");
				$("#seldlg-user, #seldlg-user-background").toggle();
			},
			loadError: function(xhr, status, error) {
				ajaxerror(xhr, status, error);
				window.close();
			}
		});
	});

	$("#seldlg-user-close").click(function () {
		$("#seldlg-user, #seldlg-user-background").toggle();
	});

	$("#goAllOK").click(function() {
		this.blur();
		$("#userid").val("");
		$("#sel-user").val("");
		$("#seldlg-user, #seldlg-user-background").toggle();
	});

	$("#goUserOK").click(function() {
		this.blur();
		if ($("#user_list").getGridParam("reccount") == 0)
			return;

		var id = $("#user_list").getGridParam("selrow");
		var row = $("#user_list").getRowData(id);
		if (row.id == null || row.id == "") {
			alert(" 사용자를 선택하세요.");
			return;
		}

		$("#userid").val(row.id);
		$("#sel-user").val(row.name + " (" + row.id + ")");
		$("#seldlg-user, #seldlg-user-background").toggle();
	});

	$("#pop-searchBtn").click(function() {
		goPopSearch();
	});

	$("#pop-searchtext").keypress(function(e) {
		if (e.which == 13) {
			goPopSearch();
		}
	});

	function goPopSearch()
	{
		var pagerow = $("#pop-pageRow").val();
		var stype = $("#pop-searchtype option:selected").val();
		var svalue = $("#pop-searchtext").val().toLowerCase();
		$("#pop-searchtext").val($.trim(svalue));
		svalue = $.trim(svalue);

		$("#pop-curPage").val(1);

		$("#user_list").setGridParam({ datatype:"json" });
		$("#user_list").setGridParam({ url:"sub/getUserLoginListByVal.jsp", mtype:"POST", postData:{stype:stype, svalue:svalue, spage:1, pagerow:13} });
		$("#user_list").trigger("reloadGrid");
	}

	function pagePopSearch(pageNo)
	{
		var pagerow = $("#pop-pageRow").val();
		var stype = $("#pop-searchtype option:selected").val();
		var svalue = $("#pop-searchtext").val().toLowerCase();
		svalue = $.trim(svalue);

		if (stype != $("#pop-hstype").val()) {
			alert(" 조회 조건이 변경되었습니다.  [조회] 버튼을 클릭하세요.");
			return;
		}

		if (svalue != $("#pop-hsvalue").val()) {
			alert(" 조회 조건이 변경되었습니다.  [조회] 버튼을 클릭하세요.");
			return;
		}

		$("#pop-curPage").val(pageNo);

		$("#user_list").setGridParam({ datatype:"json" });
		$("#user_list").setGridParam({ url:"sub/getUserLoginListByVal.jsp", mtype:"POST", postData:{stype:stype, svalue:svalue, spage:pageNo, pagerow:13} });
		$("#user_list").trigger("reloadGrid");
	}

	function setPopPageTag(totalCnt, curPage)
	{
		var maxRows = 13;
		var maxPages = 7;
		var tagString = "";

		if (totalCnt <= 0) {
			tagString += "<a class='first paginate_button_disabled'></a>";
			tagString += "<a class='previous paginate_button_disabled'></a>";
			tagString += "<a class='paginate_active'>1</a>";
			tagString += "<a class='next paginate_button_disabled'></a>";
			tagString += "<a class='last paginate_button_disabled'></a>";
			$("#pop-total-tag").text("전체 0 건");
			$("#pop-page-tag").html(tagString);
			return;
		}

		var pageCnt = parseInt((totalCnt - 1) / maxRows) + 1;
		var fromPage = parseInt((curPage - 1) / maxPages) * maxPages + 1;
		var toPage = fromPage + maxPages - 1;
		if (toPage > pageCnt)
			toPage = pageCnt;

		if (curPage > maxPages) {
			tagString += "<a class='first paginate_button' href='javascript:pagePopSearch(1);' title='맨 앞'></a>";
			tagString += "<a class='previous paginate_button' href='javascript:pagePopSearch(" + (fromPage - 1) + ");' title='이전'></a>";
		}
		else {
			tagString += "<a class='first paginate_button_disabled'></a>";
			tagString += "<a class='previous paginate_button_disabled'></a>";
		}
		for (var i = fromPage; i <= toPage; i++) {
			if (i == curPage)
				tagString += "<a class='paginate_active'>" + i + "</a>";
			else
				tagString += "<a class='paginate_button' href='javascript:pagePopSearch(" + i + ");'>" + i + "</a>";
		}
		if (toPage < pageCnt) {
			tagString += "<a class='next paginate_button' href='javascript:pagePopSearch(" + (toPage + 1) + ");' title='다음'></a>";
			tagString += "<a class='last paginate_button' href='javascript:pagePopSearch(" + pageCnt + ");' title='맨 뒤'></a>";
		}
		else {
			tagString += "<a class='next paginate_button_disabled'></a>";
			tagString += "<a class='last paginate_button_disabled'></a>";
		}

		var cnt = totalCnt.toString().replace(/\B(?=(\d{3})+(?!\d))/g, ",");
		$("#pop-total-tag").text("전체  " + cnt + " 건");

		$("#pop-page-tag").html(tagString);
	}

	function showSelUser()
	{
		$("#seldlg-user, #seldlg-user-background").toggle();
		$('#user_list').setGridWidth($('#pop-content').width(), true);
		$('#pop-searchtext').focus();
	}
</script>
