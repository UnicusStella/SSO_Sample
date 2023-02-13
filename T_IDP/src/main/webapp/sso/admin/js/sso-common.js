function checkAdmin()
{
	var pAdminid = $("#adminidp", parent.document).val();
	if (pAdminid === undefined || pAdminid === "") {
		top.location.href = "./adminLogin.jsp";
		return;
	}

	var cAdminid = $("#adminid").val();
	if (pAdminid != cAdminid) {
		alert(" 로그인 아이디가 변경되었습니다.\n\n 메인 화면으로 이동합니다.");
		parent.location.reload();
		return;
	}

	var loginip = $("#adminip").val();
	var currentip = $("#currip").val();
	if (loginip != currentip) {
		alert(" 관리자의 접속 IP가 변경되었습니다.\n\n 로그아웃 됩니다.");
		top.location.href = "./adminLogout.jsp?dt=ip";
		return;
	}
}