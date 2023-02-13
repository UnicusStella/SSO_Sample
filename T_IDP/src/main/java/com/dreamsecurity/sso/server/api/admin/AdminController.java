package com.dreamsecurity.sso.server.api.admin;

import java.io.File;
import java.net.URLDecoder;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Date;
import java.util.List;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

import com.dreamsecurity.jcaos.util.FileUtil;
import com.dreamsecurity.sso.lib.jsn.JSONObject;
import com.dreamsecurity.sso.lib.slf.Logger;
import com.dreamsecurity.sso.lib.slf.LoggerFactory;
import com.dreamsecurity.sso.lib.xsc.utils.Base64;
import com.dreamsecurity.sso.server.api.admin.service.AdminService;
import com.dreamsecurity.sso.server.api.admin.vo.ClientVO;
import com.dreamsecurity.sso.server.api.admin.vo.UserAccessInfo;
import com.dreamsecurity.sso.server.client.ClientRepository;
import com.dreamsecurity.sso.server.common.MStatus;
import com.dreamsecurity.sso.server.config.SSOConfig;
import com.dreamsecurity.sso.server.crypto.CryptoApiException;
import com.dreamsecurity.sso.server.crypto.SSOCryptoApi;
import com.dreamsecurity.sso.server.dup.DupClient;
import com.dreamsecurity.sso.server.ha.SyncMonitor;
import com.dreamsecurity.sso.server.provider.EnvironInform;
import com.dreamsecurity.sso.server.util.JsonUtil;
import com.dreamsecurity.sso.server.util.OIDCUtil;
import com.dreamsecurity.sso.server.util.Util;

import jxl.Workbook;
import jxl.write.Label;
import jxl.write.WritableSheet;
import jxl.write.WritableWorkbook;

public class AdminController
{
	private static Logger log = LoggerFactory.getLogger(AdminController.class);

	private AdminService service = null;

	public AdminController()
	{
		service = new AdminService();
	}

	public String createLoginCSRFToken(HttpServletRequest request)
	{
		String challenge = "";

		try {
			challenge = SSOCryptoApi.getInstance().createRandom(16);
		}
		catch (CryptoApiException e) {
			e.printStackTrace();
		}

		HttpSession session = request.getSession(true);
		session.setAttribute("LPCHLG", challenge);
		session.setAttribute("LPTIME", new Date());

		return challenge;
	}

	public String createAdminCSRFToken(HttpServletRequest request)
	{
		String challenge = "";

		try {
			challenge = SSOCryptoApi.getInstance().createRandom(16);
		}
		catch (CryptoApiException e) {
			e.printStackTrace();
		}

		HttpSession session = request.getSession(true);
		session.setAttribute("APCHLG", challenge);
		session.setAttribute("APTIME", new Date());

		return challenge;
	}

	public JSONObject adminLogin(HttpServletRequest request)
	{
		JSONObject result = new JSONObject();
		int returncode = MStatus.FAIL;

		if (SSOConfig.getInstance().getAuthStatus() != 0) {
			result.put("code", String.valueOf(MStatus.AUTH_NON_ACTIVE));
			result.put("message", "인증 비활성화 상태");
			result.put("data", "");
			return result;
		}

		HttpSession session = request.getSession(false);

		String id = request.getParameter("loginId") == null ? "" : (String) request.getParameter("loginId");
		String pw = request.getParameter("loginPw") == null ? "" : (String) request.getParameter("loginPw");
		String ip = Util.getClientIP(request);
		String br = request.getAttribute("loginBr") == null ? "NN" : (String) request.getAttribute("loginBr");
		String ch = request.getParameter("loginCh") == null ? "" : (String) request.getParameter("loginCh");

		String sessionCh = session.getAttribute("LPCHLG") == null ? "" : (String) session.getAttribute("LPCHLG");
		Date sessionTm = (Date) session.getAttribute("LPTIME");
		session.removeAttribute("LPCHLG");
		session.removeAttribute("LPTIME");

		if (sessionTm != null) {
			Date curDate = new Date(System.currentTimeMillis());
			Calendar cal = Calendar.getInstance();
			cal.setTime(sessionTm);
			cal.add(Calendar.MINUTE, SSOConfig.getInstance().getLoginCSRFTokenTime());
			sessionTm = cal.getTime();

			int compare = curDate.compareTo(sessionTm);
			if (compare > 0) {
				result.put("code", String.valueOf(MStatus.FAIL));
				result.put("message", "Login CSRFToken Timeout");
				result.put("data", "");
				return result;
			}
		}
		else {
			sessionCh = "";
		}

		if (Util.isEmpty(sessionCh) || !sessionCh.equals(ch)) {
			service.setAuditInfo(Util.getDateFormat("yyyyMMdd"), Util.getDateFormat("HHmmss"),
					SSOConfig.getInstance().getServerName(), "AB", "1", "로그인 패킷 재사용");

			result.put("code", String.valueOf(MStatus.FAIL));
			result.put("message", "로그인 패킷 재사용");
			result.put("data", "");
			return result;
		}

		try {
			id = SSOCryptoApi.getInstance().decryptJS(ch, id);
			pw = SSOCryptoApi.getInstance().decryptJS(ch, pw);
		}
		catch (CryptoApiException e) {
			e.printStackTrace();
			log.debug("### 관리자 로그인 파라미터 복호화 오류");

			result.put("code", String.valueOf(MStatus.FAIL));
			result.put("message", "관리자 로그인 파라미터 복호화 오류");
			result.put("data", "");
			return result;
		}

		Map<String, Object> returnMap = service.adminLogin(id, pw, ip, br);

		returncode = (Integer) returnMap.get("code");
		if (returncode != MStatus.SUCCESS) {
			result.put("code", String.valueOf((Integer) returnMap.get("code")));
			result.put("message", (String) returnMap.get("message"));
			result.put("data", (String) returnMap.get("detail"));
		}
		else {
			session.setAttribute("SSO_ADMIN_ID", (String) returnMap.get("id"));
			session.setAttribute("SSO_ADMIN_INFO", returnMap);

			result.put("code", String.valueOf(MStatus.SUCCESS));
			result.put("message", "SUCCESS");
			result.put("data", "");
		}

		return result;
	}

	public void setAdminLogoutInfo(String id, String ip, String tp, String dt)
	{
		service.setAdminLogoutInfo(id, tp);

		String detail = "";
		if (dt.equals("ip")) {
			detail = "IP 변경";
		}
		else if (dt.equals("ss")) {
			detail = "세션 비활동 시간 경과";
		}

		if (Util.isEmpty(detail)) {
			service.setAuditInfo(Util.getDateFormat("yyyyMMdd"), Util.getDateFormat("HHmmss"), id, "BC", "0", ip);
		}
		else {
			service.setAuditInfo(Util.getDateFormat("yyyyMMdd"), Util.getDateFormat("HHmmss"), id, "BC", "0", ip + ", " + detail);
		}
	}

	public String setAdminPwd(HttpServletRequest request, String id, String curPwd, String newPwd, String adminsalt, String adminfirst)
	{
		String pString = "";

		try {
			int cnt = service.setAdminPwd(request, id, curPwd, newPwd, adminsalt, adminfirst);

			String detail = adminfirst.equals("Y") ? "최초 접속 변경": "";

			if (cnt > 0) {
				service.setAuditInfo(Util.getDateFormat("yyyyMMdd"), Util.getDateFormat("HHmmss"), id, "AU", "0", detail);
				pString = "{\"page\":1,\"total\":1,\"records\":1,\"rows\":[{\"resultstatus\":1,\"resultdata\":\"\"}]}";
			}
			else {
				service.setAuditInfo(Util.getDateFormat("yyyyMMdd"), Util.getDateFormat("HHmmss"), id, "AU", "1", detail + "비밀번호 불일치");
				pString = "{\"page\":1,\"total\":1,\"records\":1,\"rows\":[{\"resultstatus\":-1,\"resultdata\":\"\"}]}";
			}
		}
		catch (Exception e) {
			pString = "Error : 비밀번호 변경 오류";
		}

		return pString;
	}

	public String getAdminList()
	{
		String pString = "";

		try {
			List<Object> list = service.getAdminList();

			List<String> key = new ArrayList<String>();
			key.add("name");
			key.add("id");
			key.add("type");
			key.add("typeText");

			pString = JsonUtil.jqgridPaser(key, list);
		}
		catch (Exception e) {
			pString = "Error : 데이터 조회 오류 ";
		}

		return pString;
	}

	public String getAdminInfo(String id)
	{
		String pString = "";

		try {
			List<Object> list = service.getAdminInfo(id);

			List<String> key = new ArrayList<String>();
			key.add("name");
			key.add("id");
			key.add("type");
			key.add("email");
			key.add("menuCode");

			pString = JsonUtil.jqgridPaser(key, list);
		}
		catch (Exception e) {
			pString = "Error : 데이터 조회 오류";
		}

		return pString;
	}

	public String setAdminInfo(String adminid, String newflag, String id, String name, String pwd, String type, String email, String menucode)
	{
		String pString = "";

		try {
			service.setAdminInfo(newflag, id, name, pwd, type, email, menucode);

			StringBuilder sb = new StringBuilder();
			if (newflag.equals("1")) {
				sb.append("신규");
			}
			else {
				sb.append("수정");
			}
			sb.append(", 아이디:" + id);
			sb.append(", 이름:" + name);
			sb.append(", 구분:");
			if (type.equals("S")) {
				sb.append("최고관리자");
			}
			else {
				sb.append("모니터링관리자");
			}
			sb.append(", 이메일:" + email);

			service.setAuditInfo(Util.getDateFormat("yyyyMMdd"), Util.getDateFormat("HHmmss"),
					adminid, "AR", "0", sb.toString());

			pString = "{\"page\":1,\"total\":1,\"records\":1,\"rows\":[{\"resultstatus\":1,\"resultdata\":\"\"}]}";
		}
		catch (Exception e) {
			pString = "Error : 데이터 저장 오류 ";
		}

		return pString;
	}

	public String removeAdminInfo(String adminid, String uid)
	{
		String pString = "";

		try {
			service.removeAdminInfo(uid);

			StringBuilder sb = new StringBuilder();
			sb.append("삭제, 아이디:" + uid);

			service.setAuditInfo(Util.getDateFormat("yyyyMMdd"), Util.getDateFormat("HHmmss"),
					adminid, "AR", "0", sb.toString());

			pString = "{\"page\":1,\"total\":1,\"records\":1,\"rows\":[{\"resultstatus\":1,\"resultdata\":\"\"}]}";
		}
		catch (Exception e) {
			pString = "Error : 데이터 삭제 오류";
		}

		return pString;
	}

	public String getAdpyInfo(String code)
	{
		String pString = "";

		try {
			List<Object> list = service.getAdpyInfo(code);

			List<String> key = new ArrayList<String>();
			key.add("pwMismatchAllow");
			key.add("lockTime");
			key.add("sessionTime");
			key.add("ipMaxCount");

			pString = JsonUtil.jqgridPaser(key, list);
		}
		catch (Exception e) {
			pString = "Error : 데이터 조회 오류";
		}

		return pString;
	}

	public String setAdpyInfo(String adminid, String code, String pwallow, String locktime, String sesstime, String ipcnt)
	{
		String pString = "";

		try {
			service.setAdpyInfo(code, pwallow, locktime, sesstime, ipcnt);

			StringBuilder sb = new StringBuilder();
			sb.append("비밀번호 실패 허용 회수:" + pwallow + "회");
			sb.append(", 로그인 제한 시간:" + locktime + "분");
			sb.append(", 세션 비활동 시간:" + sesstime + "분");
			sb.append(", 접속 IP 최대 개수:" + ipcnt + "개");

			service.setAuditInfo(Util.getDateFormat("yyyyMMdd"), Util.getDateFormat("HHmmss"),
					adminid, "AS", "0", sb.toString());

			pString = "{\"page\":1,\"total\":1,\"records\":1,\"rows\":[{\"resultstatus\":1,\"resultdata\":\"\"}]}";
		}
		catch (Exception e) {
			pString = "Error : 데이터 저장 오류";
		}

		return pString;
	}

	public String getAdminIpList()
	{
		String pString = "";

		try {
			List<Object> list = service.getAdminIpList();

			List<String> key = new ArrayList<String>();
			key.add("ip");

			pString = JsonUtil.jqgridPaser(key, list);
		}
		catch (Exception e) {
			pString = "Error : 데이터 조회 오류";
		}

		return pString;
	}

	public String setAdminIp(String adminid, String ip)
	{
		String pString = "";

		try {
			service.setAdminIp(ip);

			StringBuilder sb = new StringBuilder();
			sb.append("추가, " + ip);

			service.setAuditInfo(Util.getDateFormat("yyyyMMdd"), Util.getDateFormat("HHmmss"),
					adminid, "AT", "0", sb.toString());

			pString = "{\"page\":1,\"total\":1,\"records\":1,\"rows\":[{\"resultstatus\":1,\"resultdata\":\"\"}]}";
		}
		catch (Exception e) {
			pString = "Error : 데이터 저장 오류";
		}

		return pString;
	}

	public String removeAdminIp(String adminid, String ip)
	{
		String pString = "";

		try {
			service.removeAdminIp(ip);

			StringBuilder sb = new StringBuilder();
			sb.append("삭제, " + ip);

			service.setAuditInfo(Util.getDateFormat("yyyyMMdd"), Util.getDateFormat("HHmmss"),
					adminid, "AT", "0", sb.toString());

			pString = "{\"page\":1,\"total\":1,\"records\":1,\"rows\":[{\"resultstatus\":1,\"resultdata\":\"\"}]}";
		}
		catch (Exception e) {
			pString = "Error : 데이터 삭제 오류";
		}

		return pString;
	}

	public String getUserListByVal(String sType, String sValue, int fnum, int tnum)
	{
		String pString = "";

		try {
			int totalCnt = service.countUserListByVal(sType, sValue);
			List<Object> list = service.getUserListByVal(sType, sValue, fnum, tnum);

			List<String> key = new ArrayList<String>();
			key.add("index");
			key.add("name");
			key.add("id");
			key.add("statusNm");

			pString = JsonUtil.jqgridPaser(key, list, totalCnt);
		}
		catch (Exception e) {
			pString = "Error : 데이터 조회 오류";
		}

		return pString;
	}

	public String getUserLoginListByVal(String sType, String sValue, int fnum, int tnum)
	{
		String pString = "";

		try {
			int totalCnt = service.countUserListByVal(sType, sValue);
			List<Object> list = service.getUserListByVal(sType, sValue, fnum, tnum);

			List<String> key = new ArrayList<String>();
			key.add("index");
			key.add("name");
			key.add("id");
			key.add("statusNm");
			key.add("logintime");
			key.add("loginip");
			key.add("loginbr");

			pString = JsonUtil.jqgridPaser(key, list, totalCnt);
		}
		catch (Exception e) {
			pString = "Error : 데이터 조회 오류";
		}

		return pString;
	}

	public String getUserListByVal(String sType, String sValue, int pagerow)
	{
		String pString = "";

		try {
			int totalCnt = service.countUserList();
			int userRow = service.getUserRowByVal(sType, sValue);

			if (userRow > 0) {
				int pageno = ((userRow - 1) / pagerow) + 1;
				int tnum = pageno * pagerow;
				int fnum = tnum - pagerow + 1;
				log.debug("### UserList : {} ~ {}", fnum, tnum);

				ArrayList<Object> arraylist = service.getUserList(fnum, tnum);

				List<String> key = new ArrayList<String>();
				key.add("name");
				key.add("id");

				pString = JsonUtil.jqgridPaser(key, arraylist, totalCnt, pageno);
			}
			else {
				pString = "Error : 검색 자료가 없습니다.";
			}
		}
		catch (Exception e) {
			pString = "Error : 데이터 조회 오류 ";
		}

		return pString;
	}

	public String setUserUnlock(String adminid, String userId)
	{
		String pString = "";

		try {
			service.setUserUnlock(userId);

			StringBuilder sb = new StringBuilder();
			sb.append("사용자:" + userId);

			service.setAuditInfo(Util.getDateFormat("yyyyMMdd"), Util.getDateFormat("HHmmss"),
					adminid, "AQ", "0", sb.toString());

			pString = "{\"page\":1,\"total\":1,\"records\":1,\"rows\":[{\"resultstatus\":1,\"resultdata\":\"\"}]}";
		}
		catch (Exception e) {
			pString = "Error : 사용자 잠김 해제 오류";
		}

		return pString;
	}

	public String setUserLogout(String adminid, String userId)
	{
		String pString = "";

		try {
			// DPM
			DupClient.putLogout("dream", userId);

			StringBuilder sb = new StringBuilder();
			sb.append("사용자:" + userId + " 강제 로그아웃");

			service.setAuditInfo(Util.getDateFormat("yyyyMMdd"), Util.getDateFormat("HHmmss"),
					adminid, "BD", "0", sb.toString());

			pString = "{\"page\":1,\"total\":1,\"records\":1,\"rows\":[{\"resultstatus\":1,\"resultdata\":\"\"}]}";
		}
		catch (Exception e) {
			pString = "Error : 사용자 강제 로그아웃 오류";
		}

		return pString;
	}

	public String getUrpyInfo(String code)
	{
		String pString = "";

		try {
			List<Object> list = service.getUrpyInfo(code);

			List<String> key = new ArrayList<String>();
			key.add("pwMismatchAllow");
			key.add("pwChangeWarn");
			key.add("pwValidate");
			key.add("pollingTime");
			key.add("sessionTime");

			pString = JsonUtil.jqgridPaser(key, list);
		}
		catch (Exception e) {
			pString = "Error : 데이터 조회 오류";
		}

		return pString;
	}

	public String setUrpyInfo(String adminid, String ucode, String pwcnt, String pwwarn, String pwvalid,
			String polltime, String sesstime)
	{
		String pString = "";

		try {
			service.setUrpyInfo(ucode, pwcnt, pwwarn, pwvalid, polltime, sesstime);

			StringBuilder sb = new StringBuilder();
			sb.append("비밀번호 실패 허용 회수:" + pwcnt + "회");
			sb.append(", 비밀번호 유효기간:" + pwvalid + "일");
			sb.append(", 비밀번호 만료경고:" + pwwarn + "일");
			//sb.append(", 중복 로그인 체크 주기:" + polltime + "초");
			sb.append(", 세션 비활동 시간:" + sesstime + "분");

			service.setAuditInfo(Util.getDateFormat("yyyyMMdd"), Util.getDateFormat("HHmmss"),
					adminid, "AP", "0", sb.toString());

			pString = "{\"page\":1,\"total\":1,\"records\":1,\"rows\":[{\"resultstatus\":1,\"resultdata\":\"\"}]}";
		}
		catch (Exception e) {
			pString = "Error : 데이터 저장 오류";
		}

		return pString;
	}

	public String getUserList(int pageno, int pagerow)
	{
		String pString = "";

		try {
			int tnum = pageno * pagerow;
			int fnum = tnum - pagerow + 1;

			int totalCnt = service.countUserList();

			ArrayList<Object> arraylist = service.getUserList(fnum, tnum);

			List<String> key = new ArrayList<String>();
			key.add("name");
			key.add("id");

			pString = JsonUtil.jqgridPaser(key, arraylist, totalCnt, pageno);
		}
		catch (Exception e) {
			pString = "Error : 데이터 조회 오류 ";
		}

		return pString;
	}

	public String getUserLockedList(int fnum, int tnum)
	{
		String pString = "";

		try {
			int totalCnt = service.countUserLockedList();

			ArrayList<Object> arraylist = service.getUserLockedList(fnum, tnum);

			List<String> key = new ArrayList<String>();
			key.add("index");
			key.add("name");
			key.add("id");
			key.add("statusNm");

			pString = JsonUtil.jqgridPaser(key, arraylist, totalCnt);
		}
		catch (Exception e) {
			pString = "Error : 데이터 조회 오류 ";
		}

		return pString;
	}

	public String getUserInfo(String id)
	{
		String pString = "";

		try {
			List<Object> list = service.getUserInfo(id);

			List<String> key = new ArrayList<String>();
			key.add("name");
			key.add("id");

			pString = JsonUtil.jqgridPaser(key, list);
		}
		catch (Exception e) {
			pString = "Error : 데이터 조회 오류";
		}

		return pString;
	}

	public String setUserInfo(String adminid, String newflag, String id, String name, String pwd)
	{
		String pString = "";

		try {
			service.setUserInfo(newflag, id, name, pwd);

			StringBuilder sb = new StringBuilder();
			if (newflag.equals("1")) {
				sb.append("신규");
			}
			else {
				sb.append("수정");
			}
			sb.append(", 아이디:" + id);
			sb.append(", 이름:" + name);

			service.setAuditInfo(Util.getDateFormat("yyyyMMdd"), Util.getDateFormat("HHmmss"),
					adminid, "BE", "0", sb.toString());

			pString = "{\"page\":1,\"total\":1,\"records\":1,\"rows\":[{\"resultstatus\":1,\"resultdata\":\"\"}]}";
		}
		catch (Exception e) {
			pString = "Error : 데이터 저장 오류 ";
		}

		return pString;
	}

	public String removeUserInfo(String adminid, String uid)
	{
		String pString = "";

		try {
			service.removeUserInfo(uid);

			StringBuilder sb = new StringBuilder();
			sb.append("삭제, 아이디:" + uid);

			service.setAuditInfo(Util.getDateFormat("yyyyMMdd"), Util.getDateFormat("HHmmss"),
					adminid, "BE", "0", sb.toString());

			pString = "{\"page\":1,\"total\":1,\"records\":1,\"rows\":[{\"resultstatus\":1,\"resultdata\":\"\"}]}";
		}
		catch (Exception e) {
			pString = "Error : 데이터 삭제 오류";
		}

		return pString;
	}

	public String getUserAccessInfo(String uid, String fdate, String tdate, String stype, int fnum, int tnum)
	{
		String pString = "";

		try {
			int totalCnt = service.countUserAccessInfo(uid, fdate, tdate, stype);

			ArrayList<Object> arraylist = service.getUserAccessInfo(uid, fdate, tdate, stype, fnum, tnum);

			List<String> key = new ArrayList<String>();
			key.add("index");
			key.add("logDate");
			key.add("logTime");
			key.add("userId");
			key.add("userName");
			key.add("accessIp");
			key.add("accessBr");
			key.add("accessSp");
			key.add("accessType");
			key.add("accessRslt");

			pString = JsonUtil.jqgridPaser(key, arraylist, totalCnt);
		}
		catch (Exception e) {
			pString = "Error : 데이터 조회 오류";
			e.printStackTrace();
		}

		return pString;
	}

	public String getExcelAccessInfo(String uid, String fdate, String tdate, String stype, String adminid)
	{
		String pString = "";

		try {
			ArrayList<Object> arraylist = service.getExcelAccessInfo(uid, fdate, tdate, stype);

			if (arraylist.size() > 0) {
				SSOConfig config = SSOConfig.getInstance();
				String filename = "accesslog_" + Util.getDateFormat("yyyyMMddHHmmss") + "_" + adminid + ".xls";
				String path_filename = config.getSsoHomepath() + "/down/" + filename;
				//filename = filename.replace('\\', '/');
				log.debug("### Excel: {}", path_filename);

				File file = new File(path_filename);

				if (!file.exists()) {
					file.createNewFile();
				}

				WritableWorkbook workbook = Workbook.createWorkbook(file);
				WritableSheet sheet = workbook.createSheet("Sheet1", 0);
				Label label;

				label = new Label(0, 1, "No");  sheet.addCell(label);
				label = new Label(1, 1, "접속일시");  sheet.addCell(label);
				label = new Label(2, 1, "아이디");  sheet.addCell(label);
				label = new Label(3, 1, "이름");  sheet.addCell(label);
				label = new Label(4, 1, "IP");  sheet.addCell(label);
				label = new Label(5, 1, "브라우저");  sheet.addCell(label);
				label = new Label(6, 1, "서버ID");  sheet.addCell(label);
				label = new Label(7, 1, "접속타입");  sheet.addCell(label);
				label = new Label(8, 1, "접속결과");  sheet.addCell(label);

				for (int i = 0; i < arraylist.size(); i++) {
					UserAccessInfo access = (UserAccessInfo) arraylist.get(i);

					label = new Label(0, i+2, access.getIndex());  sheet.addCell(label);
					label = new Label(1, i+2, access.getLogDate() + " " + access.getLogTime());  sheet.addCell(label);
					label = new Label(2, i+2, access.getUserId());  sheet.addCell(label);
					label = new Label(3, i+2, access.getUserName());  sheet.addCell(label);
					label = new Label(4, i+2, access.getAccessIp());  sheet.addCell(label);
					label = new Label(5, i+2, access.getAccessBr());  sheet.addCell(label);
					label = new Label(6, i+2, access.getAccessSp());  sheet.addCell(label);
					label = new Label(7, i+2, access.getAccessType());  sheet.addCell(label);
					label = new Label(8, i+2, access.getAccessRslt());  sheet.addCell(label);
				}

				workbook.write();
				workbook.close();

				pString = "{\"page\":1,\"total\":1,\"records\":1,\"rows\":[{\"resultstatus\":1,\"resultdata\":\"" + filename + "\"}]}";
			}
			else {
				pString = "{\"page\":1,\"total\":1,\"records\":1,\"rows\":[{\"resultstatus\":-1,\"resultdata\":\"\"}]}";
			}
		}
		catch (Exception e) {
			pString = "Error : 데이터 조회 오류";
			e.printStackTrace();
		}

		return pString;
	}

	public String getStatsAccessInfo(String stype, String sdate)
	{
		String pString = "";

		try {
			ArrayList<Object> arraylist = null;

			if (stype.equals("1")) {
				arraylist = service.getStatsDateAccessInfo(sdate);
			}
			else if (stype.equals("2")) {
				arraylist = service.getStatsMonthAccessInfo(sdate);
			}
			else if (stype.equals("3")) {
				arraylist = service.getStatsYearAccessInfo(sdate);
			}
			else {
				pString = "Error : 파라미터 오류";
				return pString;
			}

			List<String> key = new ArrayList<String>();
			key.add("xvalue");
			key.add("lcount");
			key.add("ccount");
			key.add("ocount");

			pString = JsonUtil.jqgridPaser(key, arraylist);
		}
		catch (Exception e) {
			pString = "Error : 데이터 조회 오류";
			e.printStackTrace();
		}

		return pString;
	}

	public String getClientList()
	{
		String pString = "";

		try {
			List<Object> list = service.getClientList();

			List<String> key = new ArrayList<String>();
			key.add("name");
			key.add("id");
			key.add("protocol");

			pString = JsonUtil.jqgridPaser(key, list);
		}
		catch (Exception e) {
			pString = "Error : 데이터 조회 오류 ";
		}

		return pString;
	}

	public List<Object> listClientInfo()
	{
		try {
			return service.getClientList();
		}
		catch (Exception e) {
			e.printStackTrace();
		}

		return null;
	}

	public List<String> getClientIdList()
	{
		List<String> retList = new ArrayList<String>();

		try {
			List<Object> list = service.getClientList();

			for (int i = 0; i < list.size(); i++) {
				ClientVO clientVO = (ClientVO) list.get(i);
				retList.add(clientVO.getId());
			}
		}
		catch (Exception e) {
			e.printStackTrace();
		}

		return retList;
	}
	
	public String getClientInfo(String id)
	{
		String pString = "";

		try {
			List<Object> list = service.getClientInfo(id);

			SSOConfig config = SSOConfig.getInstance();
			String publicKey = Base64.encode(FileUtil.read(config.getHomePath() + "/cert/" + config.getServerName() + "_Sig.der"));
			ClientVO client = (ClientVO) list.get(0);
			client.setServerCert(publicKey);

			List<String> key = new ArrayList<String>();
			key.add("id");
			key.add("name");
			key.add("protocol");
			key.add("enabled");
			key.add("secret");
			key.add("nonce");
			key.add("pkce");
			key.add("refreshTokenUse");
			key.add("codeLifespan");
			key.add("tokenLifespan");
			key.add("refreshTokenLifespan");
			key.add("serverCert");

			pString = JsonUtil.jqgridPaser(key, list);
		}
		catch (Exception e) {
			pString = "Error : 데이터 조회 오류";
		}

		return pString;
	}
	
	public String getClientRedirect(String id)
	{
		String pString = "";
		try {
			List<Object> list = service.getClientRedirect(id);

			List<String> key = new ArrayList<String>();
			key.add("redirectUri");
			
			pString = JsonUtil.jqgridPaser(key, list);
		}
		catch (Exception e) {
			pString = "Error : 데이터 조회 오류";
		}

		return pString;
	}

	public List<Object> listClientRedirect(String id)
	{
		try {
			return service.listClientRedirect(id);
		}
		catch (Exception e) {
			e.printStackTrace();
		}

		return null;
	}

	public String getClientScope(String id)
	{
		String pString = "";
		try {
			List<Object> list = service.getClientScope(id);

			List<String> key = new ArrayList<String>();
			key.add("scope");
			key.add("enabled");
			
			pString = JsonUtil.jqgridPaser(key, list);
		}
		catch (Exception e) {
			pString = "Error : 데이터 조회 오류";
		}

		return pString;
	}

	public List<Object> listClientScope( String id)
	{
		try {
			return service.listClientScope(id);
		}
		catch (Exception e) {
			e.printStackTrace();
		}

		return null;
	}

	public String getScopeList()
	{
		String pString = "";

		try {
			List<Object> list = service.getScopeList();

			List<String> key = new ArrayList<String>();
			key.add("id");

			pString = JsonUtil.jqgridPaser(key, list);
		}
		catch (Exception e) {
			pString = "Error : 데이터 조회 오류 ";
		}

		return pString;
	}

	public String removeClient(String adminid, String id, String clientId)
	{
		String pString = "";

		try {
			service.removeClient(id);

			pString = "{\"page\":1,\"total\":1,\"records\":1,\"rows\":[{\"resultstatus\":1,\"resultdata\":\"\"}]}";

			ClientRepository clientRepository = ClientRepository.getInstance();
			clientRepository.removeClient(id);

			SyncMonitor.startMonitor();
			SyncMonitor.reloadOidcClientEvent();

			// Set License
			EnvironInform.getInstance().removeClientLicense(clientId);

			/***
			SSOConfig config = SSOConfig.getInstance();
			Util.deleteFile(config.getHomePath() + "/cert/" + clientId + "_Enc.der");
			Util.deleteFile(config.getHomePath() + "/cert/" + clientId + "_Sig.der");
			Util.deleteFile(config.getHomePath() + "/cert/CA/" + clientId + "_Enc.der");
			Util.deleteFile(config.getHomePath() + "/cert/CA/" + clientId + "_Enc.key");
			Util.deleteFile(config.getHomePath() + "/cert/CA/" + clientId + "_Sig.der");
			Util.deleteFile(config.getHomePath() + "/cert/CA/" + clientId + "_Sig.key");

			CredentialRepository.removeCredential(clientId);
			MetadataGenerator.removeMetadata(clientId);
			***/

			// Audit Log
			StringBuilder sb = new StringBuilder();
			sb.append("삭제, " + clientId);

			service.setAuditInfo(Util.getDateFormat("yyyyMMdd"), Util.getDateFormat("HHmmss"),
					adminid, "BF", "0", sb.toString());
		}
		catch (Exception e) {
			pString = "Error : 데이터 삭제 오류";
			e.printStackTrace();
		}

		return pString;
	}

	public String setClientInfo(String newflag ,String adminid, String id, String name, String protocol, String enabled,
			String nonce, String pkce, String refresh, String secret, String tokenLife, String refreshLife, String codeLife,
			String grantType, String responseType, String[] scopeList, String[] redirectUriList)
	{
		String pString = "";

		try {
			
			boolean newsecret = false;

			if (protocol.equals("OIDC") && Util.isEmpty(secret)) {
				secret = OIDCUtil.generateUUID();
				newsecret = true;
			}

			service.setClientInfo(newflag ,id, name, protocol, enabled, nonce, pkce, refresh, secret, tokenLife,
					refreshLife, codeLife, grantType, responseType, scopeList, redirectUriList);

			ClientRepository clientRepository = ClientRepository.getInstance();
			clientRepository.addClient(id, name, protocol, enabled, secret, nonce, pkce, refresh, codeLife, tokenLife,
					refreshLife, responseType, grantType, redirectUriList, scopeList);

			SyncMonitor.startMonitor();
			SyncMonitor.reloadOidcClientEvent();

			// Set License
			//EnvironInform.getInstance().setClientLicense(clientId);

			/***
			if (newflag.equals("1"))
				SSOCryptoApi.getInstance().generateServerCert(clientId);

			String asserturl = "";
			String logouturl = "";

			for (int i = 0; i < redirectUriList.length; i++) {
				String decData = URLDecoder.decode(redirectUriList[i], "UTF-8");
				int index = decData.indexOf("?");
				String redirectUri = (index >= 0) ? decData.substring(0, index) : decData;

				String logoutUri;
				index = redirectUri.indexOf("://");
				if (index >= 0) {
					index = redirectUri.indexOf("/", index + 3);
					logoutUri = (index >= 0) ? redirectUri.substring(0, index) : redirectUri;
				}
				else {
					logoutUri = redirectUri;
				}

				if (Util.isEmpty(asserturl)) {
					asserturl += redirectUri;
					logouturl += logoutUri + "/oidc/logout";
				}
				else {
					asserturl += "^" + redirectUri;
					logouturl += "^" + logoutUri + "/oidc/logout";
				}
			}

			MetadataGenerator.generateMetadata(clientId, "", asserturl, logouturl);
			***/

			// Audit Log
			StringBuilder sb = new StringBuilder();
			if (newflag.equals("1")) {
				sb.append("신규");
			}
			else {
				sb.append("수정");
			}
			sb.append(", " + id);
			if (enabled.equals("1")) {
				sb.append(", 사용");
			}
			else {
				sb.append(", 미사용");
			}
			if (nonce.equals("1")) {
				sb.append(", Nonce 사용");
			}
			else {
				sb.append(", Nonce 미사용");
			}
			if (pkce.equals("1")) {
				sb.append(", PKCE 사용");
			}
			else {
				sb.append(", PKCE 미사용");
			}
			if (refresh.equals("1")) {
				sb.append(", Refresh Token 사용");
			}
			else {
				sb.append(", Refresh Token 미사용");
			}
			sb.append(", Secret:" + secret);
			sb.append(", Token Lifespan:" + tokenLife);
			sb.append(", Refresh Token Lifespan:" + refreshLife);
			sb.append(", Code Lifespan:" + codeLife);
			sb.append(", Redirect URI:" + URLDecoder.decode(Arrays.toString(redirectUriList), "UTF-8"));
			sb.append(", Scope:" + Arrays.toString(scopeList));

			if (sb.toString().length() > 500)
				service.setAuditInfo(Util.getDateFormat("yyyyMMdd"), Util.getDateFormat("HHmmss"),
						adminid, "BF", "0", sb.toString().substring(0, 500));
			else
				service.setAuditInfo(Util.getDateFormat("yyyyMMdd"), Util.getDateFormat("HHmmss"),
						adminid, "BF", "0", sb.toString());

			if (protocol.equals("OIDC") && newsecret)
				pString = "{\"page\":1,\"total\":1,\"records\":1,\"rows\":[{\"resultstatus\":1,\"resultdata\":\"" + secret + "\"}]}";
			else
				pString = "{\"page\":1,\"total\":1,\"records\":1,\"rows\":[{\"resultstatus\":1,\"resultdata\":\"\"}]}";
		}
		catch (Exception e) {
			e.printStackTrace();
			pString = "Error : 데이터 저장 오류 ";
		}

		return pString;
	}

	public String removeScope(String adminid, String id)
	{
		String pString = "";

		try {
			service.removeScope(id);

			pString = "{\"page\":1,\"total\":1,\"records\":1,\"rows\":[{\"resultstatus\":1,\"resultdata\":\"\"}]}";

			ClientRepository clientRepository = ClientRepository.getInstance();
			clientRepository.loadClient();

			SyncMonitor.startMonitor();
			SyncMonitor.reloadOidcClientEvent();

			// Audit Log
			StringBuilder sb = new StringBuilder();
			sb.append("삭제, " + id);

			service.setAuditInfo(Util.getDateFormat("yyyyMMdd"), Util.getDateFormat("HHmmss"),
					adminid, "BG", "0", sb.toString());
		}
		catch (Exception e) {
			pString = "Error : 데이터 삭제 오류";
		}

		return pString;
	}
	
	public String setScope(String adminid, String id)
	{
		String pString = "";

		try {
			service.setScope(id);

			pString = "{\"page\":1,\"total\":1,\"records\":1,\"rows\":[{\"resultstatus\":1,\"resultdata\":\"\"}]}";

			ClientRepository clientRepository = ClientRepository.getInstance();
			clientRepository.loadClient();

			SyncMonitor.startMonitor();
			SyncMonitor.reloadOidcClientEvent();

			// Audit Log
			StringBuilder sb = new StringBuilder();
			sb.append("추가, " + id);

			service.setAuditInfo(Util.getDateFormat("yyyyMMdd"), Util.getDateFormat("HHmmss"),
					adminid, "BG", "0", sb.toString());
		}
		catch (Exception e) {
			e.printStackTrace();
			pString = "Error : 데이터 저장 오류 ";
		}

		return pString;
	}

	public String setUserChangePwd(String adminid, String id, String name, String pwd)
	{
		String pString = "";

		try {
			service.setUserChangePwd(id, name, pwd);

			StringBuilder sb = new StringBuilder();
			sb.append("수정");

			sb.append(", 아이디:" + id);
			sb.append(", 이름:" + name);

			service.setAuditInfo(Util.getDateFormat("yyyyMMdd"), Util.getDateFormat("HHmmss"),
					adminid, "BE", "0", sb.toString());

			pString = "{\"page\":1,\"total\":1,\"records\":1,\"rows\":[{\"resultstatus\":1,\"resultdata\":\"\"}]}";
		}
		catch (Exception e) {
			pString = "Error : 데이터 저장 오류 ";
		}

		return pString;
	}
}