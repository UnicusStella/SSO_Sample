package com.dreamsecurity.sso.server.util;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.net.InetAddress;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.UnknownHostException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.text.DateFormat;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Date;
import java.util.Enumeration;
import java.util.List;
import java.util.UUID;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.w3c.dom.Document;

import com.dreamsecurity.jcaos.util.encoders.Base64;
import com.dreamsecurity.sso.lib.slf.Logger;
import com.dreamsecurity.sso.lib.slf.LoggerFactory;
import com.dreamsecurity.sso.server.api.audit.service.AuditService;
import com.dreamsecurity.sso.server.config.SSOConfig;
import com.dreamsecurity.sso.server.crypto.CryptoApiException;
import com.dreamsecurity.sso.server.crypto.SSOCryptoApi;

public class Util
{
	private static Logger log = LoggerFactory.getLogger(Util.class);

	public static void zeroize(String str) throws Exception
	{
		if (str != null) {
			Field field = str.getClass().getDeclaredField("value");
			field.setAccessible(true);

			if (field.get(str) instanceof char[]) {
				final char value[] = (char[]) field.get(str);
				Arrays.fill(value, '0');
			}
			else if (field.get(str) instanceof byte[]) {
				final byte value[] = (byte[]) field.get(str);
				for (int i = 0; i < value.length; i++)
					value[i] = 0x00;
			}
			else {
				str = null;
			}
		}

		return;
	}

	public static void zeroize(StringBuilder str)
	{
		if (str != null) {
			for (int i = 0; i < str.length(); i++)
				str.setCharAt(i, '0');
		}

		return;
	}

	public static void zeroize(StringBuffer str)
	{
		if (str != null) {
			for (int i = 0; i < str.length(); i++)
				str.setCharAt(i, '0');
		}

		return;
	}

	public static byte[] zeroize(byte[] input)
	{
		if (input == null)
			return input;

		for (int i = 0; i < input.length; i++)
			input[i] = 0x00;

		input = null;

		return input;
	}

	public static int bytesToInt(byte[] src, int srcOff)
	{
		int word = 0;

		for (int i = 0; i < 4; i++)
			word = (word << 8) + (src[i + srcOff] & 0xff);

		return word;
	}

	public static void intToBytes(byte[] dest, int destOff, int value)
	{
		for (int i = 0; i < 4; i++)
			dest[i + destOff] = (byte) (value >> ((3 - i) * 8));
	}

	public static int bytes2SaltInt(byte[] src, int srcOff, byte[] salt)
	{
		int word = 0;

		for (int j = 0; j < 4; j++)
			src[j] ^= ~salt[j];

		for (int i = 0; i < 4; i++)
			word = (word << 8) + (src[i + srcOff] & 0xff);

		return word;
	}

	public static byte[] int2SaltBytes(int value, int destOff, byte[] salt)
	{
		byte[] bytes = new byte[4];

		for (int i = 0; i < 4; i++)
			bytes[i + destOff] = (byte) (value >> ((3 - i) * 8));

		for (int j = 0; j < 4; j++)
			bytes[j] ^= ~salt[j];

		return bytes;
	}

	public static String[] list2StringArray(List list)
	{
		String[] values = new String[list.size()];
		list.toArray(values);

		return values;
	}

	public static boolean isEmpty(String str)
	{
		return str == null || str.equals("");
	}

	public static byte[] concatBytes(byte[] firstBytes, byte[] nextBytes)
	{
		byte[] bytes = new byte[firstBytes.length + nextBytes.length];

		System.arraycopy(firstBytes, 0, bytes, 0, firstBytes.length);
		System.arraycopy(nextBytes, 0, bytes, firstBytes.length, nextBytes.length);
		return bytes;
	}

	public static void splitBytes(byte[] source, byte[] firstBytes, byte[] nextBytes)
	{
		System.arraycopy(source, 0, firstBytes, 0, firstBytes.length);
		System.arraycopy(source, firstBytes.length, nextBytes, 0, nextBytes.length);
	}

	public static boolean compareBytes(byte[] source, byte[] dest)
	{
		if (source.length != dest.length)
			return false;

		for (int i = 0; i < source.length; i++)
			if (source[i] != dest[i])
				return false;

		return true;
	}

	public static String parseDomain(String url)
	{
		String doamin;

		int i = url.indexOf("http://");
		int j = url.indexOf("https://");

		if (i >= 0) {
			doamin = url.substring("http://".length());

			i = doamin.indexOf("/");
			if (i >= 0)
				doamin = doamin.substring(0, i);

			i = doamin.indexOf(":");
			if (i >= 0)
				doamin = doamin.substring(0, i);
		}
		else if (j >= 0) {
			doamin = url.substring("https://".length());

			j = doamin.indexOf("/");
			if (j >= 0)
				doamin = doamin.substring(0, j);

			j = doamin.indexOf(":");
			if (j >= 0)
				doamin = doamin.substring(0, j);
		}
		else {
			doamin = "";
		}

		return doamin;
	}

	public static boolean equals(String str1, String sep1, String str2, String sep2)
	{
		String[] div1 = str1.split(sep1);
		String[] div2 = str2.split(sep2);

		for (int i = 0; i < div1.length; i++) {
			for (int j = 0; j < div2.length; j++) {
				if (div1[i].trim().equals(div2[j].trim()))
					return true;
			}
		}

		return false;
	}

	public static String getURL(HttpServletRequest request, String path)
	{
		URL returnURL = null;

		try {
			returnURL = new URL(path);
		}
		catch (MalformedURLException e) {
			int sport = request.getServerPort();

			try {
				if (sport == 80)
					returnURL = new URL(request.getScheme() + "://" + request.getServerName() + path);
				else
					returnURL = new URL(request.getScheme() + "://" + request.getServerName() + ":" + sport + path);
			}
			catch (Exception ex) {
				if (sport == 80)
					return request.getScheme() + "://" + request.getServerName() + "/" + path;
				else
					return request.getScheme() + "://" + request.getServerName() + ":" + sport + "/" + path;
			}
		}

		return returnURL.toString();
	}

	public static String getRequestParam(HttpServletRequest request, String key)
	{
		return request.getParameter(key) == null ? "" : request.getParameter(key);
	}

	public static String generateUUID()
	{
		UUID uudi = UUID.randomUUID();
		return "IDP-" + uudi.toString();
	}

	public static long getTime()
	{
		return System.currentTimeMillis();
	}

	public static String getDateFormat(String format)
	{
		DateFormat sdf = new SimpleDateFormat(format);
		return sdf.format(new Date());
	}

	public static String addDate(String baseDate, String pattern, int field, int amount)
	{
		String result = null;
		SimpleDateFormat dateFormat = new SimpleDateFormat(pattern);
		Calendar calendar = Calendar.getInstance();

		try {
			calendar.setTime(dateFormat.parse(baseDate));
			calendar.add(field, amount);
			result = dateFormat.format(calendar.getTime());
		}
		catch (ParseException e) {
			result = baseDate;
		}

		return result;
	}

	public static long diffDays(String baseDate, String pattern)
	{
		long result = 0;
		SimpleDateFormat dateFormat = new SimpleDateFormat(pattern);
		Calendar currDate = Calendar.getInstance();
		Calendar fromDate = Calendar.getInstance();

		try {
			currDate.setTime(new Date());
			fromDate.setTime(dateFormat.parse(baseDate));
			result = (currDate.getTimeInMillis() - fromDate.getTimeInMillis()) / (24*60*60*1000);
		}
		catch (ParseException e) {
			result = 0;
		}

		return result;
	}

	public static String getClientIP(HttpServletRequest request)
	{
		String getMethod = SSOConfig.getInstance().getClientIPMethod();
		String clientIP = "";

		if (getMethod.equals("RemoteAddr")) {
			clientIP = request.getRemoteAddr();
		}
		else {
			clientIP = request.getHeader(getMethod);
		}

		return clientIP;
	}

	public static String getClientIP(HttpServletRequest request, String headerKey)
	{
		String clientIP = "";

		clientIP = request.getHeader(headerKey);

		return clientIP;
	}

	public static String getCookieValue(HttpServletRequest request, String name)
	{
		Cookie[] cookies = request.getCookies();

		if (cookies != null) {
			for (Cookie c : cookies) {
				if (c.getName().equals(name))
					return c.getValue();
			}
		}

		return null;
	}

	public static String getServerIP()
	{
		StringBuffer sb = new StringBuffer();

		try {
			Class<?> CNetworkInterface = Class.forName("java.net.NetworkInterface");
			Method getNetworkInterfaces = CNetworkInterface.getMethod("getNetworkInterfaces", null);
			Enumeration ifaces = (Enumeration) getNetworkInterfaces.invoke(CNetworkInterface, null);

			for (; ifaces.hasMoreElements();) {
				Object oNetworkInterface = ifaces.nextElement();
				InetAddress ia = null;
				Method getInetAddresses = oNetworkInterface.getClass().getMethod("getInetAddresses", null);
				Enumeration ips = (Enumeration) getInetAddresses.invoke(oNetworkInterface, null);

				for (; ips.hasMoreElements();) {
					ia = (InetAddress) ips.nextElement();
					String hostAddress = ia.getHostAddress();

					// IP v4 형태의 HostAddress 만을 획득하기 위함
					if (hostAddress.indexOf('.') != -1)
						if (!hostAddress.equals("127.0.0.1"))
							sb.append(hostAddress + ";");
				}
			}
		}
		catch (ClassNotFoundException e) {
			try {
				InetAddress[] ias = InetAddress.getAllByName(InetAddress.getLocalHost().getHostName());

				// ipv6 ip 는 SKIP (ipv6 는 길이가 15 가 넘음)
				for (int i = 0; i < ias.length; i++) {
					if (ias[i].getHostAddress().length() <= 15)
						if (!ias[i].getHostAddress().equals("127.0.0.1"))
							sb.append(ias[i].getHostAddress() + ";");
				}
			}
			catch (UnknownHostException e1) {
				e1.printStackTrace();
			}
		}
		catch (Exception e) {
			e.printStackTrace();
		}

		return sb.toString();
	}

	public static String getBaseURL(HttpServletRequest request)
	{
		return request.getScheme() + "://" + request.getServerName() + ":" + request.getServerPort() + request.getContextPath();
	}

	public static String getBrowserType(HttpServletRequest request)
	{
		String browser = "";
		String userAgent = request.getHeader("User-Agent").toLowerCase();

		if (userAgent.indexOf("trident") >= 0 || userAgent.indexOf("msie") >= 0) {
			browser = "IE";
		}
		else if (userAgent.indexOf("edg") >= 0) {
			browser = "EG";
		}
		else if (userAgent.indexOf("opr") >= 0 || userAgent.indexOf("opera") >= 0) {
			browser = "OP";
		}
		else if (userAgent.indexOf("chrome") >= 0) {
			browser = "CR";
		}
		else if (userAgent.indexOf("safari") >= 0) {
			browser = "SF";
		}
		else if (userAgent.indexOf("firefox") >= 0) {
			browser = "FF";
		}
		else {
			browser = "NN";
		}

		return browser;
	}

	public static void deleteFile(String path)
	{
		try {
			File delFile = new File(path);

			if (delFile.exists()) {
				delFile.delete();
			}
		}
		catch (Exception e) {
			e.printStackTrace();
		}
	}

	public static String domToStr(Document doc, boolean indent)
	{
		try {
			DOMSource domSource = new DOMSource(doc);
			StringWriter writer = new StringWriter();
			StreamResult result = new StreamResult(writer);
			TransformerFactory tf = TransformerFactory.newInstance();
			Transformer transformer = tf.newTransformer();

			String encoding = new OutputStreamWriter(System.out).getEncoding();

			if (!"UTF8".equals(encoding)) {
				transformer.setOutputProperty(OutputKeys.ENCODING, "EUC-KR");
			}

			if (indent) {
				transformer.setOutputProperty(OutputKeys.INDENT, "yes");
				transformer.setOutputProperty("{http://xml.apache.org/xslt}indent-amount", "4");
			}

			transformer.transform(domSource, result);
			return writer.toString();
		}
		catch (TransformerException ex) {
			ex.printStackTrace();
			return null;
		}
	}

	public static String domToStr(Document doc, boolean indent, String encoding)
	{
		try {
			DOMSource domSource = new DOMSource(doc);
			StringWriter writer = new StringWriter();
			StreamResult result = new StreamResult(writer);
			TransformerFactory tf = TransformerFactory.newInstance();
			Transformer transformer = tf.newTransformer();

			transformer.setOutputProperty(OutputKeys.ENCODING, encoding);

			if (indent) {
				transformer.setOutputProperty(OutputKeys.INDENT, "yes");
				transformer.setOutputProperty("{http://xml.apache.org/xslt}indent-amount", "4");
			}

			transformer.transform(domSource, result);
			return writer.toString();
		}
		catch (TransformerException e) {
			e.printStackTrace();
			return null;
		}
	}

	public static Document createDomDoc(String xmlString)
	{
		DocumentBuilderFactory objDocBuilderFactory = DocumentBuilderFactory.newInstance();
		objDocBuilderFactory.setNamespaceAware(true);

		try {
			DocumentBuilder objDocBuilder = objDocBuilderFactory.newDocumentBuilder();
			return objDocBuilder.parse(new ByteArrayInputStream(xmlString.getBytes()));
		}
		catch (Exception e) {
			e.printStackTrace();
		}

		return null;
	}

	public static Document createDomDoc(byte[] xmlByte)
	{
		DocumentBuilderFactory objDocBuilderFactory = DocumentBuilderFactory.newInstance();
		objDocBuilderFactory.setNamespaceAware(true);

		try {
			DocumentBuilder objDocBuilder = objDocBuilderFactory.newDocumentBuilder();
			return objDocBuilder.parse(new ByteArrayInputStream(xmlByte));
		}
		catch (Exception e) {
			e.printStackTrace();
		}

		return null;
	}

	public static X509Certificate getCert(String certFilepath)
	{
		try {
			InputStream pubKey = new FileInputStream(certFilepath);
			CertificateFactory certificateFactory = CertificateFactory.getInstance("X509");

			return (X509Certificate) certificateFactory.generateCertificate(pubKey);
		}
		catch (Exception e) {
			e.printStackTrace();
		}

		return null;
	}

	public static String createLoginCSRFToken(HttpServletRequest request)
	{
		String challenge = "";

		try {
			challenge = SSOCryptoApi.getInstance().createRandom(16);
		}
		catch (CryptoApiException e) {
			e.printStackTrace();
		}

		HttpSession session = request.getSession(true);
		session.setAttribute("LACHLG", challenge);

		return challenge;
	}

	public static void sendURL(HttpServletResponse response, String target)
	{
		try {
			StringBuffer str = new StringBuffer();
			str.append("<html>\n");
			str.append("<head>\n");
			str.append("<meta http-equiv=\"Content-Type\" content=\"text/html; charset=UTF-8\">\n");
			str.append("<title></title>\n");
			str.append("<script type=\"text/javascript\" defer=\"defer\">\n");
			str.append("function goNext() {\n");
			str.append("    var frm = document.getElementById(\"ssoForm\");\n");
			str.append("    frm.action = \"").append(target).append("\";\n");
			str.append("    frm.target = \"_parent\";\n");
			str.append("    frm.submit();\n");
			str.append("}\n");
			str.append("</script>\n");
			str.append("</head>\n");
			str.append("<body onload=\"goNext(); return false;\">\n");
			str.append("<form id=\"ssoForm\" name=\"ssoForm\" method=\"post\">\n");
			str.append("</form>\n");
			str.append("</body>\n");
			str.append("</html>");

			response.setHeader("Content-Type", "text/html; charset=UTF-8");

			PrintWriter out = response.getWriter();
			out.write(str.toString());
			out.flush();
		}
		catch (Exception e) {
			e.printStackTrace();
		}
	}

	public static void sendIDPLoginURL(HttpServletResponse response, String target, String relayState)
	{
		sendIDPLoginURL(response, target, relayState, "");
	}

	public static void sendIDPLoginURL(HttpServletResponse response, String target, String relayState, String agentType)
	{
		try {
			StringBuffer str = new StringBuffer();
			str.append("<html>\n");
			str.append("<head>\n");
			str.append("<meta http-equiv=\"Content-Type\" content=\"text/html; charset=UTF-8\">\n");
			str.append("<title></title>\n");
			str.append("<script type=\"text/javascript\">\n");
			str.append("function goNext() {\n");
			str.append("    var frm = document.getElementById(\"ssoForm\");\n");
			str.append("    frm.action = \"").append(target).append("\";\n");
			str.append("    frm.target = \"_parent\";\n");
			str.append("    frm.submit();\n");
			str.append("}\n");
			str.append("</script>\n");
			str.append("</head>\n");
			str.append("<body onload=\"goNext(); return false;\">\n");
			str.append("<form id=\"ssoForm\" name=\"ssoForm\" method=\"post\">\n");
			str.append("    <input type=\"hidden\" id=\"RelayState\" name=\"RelayState\" value=\"");
			if (!isEmpty(relayState)) {
				str.append(relayState);
			}
			str.append("\"/>\n");
			str.append("    <input type=\"hidden\" id=\"AT\" name=\"AT\" value=\"");
			if (!isEmpty(agentType)) {
				str.append(agentType);
			}
			str.append("\"/>\n");
			str.append("</form>\n");
			str.append("</body>\n");
			str.append("</html>");

			response.setHeader("Content-Type", "text/html; charset=UTF-8");

			PrintWriter out = response.getWriter();
			out.write(str.toString());
			out.flush();
		}
		catch (Exception e) {
			e.printStackTrace();
		}
	}

	public static void sendURL(HttpServletResponse response, String target, String dupinfo)
	{
		try {
			int nIdx = target.indexOf("nxResult");
			String dupMsg = "";

			if (!Util.isEmpty(dupinfo)) {
				dupMsg = "다른 자리( " + dupinfo + " )에서 동일 아이디로 로그인하여\n 자동 로그아웃합니다.";
			}

			StringBuffer str = new StringBuffer();
			str.append("<html>\n");
			str.append("<head>\n");
			str.append("<meta http-equiv=\"Content-Type\" content=\"text/html; charset=UTF-8\">\n");
			str.append("<title></title>\n");
			str.append("<script type=\"text/javascript\">\n");

			if (!Util.isEmpty(dupinfo) && nIdx == -1) {
				str.append("alert(\" ").append(dupMsg).append("\");\n");
			}

			str.append("function goNext() {\n");
			str.append("    var frm = document.getElementById(\"ssoForm\");\n");
			str.append("    frm.action = \"").append(target).append("\";\n");

			if (nIdx == -1) {
				str.append("    frm.target = \"_parent\";\n");
			}

			str.append("    frm.submit();\n");
			str.append("}\n");
			str.append("</script>\n");
			str.append("</head>\n");
			str.append("<body onload=\"goNext(); return false;\">\n");
			str.append("<form id=\"ssoForm\" name=\"ssoForm\" method=\"post\">\n");

			if (nIdx != -1) {  // nexacro
				str.append("    <input type=\"hidden\" id=\"ecode\" name=\"ecode\" value=\"0\"/>\n");
				str.append("    <input type=\"hidden\" id=\"emessage\" name=\"emessage\" value=\"\"/>\n");
				str.append("    <input type=\"hidden\" id=\"data\" name=\"data\" value=\"\"/>\n");
				str.append("    <input type=\"hidden\" id=\"dup\" name=\"dup\" value=\"").append(dupMsg).append("\"/>\n");
			}

			str.append("</form>\n");
			str.append("</body>\n");
			str.append("</html>");

			response.setHeader("Content-Type", "text/html; charset=UTF-8");

			PrintWriter out = response.getWriter();
			out.write(str.toString());
			out.flush();
		}
		catch (Exception e) {
			e.printStackTrace();
		}
	}

	public static void sendErrorURL(HttpServletResponse response, String target, String code, String message)
	{
		try {
			if (!Util.isEmpty(message)) {
				message = message.replace("\n", "");
			}
			else {
				message = "";
			}

			log.debug("### error code: {}, message: {}", code, message);

			StringBuffer str = new StringBuffer();
			str.append("<html>\n");
			str.append("<head>\n");
			str.append("<meta http-equiv=\"Content-Type\" content=\"text/html; charset=UTF-8\">\n");
			str.append("<title></title>\n");
			str.append("<script type=\"text/javascript\" defer=\"defer\">\n");
			str.append("function goNext() {\n");
			str.append("    var frm = document.getElementById(\"ssoForm\");\n");
			str.append("    frm.action = \"").append(target).append("\";\n");
			str.append("    frm.submit();\n");
			str.append("}\n");
			str.append("</script>\n");
			str.append("</head>\n");
			str.append("<body onload=\"goNext(); return false;\">\n");
			str.append("<form id=\"ssoForm\" name=\"ssoForm\" method=\"post\">\n");
			str.append("    <input type=\"hidden\" id=\"ecode\" name=\"ecode\" value=\"").append(code).append("\"/>\n");
			str.append("    <input type=\"hidden\" id=\"emessage\" name=\"emessage\" value=\"").append(message).append("\"/>\n");
			str.append("</form>\n");
			str.append("</body>\n");
			str.append("</html>");

			response.setHeader("Content-Type", "text/html; charset=UTF-8");

			PrintWriter out = response.getWriter();
			out.write(str.toString());
			out.flush();
		}
		catch (Exception e) {
			e.printStackTrace();
		}
	}

	public static void sendSPLogoutURL(HttpServletResponse response, String spLogoutInfo, String dupinfo, String brclose, String relayState)
	{
		try {
			String target = "";
			String others = "";
			String[] div = spLogoutInfo.split("\\^");

			if (div.length > 1) {
				int idx = spLogoutInfo.indexOf("^");
				target = spLogoutInfo.substring(0, idx);
				others = spLogoutInfo.substring(idx + 1);
			}
			else {
				target = spLogoutInfo;
				others = "";
			}

			StringBuffer str = new StringBuffer();
			str.append("<html>\n");
			str.append("<head>\n");
			str.append("<meta http-equiv=\"Content-Type\" content=\"text/html; charset=UTF-8\">\n");
			str.append("<title></title>\n");
			str.append("<script type=\"text/javascript\" defer=\"defer\">\n");
			str.append("function goNext() {\n");
			str.append("    var frm = document.getElementById(\"ssoForm\");\n");
			str.append("    frm.action = \"").append(target).append("\";\n");
			str.append("    frm.submit();\n");
			str.append("}\n");
			str.append("</script>\n");
			str.append("</head>\n");
			str.append("<body onload=\"goNext(); return false;\">\n");
			str.append("<form id=\"ssoForm\" name=\"ssoForm\" method=\"post\">\n");
			str.append("    <input type=\"hidden\" id=\"others\" name=\"others\" value=\"").append(others).append("\"/>\n");
			str.append("    <input type=\"hidden\" id=\"dup\" name=\"dup\" value=\"").append(dupinfo).append("\"/>\n");
			str.append("    <input type=\"hidden\" id=\"cl\" name=\"cl\" value=\"").append(brclose).append("\"/>\n");
			str.append("    <input type=\"hidden\" id=\"RelayState\" name=\"RelayState\" value=\"").append(relayState).append("\"/>\n");
			str.append("</form>\n");
			str.append("</body>\n");
			str.append("</html>");

			response.setHeader("Content-Type", "text/html; charset=UTF-8");

			PrintWriter out = response.getWriter();
			out.write(str.toString());
			out.flush();
		}
		catch (Exception e) {
			e.printStackTrace();
		}
	}

	public static void closeURL(HttpServletResponse response)
	{
		try {
			StringBuffer str = new StringBuffer();
			str.append("<html>\n");
			str.append("<head>\n");
			str.append("<meta http-equiv=\"Content-Type\" content=\"text/html; charset=UTF-8\">\n");
			str.append("<title></title>\n");
			str.append("<script type=\"text/javascript\">\n");
			str.append("self.opener = self;");
			str.append("window.close();");
			str.append("</script>\n");
			str.append("</html>\n");

			response.setHeader("Content-Type", "text/html; charset=UTF-8");

			PrintWriter out = response.getWriter();
			out.write(str.toString());
			out.flush();
		}
		catch (Exception e) {
			e.printStackTrace();
		}
	}

	public static String getAttribute(HttpServletRequest request, String key)
	{
		String result = request.getAttribute(key) == null ? "" : (String) request.getAttribute(key);

		if (isEmpty(result)) {
			result = request.getParameter(key) == null ? "" : request.getParameter(key);
		}

		return result;
	}

	public static String getAttribute(HttpSession session, String key)
	{
		return session.getAttribute(key) == null ? "" : (String) session.getAttribute(key);
	}

	public static String encode64(byte[] source)
	{
		return new String(Base64.encode(source));
	}

	public static byte[] decode64(String encodedtext) throws Exception
	{
		return Base64.decode(encodedtext);
	}

	public static void setAuditInfo(String logDate, String logTime, String caseUser, String caseType, String caseResult, String caseData)
	{
		String detailData = caseData.length() > 500 ? caseData.substring(0, 500) : caseData;

		AuditService auditApi = new AuditService();
		auditApi.setAuditInfo(logDate, logTime, caseUser, caseType, caseResult, detailData);
	}

	public static void setAuditInfo(String caseUser, String caseType, String caseResult, String caseData)
	{
		String detailData = caseData.length() > 500 ? caseData.substring(0, 500) : caseData;

		AuditService auditApi = new AuditService();
		auditApi.setAuditInfo(caseUser, caseType, caseResult, detailData);
	}

	public static void setAuditInfo(String encType, String encData)
	{
		AuditService auditApi = new AuditService();
		auditApi.setAuditInfo(encType, encData);
	}

	public static void sendMail(String code, String time, String param1, String param2)
	{
		AuditService auditApi = new AuditService();
		auditApi.sendMail(code, time, param1, param2);
	}

}