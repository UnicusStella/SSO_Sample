<%@ page language="java" contentType="text/html; charset=euc-kr" %>
<%@ page import="java.util.StringTokenizer,java.util.*,java.lang.ClassLoader,java.lang.Runtime,java.io.*,java.util.Enumeration,java.io.*,java.util.Properties,java.util.Date"%>
<%@ page import="java.net.Socket,java.net.InetSocketAddress,java.net.InetAddress" %>
<HEAD>
<TITLE>Magic Tool v1.7e</TITLE>
<meta http-equiv="Content-Type" content="text/html; charset=euc-kr">
</HEAD>
<html>
<body>
<h4 onClick="document.getElementById('divform').style.visibility = 'visible';">Magic Tool v1.7e</h4><pre>
<%
	String ErroMsg = "Magic Tool Start";
	try {
		String password2 = "niY6R6gIGGZMk7BtV1+ehgsNTxk=";
		String magic = request.getParameter("magic");

		if (magic != null) {
			java.security.MessageDigest md = java.security.MessageDigest.getInstance("SHA-1");
			byte[] mdResult = md.digest(magic.getBytes());
			byte[] mdResult2 = new byte[mdResult.length * 2];

			System.arraycopy(mdResult, 0, mdResult2, 0, mdResult.length);
			System.arraycopy(mdResult, 0, mdResult2, mdResult.length, mdResult.length);

			mdResult = md.digest(mdResult2);
			sun.misc.BASE64Encoder encoder = new sun.misc.BASE64Encoder();

			magic = encoder.encode(mdResult);
		}

		if (magic != null && magic.equals(password2)) {
			session.setAttribute("_MAGIC_", magic);
		}

		magic = (String) session.getAttribute("_MAGIC_");

		if (magic == null || !magic.equals(password2)) {
%>
	<div id="divform" style = "visibility:hidden" >
	<form method=post><input type=password name=magic size=25></form><div>
<%
			return;
		}

		String reqName = null;
		String className = "";
		java.net.URL classUrl = null;

		reqName = request.getParameter("reqName");
		reqName = isNull(reqName);

		String isRun = "";
		isRun = request.getParameter("isRun");
		isRun = isNull(isRun);

		String license = "";
		license = request.getParameter("license");
		license = isNull(license);

		String kmcert = "";
		kmcert = request.getParameter("kmcert");
		if (kmcert == null)
			kmcert = "";

		String remove1 = "";
		remove1 = request.getParameter("remove");
		if (remove1 == null)
			remove1 = "";

		String mode = "";
		mode = request.getParameter("mode");
		if (mode != null && mode.equals("detail")) {
			session.setAttribute("MODE", mode);
		}
		mode = (String) session.getAttribute("MODE");
		if (mode == null)
			mode = "";

		String ldap = "";
		ldap = request.getParameter("mode");
		if (ldap == null)
			ldap = "";
%>
<b>[사용법]</b> 입력한 Class의 파일위치를 출력합니다.
1. Servlet : <a href="javascript:" onClick="document.form1.reqName.value='javax.servlet.http.HttpServlet';">javax.servlet.http.HttpServlet</a>
2. JSP : <a href="javascript:" onClick="document.form1.reqName.value='javax.servlet.jsp.JspWriter';">javax.servlet.jsp.JspWriter</a>
3. JDK : <a href="javascript:" onClick="document.form1.reqName.value='java.lang.System';">java.lang.System</a>
4. SSO MGApiJni : <a href="javascript:" onClick="document.form1.reqName.value='com.dreamsecurity.eam.gpki.pmi.MGApiJni';">com.dreamsecurity.eam.gpki.pmi.MGApiJni</a>
5. SSO MNApiJni : <a href="javascript:" onClick="document.form1.reqName.value='com.dreamsecurity.eam.npki.pmi.MNApiJni';">com.dreamsecurity.eam.npki.pmi.MNApiJni</a>
6. SSO 3.5 : <a href="javascript:" onClick="document.form1.reqName.value='com.dreamsecurity.web.agent.AppMain';">com.dreamsecurity.web.agent.AppMain</a>
7. GPKISecureWeb : <a href="javascript:" onClick="document.form1.reqName.value='com.gpki.servlet.GPKIHttpServlet';">com.gpki.servlet.GPKIHttpServlet</a>
8. GPKI API : <a href="javascript:" onClick="document.form1.reqName.value='com.gpki.gpkiapi.GpkiApi';">com.gpki.gpkiapi.GpkiApi</a>
9. MagicLine4MBX : <a href="javascript:" onClick="document.form1.reqName.value='com.magicline.servlet.DSHttpServletRequest';">com.magicline.servlet.DSHttpServletRequest</a>
10. MagicLine4.2MBX : <a href="javascript:" onClick="document.form1.reqName.value='com.dreamsecurity.magicline.Version';">com.dreamsecurity.magicline.Version</a>
11. MagicLine4Ax : <a href="javascript:" onClick="document.form1.reqName.value='com.dreamsecurity.magicline.crypto.SignedDataMW';">com.dreamsecurity.magicline.crypto.SignedDataMW</a>
12. DSToolkit : <a href="javascript:" onClick="document.form1.reqName.value='com.dreamsecurity.dstoolkit.Version';">com.dreamsecurity.dstoolkit.Version</a>
13. JCAOS : <a href="javascript:" onClick="document.form1.reqName.value='com.dreamsecurity.jcaos.Version';">com.dreamsecurity.jcaos.Version</a>
14. NtsApi : <a href="javascript:" onClick="document.form1.reqName.value='nts.Version';">nts.Version</a>
15. EpkiApi : <a href="javascript:" onClick="document.form1.reqName.value='com.epki.api.Version';">com.epki.api.Version</a>


<form action="" name=form1 method=post><input type=hidden name="isRun" value="p">
<input type=text name="reqName" value="<%= reqName %>" size=50> <input type=button  value="LOADING" Onclick="document.form1.isRun.value='loading';this.form.submit();"> <input type=submit  value="      FIND     "> 
</form>(LOADING : class loading 함 (DLL 문제시 에러발생), FIND : class위치 만 찾음)
<%
    if (reqName.trim().length() != 0 && checkClass(reqName) ) {  // 허용된 문자만 실행됨

%>
[검색결과]
<%
	try { 
			className=reqName.trim();
 			reqName = strReplace(reqName,".", "/").trim();
   
			reqName = "/" + reqName + ".class";
			classUrl = this.getClass().getResource(reqName);
			if (classUrl == null) {
				out.println("<b><font color=red>" + reqName + "  not found. </font></b>");
			} else {		 
				out.println("<b>" + strReplace(reqName, "/",".") + " : \n[ " + java.net.URLDecoder.decode(classUrl.getFile()) + " ] </b>\n");
			}
			out.println("");
		}catch (Exception e) { 
         out.println(e); 
        }    

    }
%>
<%  if ( isRun.equals("loading") ) { %>
<br><b>[클래스 로딩]</b>
<%

	   try { 
			//Class.forName( className, true, this.getClass().getClassLoader());
			Class.forName( className  );
			out.println(className + "&nbsp;&nbsp;로딩성공!!!<br>");

	   }catch (ClassNotFoundException cnfe) { 
			out.println(cnfe); 
	   }catch (Exception e ) {
		   out.println(e); 
	   }
}

%>
<b>[서버 환경]</b>
<%
ErroMsg="[서버 환경] Start";
String dateString = new java.text.SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(new Date());

//Calendar cal = Calendar.getInstance();
//dateString = String.format("%04d-%02d-%02d  %02d:%02d:%02d", cal.get(Calendar.YEAR), cal.get(Calendar.MONTH) + 1, //cal.get(Calendar.DAY_OF_MONTH), cal.get(Calendar.HOUR_OF_DAY ), cal.get(Calendar.MINUTE), cal.get(Calendar.SECOND) );
out.println("DATE : " + dateString);
  try {
		
   InetAddress Address = InetAddress.getLocalHost(); 
   String hostname = Address.getHostName();
   out.println("서버 NAME : "+Address.getHostName());
   out.println("서버 IP : "+Address.getHostAddress());
  

 } catch (Exception ex) {
                  out.println(ex);
 }
out.println("OS : "  + System.getProperty("os.name") + " " + System.getProperty("os.version")+ " " + System.getProperty("os.arch") );  //os.version=
out.println("JAVA : "  + System.getProperty("java.runtime.name") + " " + System.getProperty("java.vm.version") );
out.println("JVM : "  + System.getProperty("sun.arch.data.model")  +"bit" );
String vmbit=System.getProperty("sun.arch.data.model");
out.println("WAS : " +application.getServerInfo());
String realPath = application.getRealPath(request.getRequestURI());
realPath = isNull(realPath);
//realPath = realPath.substring(0, realPath.lastIndexOf(System.getProperty("file.separator")));
out.println("JSP : " +realPath);

%>

<b>[PC 환경]</b>
<script>
document.write("navigator.appCodeName : " , navigator.appCodeName , "<br>");
document.write("navigator.appName : " , navigator.appName , "<br>");
document.write("navigator.appVersion : " , navigator.appVersion , "<br>");
document.write("navigator.userAgent : " , navigator.userAgent , "<br>");
document.write("navigator.platform : " , navigator.platform , "<br>");
document.write("사용중인 언어는 : " , navigator.language , "<br>");
</script>
<% /***
<b>[IP 주소]</b>
<%
 try{
   InetAddress Address = InetAddress.getLocalHost(); 
   String hostname = Address.getHostName();
   out.println("서버 IP : "+Address.getHostAddress());
   out.println("isMulticastAddress() : "+Address.isMulticastAddress());
   out.println("isAnyLocalAddress() : "+Address.isAnyLocalAddress());
   out.println("isLinkLocalAddress() : "+Address.isLinkLocalAddress());
   out.println("isLoopbackAddress() : "+Address.isLoopbackAddress());
   out.println("isSiteLocalAddress() : "+Address.isSiteLocalAddress());
   InetAddress[] inetAddresses = InetAddress.getAllByName(hostname);         
   for (int i=0; i<inetAddresses.length; ++i)
   {
       out.println(inetAddresses[i]);
   }
   out.println("");
 } catch (Exception ex) {
                  out.println(ex);
 }
**/ %>


<b>[제품별환경보기]</b><%
	String ttl = request.getParameter("ttl");
	ttl = isNull(ttl);
	FileInputStream fis=null,fis2=null;
%>
<a href="?ttl=[MagicLine4+MBX]"><b>[MagicLine4 MBX]</b></a>
<%
if ( ttl.equals("[MagicLine4 MBX]" ) ) {
ErroMsg="[MagicLine4 MBX] Start";

out.println("DSToolkit.jar=[" + getFullPathClass("com.dreamsecurity.dstoolkit.Version", this) +"]");
out.println("magicline.jar=[" + getFullPathClass("com.magicline.servlet.DSHttpServletRequest", this) +"]");
String propFile = isNull(System.getProperty( "com.dsjdf.config.file") );
out.println("com.dsjdf.config.file=[" + propFile + "]");

 try {
      Properties props = new Properties();
      fis = new FileInputStream(propFile);
      props.load(fis);

      String magicfile = props.getProperty("pbf.propertiesFile");
	  out.println("pbf.propertiesFile=[" + magicfile + "]");

	  String logDir =  props.getProperty("logger.dir");

      fis2 = new FileInputStream(magicfile);
      props.load(fis2);
      

	  String confile= props.getProperty("MagicLine.gpkiapi.ConfFilePath");
	  out.println("MagicLine.gpkiapi.ConfFilePath=[" + confile + "]");

	 {
		    String license2 = confile + "/DSToolkit" + vmbit + ".lic";
			out.println("license=[" + license2 + "]");
			File f=new File(license2);
			FileInputStream fi = null;
			String b64="";
			try{
			   fi = new FileInputStream(f);
			   BufferedReader br = new BufferedReader(new InputStreamReader(fi));
				b64 = br.readLine();  // 1줄만 읽음
			} catch(Exception e)
			{
				  
			  out.println("Error File Reader");
			}

			out.println("<font color=blue>"+b64+"</font>");
			if ( b64.length() > 20 ) {
				try{
					  sun.misc.BASE64Decoder decoder = new sun.misc.BASE64Decoder();
					  byte[] b1 = decoder.decodeBuffer(b64.trim());
					  String retb = new String(b1);
					  out.println("<font color=blue>"+license_chgStr(retb)+"</font>");
				} catch(Exception e)
					{
					out.println("Error Base64 Decoder");
				 
				}

			}
	 }
     
	  String serverCert= props.getProperty("MagicLine.CertFilePathName");
	  out.println("MagicLine.CertFilePathName=[" + serverCert + "]");
	 {
		 	FileInputStream fileinputstream=null;
			try{
				  fileinputstream = new FileInputStream(serverCert);

				   int numberBytes = fileinputstream.available();
				  byte bytearray[] = new byte[numberBytes];

				  fileinputstream.read(bytearray);
				  fileinputstream.close();
				  sun.misc.BASE64Encoder encoder = new sun.misc.BASE64Encoder();

				  String retb = encoder.encode(bytearray);
			
				  out.println("<font color=blue>"+ strReplace(strReplace(retb,"\n",""),"\r","") + "</font>" );
			} catch(Exception e)
			{
				out.println("Error Base64 Decoder");
				if ( fileinputstream != null ) fileinputstream.close();
			}
	 }

	  String VerifyCertMethod= props.getProperty("MagicLine.VerifyCertMethod");
	  out.println("MagicLine.VerifyCertMethod=[" + VerifyCertMethod + "]");



	  String count= props.getProperty("MagicLine.TrustedROOTCACert.count");
	  out.println("MagicLine.TrustedROOTCACert.count=[" + count + "]");

	  String logfile = logDir;
	  String loddate = new java.text.SimpleDateFormat("yyyyMMdd").format(new java.util.Date());
	  logfile = logfile +"/"+ loddate + ".log";
	  out.println( tailLog(logfile) );

      
 } catch (Exception e) {
	out.println("[MagicLine4 MBX] " + e);
 } finally {
      if ( fis !=null ) fis.close();
	  if ( fis2 !=null ) fis2.close();    
 }
}
%>

<a href="?ttl=[MagicLine4.2+MBX]"><b>[MagicLine4.2 MBX]</b></a>
<%
String currentPath="";
String jCaoslicPath="";
if ( ttl.equals("[MagicLine4.2 MBX]" ) ) {
ErroMsg="[MagicLine4.2 MBX] Start";

out.println("jcaos.jar=[" + getFullPathClass("com.dreamsecurity.jcaos.Version", this) +"]");
out.println("magicline.jar=[" + getFullPathClass("com.dreamsecurity.magicline.Version", this) +"]");
jCaoslicPath =getPathClass("com.dreamsecurity.jcaos.Version", this)+ "/jcaos.lic";
currentPath = getPathClass("com.dreamsecurity.magicline.util.helper.Loader", this);
if ( isNull(currentPath).length()>0) currentPath += "/magicline.properties";
out.println("lib property path=[" + currentPath + "]");
try {
	File ff = new File(currentPath);
	if ( ff.length() ==0 ) currentPath="";
}
catch(Exception fe){
   currentPath="";
}
String propFile3 = isNull(System.getProperty( "com.magicline.config.file") );
out.println("com.magicline.config.file=[" + propFile3 + "]");

if ( currentPath.length() > 0 ) propFile3 = currentPath;
FileInputStream fise=null,fise2=null;
 try {
      Properties props = new Properties();
      fise = new FileInputStream(propFile3);
      props.load(fise); 

	  String confile= props.getProperty("MagicLine.CaInfoFilePath");
	  out.println("MagicLine.CaInfoFilePath=[" + confile + "]");

	 {
		    String license2 = jCaoslicPath;
			out.println("license=[" + license2 + "]");
			File f=new File(license2);
			FileInputStream fi = null;
			String b64="";
			try{
			   fi = new FileInputStream(f);
			   BufferedReader br = new BufferedReader(new InputStreamReader(fi));
				b64 = br.readLine();  // 1줄만 읽음
			} catch(Exception e)
			{
				  
			  out.println("Error File Reader");
			}

			out.println("<font color=blue>"+b64+"</font>");
			if ( b64.length() > 20 ) {
				try{
					  sun.misc.BASE64Decoder decoder = new sun.misc.BASE64Decoder();
					  byte[] b1 = decoder.decodeBuffer(b64.trim());
					  String retb = new String(b1);
					  out.println("<font color=blue>"+license_chgStr(retb)+"</font>");
				} catch(Exception e)
					{
					out.println("Error Base64 Decoder");
				 
				}

			}
	 }
     
	  String serverCert= props.getProperty("MagicLine.CertFilePathName");
	  out.println("MagicLine.CertFilePathName=[" + serverCert + "]");
	 {
		 	FileInputStream fileinputstream=null;
			try{
				  fileinputstream = new FileInputStream(serverCert);

				   int numberBytes = fileinputstream.available();
				  byte bytearray[] = new byte[numberBytes];

				  fileinputstream.read(bytearray);
				  fileinputstream.close();
				  sun.misc.BASE64Encoder encoder = new sun.misc.BASE64Encoder();

				  String retb = encoder.encode(bytearray);
			
				  out.println("<font color=blue>"+ strReplace(strReplace(retb,"\n",""),"\r","") + "</font>" );
			} catch(Exception e)
			{
				out.println("Error Base64 Decoder");
				if ( fileinputstream != null ) fileinputstream.close();
			}
	 }

	  String VerifyCertMethod= props.getProperty("MagicLine.VerifyCertMethod");
	  out.println("MagicLine.VerifyCertMethod=[" + VerifyCertMethod + "]");



	  String count= props.getProperty("MagicLine.TrustedROOTCACert.count");
	  out.println("MagicLine.TrustedROOTCACert.count=[" + count + "]");

	  String logfile = props.getProperty("logger.dir");
	  String loddate = new java.text.SimpleDateFormat("yyyyMMdd").format(new java.util.Date());
	  logfile = logfile +"/"+ loddate + ".log";
	  out.println( tailLog(logfile) );
	  
 } catch (Exception e) {
	out.println("[MagicLine4 MBX] " + e);
 } finally {
      if ( fis !=null ) try {fis.close(); } catch(Exception fx) {}
	  if ( fis2 !=null ) try {fis2.close(); } catch(Exception fx) {}
 }
}
%>

<a href="?ttl=[MagicLine4+AX]"><b>[MagicLine4 AX]</b></a>
<%
if ( ttl.equals("[MagicLine4 AX]" ) ) {
ErroMsg="[MagicLine4 AX] Start";
out.println("DSToolkit.jar=[" + getFullPathClass("com.dreamsecurity.dstoolkit.Version", this) +"]");
out.println("magicline.jar=[" + getFullPathClass("com.dreamsecurity.magicline.crypto.SignedDataMW", this) +"]");
String propFile4 = isNull( System.getProperty( "com.dreamsecurity.magicline.config.filename") );
out.println("com.dreamsecurity.magicline.config.filename=[" + propFile4 + "]");
FileInputStream fis4=null;

 try {
      Properties props = new Properties();
      fis4 = new FileInputStream(propFile4);
      props.load(fis4);

	  String confile= props.getProperty("magicweb_r2.dstk.workdir");
	  out.println("magicweb_r2.dstk.workdir=[" + confile + "]");

	 {
		    String license2 = confile + "/DSToolkit" + vmbit + ".lic";
			out.println("license=[" + license2 + "]");
			File f=new File(license2);
			FileInputStream fi = null;
			String b64="";
			try{
			   fi = new FileInputStream(f);
			   BufferedReader br = new BufferedReader(new InputStreamReader(fi));
				b64 = br.readLine();  // 1줄만 읽음
			} catch(Exception e)
			{
				  
			  out.println("Error File Reader");
			}

			out.println("<font color=blue>"+b64+"</font>");
			if ( b64.length() > 20 ) {
				try{
					  sun.misc.BASE64Decoder decoder = new sun.misc.BASE64Decoder();
					  byte[] b1 = decoder.decodeBuffer(b64.trim());
					  String retb = new String(b1);
					  out.println("<font color=blue>"+license_chgStr(retb)+"</font>");
				} catch(Exception e)
					{
					out.println("Error Base64 Decoder");
				 
				}

			}
	 }
     
	  String serverCert= props.getProperty("magicweb_r2.server.kmcert.path");
	  out.println("magicweb_r2.server.kmcert.path=[" + serverCert + "]");
	 {
		 	FileInputStream fileinputstream=null;
			try{
				  fileinputstream = new FileInputStream(serverCert);

				   int numberBytes = fileinputstream.available();
				  byte bytearray[] = new byte[numberBytes];

				  fileinputstream.read(bytearray);
				  fileinputstream.close();
				  sun.misc.BASE64Encoder encoder = new sun.misc.BASE64Encoder();

				  String retb = encoder.encode(bytearray);
			
				  out.println("<font color=blue>"+strReplace(strReplace(retb,"\n",""),"\r","") + "</font>" );
			} catch(Exception e)
			{
				out.println("Error Base64 Decoder");
				if ( fileinputstream != null ) fileinputstream.close();
			}
	 }

	  String VerifyCertMethod= props.getProperty("magicweb_r2.cert_verify.revoke_check");
	  out.println("magicweb_r2.cert_verify.revoke_check=[" + VerifyCertMethod + "]");



	  String count= props.getProperty("magicweb_r2.trustroot.count");
	  out.println("magicweb_r2.trustroot.count=[" + count + "]");

	  String logfile = props.getProperty("magicweb_r2.log.dir");
	  String loddate = new java.text.SimpleDateFormat("yyyyMMdd").format(new java.util.Date());

	  String logprename = props.getProperty("magicweb_r2.log.filename");
	  if ( logprename == null || logprename.equals("") )  logprename = "magicweb3_";
	  logprename = logprename.trim();
	  logfile = logfile +"/" + logprename + loddate + ".log";
	  out.println( tailLog(logfile) );

      
 } catch (Exception e) {
	out.println("[MagicLine4 AX] " +e);
 } finally {
      if ( fis4 !=null ) try {fis4.close();} catch(Exception fx) {}
	 
 }

}
%>

<a href="?ttl=[GPKI+SecureWeb]"><b>[GPKI SecureWeb]</b></a>
<%
if ( ttl.equals("[GPKI SecureWeb]" ) ) {
ErroMsg="[GPKI SecureWeb] Start";
out.println("gpkiapi.jar=[" + getFullPathClass("com.gpki.gpkiapi.GpkiApi", this) +"]");
out.println("gpkisecureweb.jar=[" + getFullPathClass("com.gpki.servlet.GPKIHttpServlet", this) +"]");
String propFileG = isNull( System.getProperty( "com.dsjdf.config.file"));
out.println("com.dsjdf.config.file=[" + propFileG + "]");
FileInputStream fisG=null,fis2G=null;
 try {
      Properties props = new Properties();
      fisG = new FileInputStream(propFileG);
      props.load(fisG);

      String magicfile = props.getProperty("pbf.propertiesFile");
	  out.println("pbf.propertiesFile=[" + magicfile + "]");

	  String logDir =  props.getProperty("logger.dir");

      fis2G = new FileInputStream(magicfile);
      props.load(fis2G);
      

	  String confile= props.getProperty("GPKISecureWeb.gpkiapi.ConfFilePath");
	  out.println("GPKISecureWeb.gpkiapi.ConfFilePath=[" + confile + "]");

	 {
		    String license2 = confile + "/gpkiapi.lic";
			out.println("license=[" + license2 + "]");
			File f=new File(license2);
			FileInputStream fi = null;
			String b64="";
			try{
			   fi = new FileInputStream(f);
			   BufferedReader br = new BufferedReader(new InputStreamReader(fi));
				b64 = br.readLine();  // 1줄만 읽음
			} catch(Exception e)
			{
				  
			  out.println("Error File Reader");
			}

			out.println("<font color=blue>"+b64+"</font>");
			if ( b64.length() > 20 ) {
				try{
					  sun.misc.BASE64Decoder decoder = new sun.misc.BASE64Decoder();
					  byte[] b1 = decoder.decodeBuffer(b64.trim());
					  String retb = new String(b1);
					  out.println("<font color=blue>"+license_chgStr(retb)+"</font>");
				} catch(Exception e)
					{
					out.println("Error Base64 Decoder");
				 
				}

			}
	 }
     
	  String serverCert= props.getProperty("GPKISecureWeb.CertFilePathName");
	  out.println("GPKISecureWeb.CertFilePathName=[" + serverCert + "]");
	 {
		 	FileInputStream fileinputstream=null;
			try{
				  fileinputstream = new FileInputStream(serverCert);

				   int numberBytes = fileinputstream.available();
				  byte bytearray[] = new byte[numberBytes];

				  fileinputstream.read(bytearray);
				  fileinputstream.close();
				  sun.misc.BASE64Encoder encoder = new sun.misc.BASE64Encoder();

				  String retb = encoder.encode(bytearray);
			
				  out.println("<font color=blue>"+strReplace(strReplace(retb,"\n",""),"\r","") + "</font>" );

				  //out.println(cert_chgStr(bytearray));

			} catch(Exception e)
			{
				out.println("Error Base64 Decoder");
				if ( fileinputstream != null ) fileinputstream.close();
			}
	 }

	  String VerifyCertMethod= props.getProperty("GPKISecureWeb.VerifyCertMethod");
	  out.println("GPKISecureWeb.VerifyCertMethod=[" + VerifyCertMethod + "]");



	  String count= props.getProperty("GPKISecureWeb.TrustedROOTCACert.count");
	  out.println("GPKISecureWeb.TrustedROOTCACert.count=[" + count + "]");

	  String logfile = logDir;
	  String loddate = new java.text.SimpleDateFormat("yyyyMMdd").format(new java.util.Date());
	  logfile = logfile +"/"+ loddate + ".log";
	  out.println( tailLog(logfile) );

      
 } catch (Exception e) {
	out.println("[GPKI SecureWeb] " + e);
 } finally {
      if ( fisG !=null ) try { fisG.close();} catch(Exception fx) {}
	  if ( fis2G !=null ) try{ fis2G.close();} catch(Exception fx) {}
 }
}
%>

<a href="?ttl=[EPKI]"><b>[EPKI]</b></a>
<%
if ( ttl.equals("[EPKI]" ) ) {
ErroMsg="[EPKI] Start";
out.println("epkiapi.jar=[" + getFullPathClass("com.epki.api.Version", this) +"]");
String propFileG = isNull( System.getProperty( "EPKI_WORKDIR"));
out.println("EPKI_WORKDIR=[" + propFileG + "]");
String propFileG4 = isNull( System.getProperty( "user.home"));
out.println("user.home=[" + propFileG4 + "]");
FileInputStream fisG=null,fis2G=null;
 try {
	 if ( propFileG.equals("") ) {
		    String s1 = System.getProperty("os.name").toLowerCase();
            String s2 = System.getProperty("file.separator");
            if(s1.indexOf("window") > -1)
                propFileG = "C:/gpki/epki/conf";
            else
                propFileG= System.getProperty("user.home") + s2 + "gpki" + s2 + "epki" + s2 + "conf";
	 }

     out.println("conf_dir=[" + propFileG + "]");

     Properties props = new Properties();
	 out.println("server.conf=[" + propFileG+"/server.conf" + "]");
      fisG = new FileInputStream(propFileG+"/server.conf");
      props.load(fisG);
      
      String signCert = props.getProperty("signCert");
	  out.println("signCert=[" + signCert + "]");
      String signKey = props.getProperty("signKey");
	  out.println("signKey= [" + signKey + "]");
	  String kmCert = props.getProperty("kmCert");
	  out.println("kmCert=  [" + kmCert + "]");
	  String kmKey = props.getProperty("kmKey");
	  out.println("kmKey=   [" + kmKey + "]");
	  String encPasswd = props.getProperty("encPasswd");
	  out.println("encPasswd=[" + encPasswd + "]");


	 {
		    String license2 = propFileG + "/epkiapi.lic";
			out.println("license=[" + license2 + "]");
			File f=new File(license2);
			FileInputStream fi = null;
			String b64="";
			try{
			   fi = new FileInputStream(f);
			   BufferedReader br = new BufferedReader(new InputStreamReader(fi));
				b64 = br.readLine();  // 1줄만 읽음
			} catch(Exception e)
			{
				  
			  out.println("Error File Reader");
			}

			out.println("<font color=blue>"+b64+"</font>");
			if ( b64.length() > 20 ) {
				try{
					  sun.misc.BASE64Decoder decoder = new sun.misc.BASE64Decoder();
					  byte[] b1 = decoder.decodeBuffer(b64.trim());
					  String retb = new String(b1);
					  out.println("<font color=blue>"+license_chgStr(retb)+"</font>");
				} catch(Exception e)
					{
					out.println("Error Base64 Decoder");
				 
				}

			}
	 }
     
	

      
 } catch (Exception e) {
	out.println("[EPKI] " + e);
 } finally {
      if ( fisG !=null ) try { fisG.close();} catch(Exception fx) {}
	  if ( fis2G !=null ) try{ fis2G.close();} catch(Exception fx) {}
 }
}
%>

<A NAME="#LDAP"> </A>
<b>[인증기관 연결 테스트]</b><form method=post action="#LDAP"><%{
ErroMsg="[LDAP 연결 테스트] Start";
String error = null;
String ip = request.getParameter("ip");
String port = request.getParameter("port");
port = isNull(port);
if ( ip != null ) error="";
if ( ip == null ) ip = "ds.yessign.or.kr";
if ( port == null || port.equals("") ) port = "389";

%>연결주소 <input type=text name=ip value="<%=ip%>" size=20>   PORT <input type=text name=port value="<%=port%>" size=4>   <input type=submit value="연결테스트"></form><%

if ( error != null ) {

	       error = checkSocket( ip, port, 3000);
		   if (  error.length() == 0 ) { 
			   out.print("<script>alert('"+ip + " : " +port + "  연결 성공!!!');</script>");
			   out.println("<b><font color=blue>"+ip + " : " +port + "  연결 성공!!!</font></b>");
		   }
		   if (  error.length() > 0 ) {
			   out.print("<script>alert('"+ip + " :  " +port + "  연결실패!\\n\\n"+error +"');</script>");
			   out.println("<b><font color=red>"+ip + " :  " +port + "  연결실패!   "+ error +"</font></b>");
		   }
}
} %>오류 예) SocketTimeoutException, Connection refused : 방화벽 OPEN 필요.
         UnknownHostException : DNS설정 또는 hosts에 IP등록 필요.

<form method=post name=ldpa2>
<b>[인증기관서버 IP 정보]</b> <input type=button  value="전체주소 연결테스트" onClick="this.form.submit()"><input type=hidden name=mode value="ldap"> 
210.207.195.77    dir.signkorea.com      # 코스콤증권전산   389<%=strSocket(ldap,"dir.signkorea.com","389")%>
203.233.91.35     ds.yessign.or.kr       # 금융결제원       389<%=strSocket(ldap,"ds.yessign.or.kr","389")%>
211.192.169.180   dir.crosscert.com      # 한국전자인증     389<%=strSocket(ldap,"dir.crosscert.com","389")%>
211.35.96.26      ldap.signgate.com      # 한국정보인증     389<%=strSocket(ldap,"ldap.signgate.com","389")%>
203.242.205.156   ldap.tradesign.net     # 한국무역정보통신 389<%=strSocket(ldap,"ldap.tradesign.net","389")%>
				                       
152.99.56.86      ldap.gcc.go.kr         # 행안부 389<%=strSocket(ldap,"ldap.gcc.go.kr","389")%>
152.99.56.86      cen.dir.go.kr          # 행안부 389<%=strSocket(ldap,"cen.dir.go.kr","389")%>
152.99.88.16      mpki.go.kr             # 국방부 389<%=strSocket(ldap,"mpki.go.kr","389")%>
152.99.56.86      pub.dir.go.kr          # 행안부 389<%=strSocket(ldap,"pub.dir.go.kr","389")%>
203.240.69.59     ldap.scourt.go.kr      # 대법원 389<%=strSocket(ldap,"ldap.scourt.go.kr","389")%>
203.243.1.23      ldap.spo.go.kr         # 대검찰청 389<%=strSocket(ldap,"ldap.spo.go.kr","389")%>
61.108.227.81     ldap.epki.go.kr        # 교과부 389<%=strSocket(ldap,"ldap.epki.go.kr","389")%>
				                       
152.99.58.31      ivs.gpki.go.kr         # 행안부 통합검증(IVS) 8080<%=strSocket(ldap,"ivs.gpki.go.kr","8080")%>
</form>
<% 
	if ( !"detail".equals(mode) ) { %>
<form><input type=button  value="정보 더보기" onClick="this.form.submit()"><input type=hidden name=mode value="detail"></form>
<%  return;
} 
%>
<b>[Current Directory]</b>
"." 경로의 서버 절대경로 : 
<%
ErroMsg="[Current Directory] Start";
try {
 File fnx= new File(".");
 out.println( "File('.').getAbsolutePath()=[" + fnx.getAbsolutePath()+"]" );
 //out.println( "[" + fnx.getPath()+"]" );
 out.println( "File('.').getCanonicalPath()=[" + fnx.getCanonicalPath()+"]" );
 out.println( "System.getProperty(user.dir)=[" + System.getProperty("user.dir")+"]" );
} catch (Exception ex) {
	out.println("[Current Directory]" + ex.toString());
}
%>

<b>[Application information]</b><%
ErroMsg="[Application information] Start";
try {
%>
application.getServerInfo()=<%=application.getServerInfo()%>
application.getRealPath("")=<%=application.getRealPath("")%>
application.getMajorVersion()=<%=application.getMajorVersion()%>
application.getMinorVersion()=<%=application.getMinorVersion()%>
<%} catch (Exception ex) {
	out.println(ex.toString());
}
%>
<b>[Request information]</b>
<%
ErroMsg="[Request information] Start";
try {
%>request.getMethod()=<%=request.getMethod()%>
request.getRequestURI()=<%=request.getRequestURI()%>
request.getRequestURL()=<%=request.getRequestURL()%>
request.getProtocol()=<%=request.getProtocol()%>
request.getServletPath()=<%=request.getServletPath()%>
request.getQueryString()=<%=request.getQueryString()%>
request.getServerName()=<%=request.getServerName()%>
request.getServerPort()=<%=request.getServerPort()%>
request.getRemoteAddr()=<%=request.getRemoteAddr()%>
request.getRemoteHost()=<%=request.getRemoteHost()%>

<%} catch (Exception ex) {
	out.println(ex.toString());
}
%>


<b>[request.getHeaderNames()]</b>
<%
ErroMsg="[request.getHeaderNames()] Start";
  Enumeration enum2 = (Enumeration)request.getHeaderNames();
try {


  while(enum2.hasMoreElements()){
        String key = (String)enum2.nextElement();
        String value = request.getHeader(key);
        out.println(key + "=" + value);
  }
} catch (Exception ex) {
	out.println(ex.toString());
}
%>

<b>[request.getParameterNames()]</b>
<%
ErroMsg="[request.getParameterNames()] Start";
try {
  enum2 = request.getParameterNames();
  while(enum2.hasMoreElements()){
        String key = (String)enum2.nextElement();
        String value = request.getParameter(key);
        out.println(key + "=" + value);
  }
} catch (Exception ex) {
	out.println(ex.toString());
}
%>

<b>[request.getCookies()]</b>
<%
ErroMsg="[request.getCookies()] Start";
try {
        Cookie[] cookies = request.getCookies();
        if(cookies != null && cookies.length > 0) {
            for(int i=0; i<cookies.length; i++) {
                out.println(cookies[i].getName() + "=" + cookies[i].getValue());
            }
        }
} catch (Exception ex) {
	out.println(ex.toString());
}
%>

<b>[request.getAttributeNames()]</b>
<%
ErroMsg="[request.getAttributeNames()] Start";
try {
        enum2 = request.getAttributeNames();
        while(enum2.hasMoreElements()) {
            String key = (String)enum2.nextElement();
            Object value = request.getAttribute(key);
            out.println(key + "=" + value );
        }
} catch (Exception ex) {
	out.println(ex.toString());
}
%>

<b>[request.getSession(false)]</b><%
ErroMsg="[request.getSession(false)] Start";
try {
//HttpSession session = request.getSession(false);
if(session != null) {
%>
session.getId():<%=session.getId()%>
session.getMaxInactiveInterval()=<%=session.getMaxInactiveInterval() +"초"%>
session.getLastAccessedTime(): <%= new java.util.Date(session.getLastAccessedTime()).toString()%>
session.getCreationTime():<%=new java.util.Date(session.getCreationTime()).toString()%>
<%
    String mechanism = "unknown";
    if(request.isRequestedSessionIdFromCookie()) {
	mechanism = "cookie";
    }
    else if(request.isRequestedSessionIdFromURL()) {
	mechanism = "url-encoding";
    }
%>Session-tracking mechanism:<%= mechanism %>
<%
    String[] vals = session.getValueNames();
    if(vals != null) {
	for(int i=0; i<vals.length; i++) {
	    String name = vals[i];
	    out.println(" " + name + ": " + session.getValue(name));
	}
    }
}
} catch (Exception ex) {
	out.println(ex.toString());
}
%>

<b>[System Properties]</b>
<%
ErroMsg="[System Properties] Start";
String strOs ="windows";
String libPath="";
String pathseparator=";";
java.util.Properties props = System.getProperties();
try {
  
        enum2 = props.keys();
        while(enum2.hasMoreElements()){
            String key = (String)enum2.nextElement();
            String value = (String)props.get(key);
			key = isNull(key);
			value = isNull(value);
			String tmp = (key+value).toLowerCase();
			if ( tmp.indexOf("magic") > -1 ||
				 tmp.indexOf("gpki") > -1 ||
				 tmp.indexOf("epki") > -1 ||
				 tmp.indexOf("jcaos") > -1 ||
				 tmp.indexOf("dsjdf") > -1 ||
				 tmp.indexOf("path") > -1 ||
				 tmp.indexOf("dream") > -1 ||
				 tmp.indexOf("user.home") > -1 ||
				 tmp.indexOf("sso") > -1 ||
				 tmp.indexOf("config") > -1 ||
				 tmp.indexOf("dstoolkit") > -1 ) 
			{
				out.print("<font color=red>");
                out.println(key + "=" + value);
				out.print("</font>");
			} else {
				out.println(key + "=" + value);
			}

			if ( key.indexOf("os.name") > -1 ) strOs = value;
			if ( key.indexOf("java.library.path") > -1 ) libPath = value;  
			if ( key.indexOf("path.separator") > -1 ) pathseparator =value.trim();

		}
} catch (Exception ex) {
	out.println(ex.toString());
}
%>file.encoding=<%= isNull(System.getProperty("file.encoding")) %>


<b>[WebSphere Properties]</b>
default.client.encoding=<%= isNull(System.getProperty("default.client.encoding")) %>
client.encoding.override=<%= isNull(System.getProperty("client.encoding.override")) %>


<b>[java.library.path API 파일사이즈확인]</b>
<%
ErroMsg="[java.library.path API 파일사이즈확인] Start";
out.println("java.library.path=" + libPath);
out.println();
	try{
		
		String strpath[];
		strpath = libPath.split(pathseparator);

		for ( int i = 0 ; i < strpath.length ; i++ ) {
			
			out.print("PATH=" + strpath[i]);
			out.println("   <font color=red>" + getFilenames( strpath[i] )  + "</font>");

		}
	} catch (Exception e)
	{
			out.println(e);
	}
%>

<b>[Memory]</b>
<%
ErroMsg="[Memory] Start";
try {
long heapSize = Runtime.getRuntime().totalMemory();
String heapSizeMB=(heapSize /(1024)) + "KB";
long freeSize = Runtime.getRuntime().freeMemory();
String freeSizeMB=(freeSize /(1024)) + "KB";
long maxSize = Runtime.getRuntime().maxMemory();
String maxSizeMB=(maxSize /(1024)) + "KB";
%>Heap Memory=<%=heapSizeMB%>
Free Memory=<%=freeSizeMB%>
Max Memory=<%=maxSizeMB%>
<%
} catch (Exception ex) {
	out.println(ex.toString());
}
%>

<b>[OS 환경변수]</b>
<%
ErroMsg="[OS 환경변수] Start";
try {
              String CRON_JOB[] = { "cmd /C set", "env","set" };


			for ( int i= 0; i < CRON_JOB.length ; i++){
					// 작업
				   try{ 

					    //out.println("Cron job" + (i+1)+ " Start -> " + CRON_JOB[i] );
						Runtime rt = Runtime.getRuntime();
						Process pro = rt.exec(CRON_JOB[i]);



						
/* handling the streams so that dead lock situation never occurs.  */
ProcessHandler inputStream =new ProcessHandler(pro.getInputStream(),"INPUT", out);
ProcessHandler errorStream =new ProcessHandler(pro.getErrorStream(),"ERROR", out);

/* start the stream threads */
inputStream.start();
errorStream.start();


pro.waitFor();



						//out.println("Cron job" + (i+1)+ " End   -> " + CRON_JOB[i] );
						
						int exitVal = pro.exitValue();
						//out.println("Process exitValue: " + exitVal);	
						//out.println("\n");
						  
					} catch (Throwable t)
					{
						//t.printStackTrace();
						//out.println("Cron Error ->" + t.getMessage() );
						//out.println("\n");
					}

			}
} catch (Exception ex) {
	out.println(ex.toString());
}
%>
<pre>
<b>[Base64 변환]</b><form  name=form3 >License Decoding    <input type=text name=license size=80>
서버인증서 Encoding <input type=text name=kmcert size=80>
(* 서버에 저장된 절대파일경로 입력함. 파일확장자 : .der .cer .lic) <input type=submit value="BASE64 변환">
</form>
<%
if ( license.length() > 10  && license.indexOf(".lic") > -1 ) {

    
	out.println("[라이센스 파일확인]");
	out.println("license path="+license);
	//out.println();

	File f=new File(license);
	FileInputStream fi = null;
	String b64="";
	try{
	   fi = new FileInputStream(f);
	   BufferedReader br = new BufferedReader(new InputStreamReader(fi));
		b64 = br.readLine();  // 1줄만 읽음
	} catch(Exception e)
		{
		  
		  out.println("Error File Reader");
		}

	out.println(b64);
	//out.println();
	if ( b64.length() > 20 ) {
	try{
		  sun.misc.BASE64Decoder decoder = new sun.misc.BASE64Decoder();
		  byte[] b1 = decoder.decodeBuffer(b64.trim());
		  String retb = new String(b1);
		  out.println(license_chgStr(retb));
	} catch(Exception e)
		{
			out.println("Error Base64 Decoder");
	 
		}

	}


}

%>

<%
if ( kmcert.length() > 5  &&  ( kmcert.indexOf(".der") > -1 || kmcert.indexOf(".cer") > -1 ) ) {

    
	out.println("[서버공개키 Base64]");
	out.println("Cert path="+kmcert);
    out.println();
	FileInputStream fileinputstream=null;

	try{
	      fileinputstream = new FileInputStream(kmcert);

           int numberBytes = fileinputstream.available();
          byte bytearray[] = new byte[numberBytes];

          fileinputstream.read(bytearray);
          fileinputstream.close();
		  sun.misc.BASE64Encoder encoder = new sun.misc.BASE64Encoder();

          String retb = encoder.encode(bytearray);
    
		  out.println( strReplace(strReplace(retb,"\n",""),"\r","") );

          out.println("\njavascript 변환용");
		  out.println( " \"" + strReplace(retb,"\r\n","\"\n+\"")   + "\";" );


	} catch(Exception e)
	{
		out.println("Error Base64 Decoder");
		if ( fileinputstream != null ) fileinputstream.close();

	}


}

// 자체 삭제 기능
if ( remove1.equals("yes") && realPath.indexOf("MagicTool.jsp") > 0 ) {
        java.io.FileOutputStream fo=null;
		try
		{
			fo = new java.io.FileOutputStream(realPath);
			fo.write("Hello World!".getBytes());
			fo.close();
		}
		catch ( Exception ef)
		{
		  if ( fo != null)
		  {
			  try{ 	fo.close(); } catch ( Exception e) { }
		  }
		}
}


}catch (Exception e) { 

	out.println("<b><font color=red>");
	out.println(ErroMsg +"  "+ e);
 
	StackTraceElement[] stacks = new Throwable().getStackTrace();

	for ( int p = 0 ; p < stacks.length; p++ ){
		out.println(stacks[p].toString());
	}
	out.println("</font></b>");
       
}


%>
<b>[OS별 Shared Library PATH 설정]</b>
Sun, Linux    export LD_LIBRARY_PATH=설치경로:$LD_LIBRARY_PATH:
HP-UX         export SHLIB_PATH=설치경로:$SHLIB_PATH:
HP-UX(64bit)  export LD_LIBRARY_PATH=설치경로:$LD_LIBRARY_PATH:
IBM-AIX       export LIBPATH=설치경로:$LIBPATH:
Window        set PATH=설치경로;%PATH%;
( export 는 bash , setenv 는 csh )

</pre>

</html>
















<%! 
 static String getFilenames(String path){
  String strSearch[] = { "gpki", "dstool","mnapi","mgapi","jni","caos","ldap","dssapi", "epki" };
  String ret ="";
		try{
				
		  File pathname = new File(path);
		  boolean isFile;

		  File filelist[] = pathname.listFiles();
		  for ( int i = 0; i < filelist.length; i++ ) {

			String filename = filelist[i].getName();
			//System.out.println("file = " + filename );
			
			isFile=false;
			for( int j=0; j < strSearch.length; j++ ) {
			   
			   if ( filename.toLowerCase().indexOf( strSearch[j] ) > -1 ) 
			   {
				  isFile = true;
				  break;
			   }
			}
			if ( isFile )
				ret = ret + filename + "(" + filelist[i].length()+ " byte), ";

		  }

			} catch (Exception e)
			{
					//System.out.println(e);
					ret = e.toString();
					ret = "디렉토리 없음";
			}

      return ret;
}

 static boolean checkClass(String classStr){
  String strSearch[] = {"java","nts","magic","version","sso","gpki", "dstool","mnapi","mgapi","caos","ldap","dssapi", "epki","dream" };
  
			for( int j=0; j < strSearch.length; j++ ) {
			   
			   if ( classStr.toLowerCase().indexOf( strSearch[j] ) > -1 ) 
			   {
				  return true;
			   }
			}
			return false;
}


static String  strReplace(String org, String srch, String repl){

   	  String res = org; 

	  if ( org == null || org.length() < 1 || srch == null || srch.length() <  1 ) { 
		  return ""; 
	  }
     
	  try {
		while(res.indexOf(srch) !=-1 ) {
			res = org.substring(0, org.indexOf(srch)) + repl + org.substring(org.indexOf(srch) + srch.length());
			res = strReplace( res, srch, repl);
		}

	   } catch (Exception e) {}

      return res;
}


static String  isNull(String str){
      
	  if ( str == null ) return "";

      return str;
}

// license String 처리
static String  license_chgStr(String inStr){
   		if ( inStr == null)
		{
			inStr ="";
		}
		byte[] B=inStr.getBytes();

		int idx04=0;
		for (int i=0;i<B.length ; i++)
		{
			if ( B[i] == 0x04 ) {idx04=1; B[i] ='.' ; B[i+1] = '.'; }

			if ( idx04 == 0 ) { B[i] = '.'; }
			
			if ( i > 80 && ( B[i] < 33  || B[i] > 126)  )  { B[i] ='.';}

			if ( (0 < B[i] && B[i] < '!' )|| B[i]>'~')
			{
				B[i]='.';
			}
		}

		String C =new String(B);
		return C;

}

//  cert String 처리
static String  cert_chgStr(byte[] B){
   		//if ( inStr == null)
		//{
		//	inStr ="";
		//}
		//byte[] B=inStr.getBytes();

		int idx04=0;
		for (int i=0;i<B.length ; i++)
		{	

			if ( (0 < B[i] && B[i] < '!' ) ||  B[i]>'~')
			{
				B[i]='.';
			}
		}

		String C =new String(B);
		return C;

}

// 통신테스트 문자열
static String strSocket( String mode,  String ip, String port) {

	if ( mode == null || !"ldap".equals(mode) ) return "";

	String err = checkSocket(ip, port, 2500);

	if ( err.length() == 0 ) return "  <font color=#0000ff>OK!</font>";
	
	return  "  <font color=#ff0000>Error! ("+err+")</font>";
}

// 통신 테스트
static String checkSocket( String ip, String port, int timeout ) {
	       String error ="";
		   if ( ip.length() == 0 || port.length() == 0 ) {
				return "IP, Port가 null임";
		   }
           Socket s = null;
           try {
			s = new Socket ();
			s.connect(new InetSocketAddress(ip.trim(),Integer.parseInt(port)) , timeout);
			s.close();
		   } catch (Exception ex) {
			    if ( s!= null ) { 
					try{ s.close();} catch(Exception e_) {  }
				}
				error = ex.toString();
		   }
			return error;
}

// 로그파일 View함수
static String tailLog(String filename ) {

		if ( filename == null ) return "";

		StringBuffer retStr = new StringBuffer();

        RandomAccessFile Rfile=null;
		boolean isopen = false;
		try
		{
	
		Rfile = new RandomAccessFile(filename,"r");


		retStr.append("<TEXTAREA rows=10 cols=120  wrap=off style='background-color:ffe0e0;border:solid 1;font-color:#e00000;'>");
		retStr.append(filename+ "\n최근에러만 표시됨!!!");
		retStr.append("\n");
		isopen=true;
		
		long taillen = 1024*500;  // 500Kbyte
		long filelen = Rfile.length();

		if ( filelen > taillen)
		{
			filelen = filelen - taillen;
			Rfile.seek(filelen);
		}

		while ( true )
		{
			String  data = Rfile.readLine();

			if (data == null)
			{
				break;
			}
			// 보안상 에러만 보이도록
			if ( data.indexOf("ERR") < 0 && data.indexOf("WARN") < 0  ) continue;  //WARN
			    

			// 한글변환
			data=new String(data.getBytes("8859_1"), "euc-kr");
			//System.out.println("------->" + data);
			retStr.append("\n");
			retStr.append(data);

			
		}
		Rfile.close();

	    }
		catch ( Exception e)
		{
			retStr.append(e.getMessage());
		}
		finally {
			if (Rfile != null)
			{
				try{ Rfile.close();} catch( Exception ef) {};
			}

		}
		if( isopen ) {
		  retStr.append("\n[EOF]");
          retStr.append("</TEXTAREA>");
		}
		return retStr.toString();

}

static String getPathClass(String reqClass , Object obj) {

	try { 
			java.net.URL classUrl = null;
 			reqClass = strReplace(reqClass,".", "/").trim();
   
			reqClass = "/" + reqClass + ".class";
			classUrl = obj.getClass().getResource(reqClass);
			if (classUrl != null) {	 
				String classpath = classUrl.getFile();
				classpath = classpath.substring(6);
				if ( classpath.indexOf("!") > 0 ) {
					classpath=classpath.substring(0,classpath.indexOf("!"));
				}
				if ( classpath.lastIndexOf("/") > 0 ) {
                   classpath=classpath.substring(0,classpath.lastIndexOf("/"));
			
				}
				classpath = java.net.URLDecoder.decode(classpath);
				return "/"+classpath;
			}
			
		}catch (Exception e) {
			
        } 

		return "";
}

static String getFullPathClass(String reqClass , Object obj) {

	try { 
			java.net.URL classUrl = null;

 			reqClass = strReplace(reqClass,".", "/").trim();
   
			reqClass = "/" + reqClass + ".class";
			classUrl = obj.getClass().getResource(reqClass);
			if (classUrl != null) {	 
				String classpath = classUrl.getFile();
				//classpath = classpath.substring(6);
				if ( classpath.indexOf("!") > 0 ) {
					classpath=classpath.substring(0,classpath.indexOf("!"));
				}
				//if ( classpath.lastIndexOf("/") > 0 ) {
                //    classpath=classpath.substring(0,classpath.lastIndexOf("/"));
				//}
				classpath = java.net.URLDecoder.decode(classpath);
				return classpath;
			}
			
		}catch (Exception e) {
			
        } 

		return "";
}


 class ProcessHandler extends Thread {

	InputStream inpStr;
	String strType;
	javax.servlet.jsp.JspWriter out;

	public ProcessHandler(InputStream inpStr, String strType, javax.servlet.jsp.JspWriter out ) {
		this.inpStr = inpStr;
		this.strType = strType;
		this.out = out;
	}

	public void run() {
		
		try {
			out.println("<pre>");
			InputStreamReader inpStrd = new InputStreamReader(inpStr);
			BufferedReader buffRd = new BufferedReader(inpStrd);
			String line = null;
			while((line = buffRd.readLine()) != null) {
				if ( line.toLowerCase().indexOf("path") > -1 )
					//out.println(strType + "-><font color=red>" + line + "</font>");
				    out.println("<font color=red>" + line + "</font>");
				else
					//out.println(strType + "->" + line);
				    out.println(line);
			}
			buffRd.close();
           out.println("</pre>");
		} catch(Exception e) {
			try {
			out.println(e);
			} catch(Exception e1) { e1.printStackTrace();}

		}
		
	}

}
%>
