package com.dreamsecurity.sso.server.config;

import java.io.Console;
import java.io.File;
import java.io.FileOutputStream;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.util.Calendar;
import java.util.Date;
import java.util.Scanner;
import java.util.regex.Pattern;

import com.dreamsecurity.jcaos.jce.provider.JCAOSProvider;
import com.dreamsecurity.jcaos.pkcs.PKCS8;
import com.dreamsecurity.jcaos.pkcs.PKCS8PrivateKeyInfo;
import com.dreamsecurity.jcaos.x509.X500Principal;
import com.dreamsecurity.jcaos.x509.X509Certificate;
import com.dreamsecurity.jcaos.x509.X509CertificateGenerator;

public class GenerateCert
{
	private static final String providerName = "JCAOS" ;

	private static final String KEYPAIR_ALGORITHM = "RSA";
	private static final String HASH_ALGORITHM = "SHA256";
	private static final String RANDOM_ALGORITHM = "SHA256DRBG";

	private static final int KEY_SIZE  = 2048;

	static {
		JCAOSProvider.installProvider();
	}

	public static KeyPair genKeyPair(String algorithm, int keyLen, String curvedName) throws Exception
	{
		KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance(algorithm, providerName);
		keyPairGen.initialize(keyLen);
		KeyPair keyPair = keyPairGen.generateKeyPair();

		return keyPair;
	}

	public static X509Certificate generateRootCert(KeyPair rootPair) throws Exception
	{
		X509CertificateGenerator x509Cert = X509CertificateGenerator.getInstance(null, rootPair.getPrivate());

		x509Cert.genRootCert();

		// Certificate Serial Number
		byte[] serialNum = {(byte)0x01};

		x509Cert.setSerialNumber(serialNum);

		// Subject Name
		x509Cert.setSubjectDN(new X500Principal("CN=ROOT,OU=SSO,O=DreamSecurity,C=KR"));

		// validity Period
		Date notBefore, notAfter;

		Calendar cal = Calendar.getInstance();

		notBefore = cal.getTime();

		cal.add(Calendar.YEAR, 20);
		notAfter = cal.getTime();
		
		x509Cert.setValidity(notBefore, notAfter);

		// Subject Public Key
		x509Cert.setSubjectPublicKey(rootPair.getPublic());

		// Subject Key Identifier
		x509Cert.setSubjectKeyIdentifier(false);

		// Basic Constraints
		x509Cert.setBasicConstraints(true, -1, true);

		return x509Cert.generate(HASH_ALGORITHM);
	}

	public static X509Certificate generatePublic(KeyPair serverPair, X509Certificate caCert, String serverName, String useType, int period) throws Exception
	{
		X509CertificateGenerator x509Cert = X509CertificateGenerator.getInstance(caCert, serverPair.getPrivate());

		// Certificate Serial Number
		byte[] serialNumber = new byte[10];
		SecureRandom random = SecureRandom.getInstance(RANDOM_ALGORITHM, providerName);
		random.nextBytes(serialNumber);

		x509Cert.setSerialNumber(serialNumber);

		// Subject Name
		x509Cert.setSubjectDN(new X500Principal("CN=" + serverName + ",OU=SSO,O=DreamSecurity,C=KR"));

		// validity Period
		Date notBefore, notAfter;

		Calendar cal = Calendar.getInstance();

		notBefore = cal.getTime();

		cal.add(Calendar.YEAR, period);
		notAfter = cal.getTime();
		
		x509Cert.setValidity(notBefore, notAfter);

		// Subject Public Key
		x509Cert.setSubjectPublicKey(serverPair.getPublic());

		// Authority Key Identifier
		x509Cert.setAuthorityKeyIdentifier(X509CertificateGenerator.AKI_KEY_ID | X509CertificateGenerator.AKI_AUTH_CERT_ISSUER_AND_SERIAL_NUM, false);

		// Subject Key Identifier
		x509Cert.setSubjectKeyIdentifier(false);

		// Key Usage
		if (useType.equalsIgnoreCase("S")) {
			x509Cert.setKeyUsage(X509CertificateGenerator.KEY_USAGE_DIGITAL_SIGNATURE | X509CertificateGenerator.KEY_USAGE_NONT_REPUDIATION, true);
		}
		else {
			x509Cert.setKeyUsage(X509CertificateGenerator.KEY_USAGE_KEY_ENCIPHERMENT | X509CertificateGenerator.KEY_USAGE_DATA_ENCIPHERMENT, true);
		}

		return x509Cert.generate(HASH_ALGORITHM);
	}

	public static byte[] generatePrivate(PrivateKey priKey, String password) throws Exception
	{
		PKCS8 pkcs8 = new PKCS8(password.getBytes());
		pkcs8.setPBES2Algorithm("SEED/CBC", 128, "HmacSHA256");
		PKCS8PrivateKeyInfo priKeyInfo = PKCS8PrivateKeyInfo.getInstance(priKey.getEncoded());
		return pkcs8.encrypt(priKeyInfo);
	}

	public static void setCertInfo(String dbDriver, String dburl, String dbusr, String dbpwd, String dn, String file) throws Exception
	{
		Class.forName(dbDriver);
		Connection conn = DriverManager.getConnection(dburl, dbusr, dbpwd);

		StringBuffer query1 = new StringBuffer();

		query1.append("UPDATE SSO_CERT SET REVOC_DATE = SYSDATE, STATUS = 'N' ")
		.append("WHERE DN = ? AND STATUS = 'Y' ");

		PreparedStatement pstmt = conn.prepareStatement(query1.toString());
        pstmt.setString(1, dn);
		pstmt.executeUpdate();
        pstmt.close();

		StringBuffer query2 = new StringBuffer();

		query2.append("INSERT INTO SSO_CERT(DN, ISSUE_DATE, REVOC_DATE, STATUS, CERT_FILE) ")
			.append("VALUES(?, SYSDATE, '', 'Y', ?) ");

		pstmt = conn.prepareStatement(query2.toString());
        pstmt.setString(1, dn);
        pstmt.setString(2, file);
		pstmt.executeUpdate();
        pstmt.close();

		if (!conn.getAutoCommit())
			conn.commit();

		conn.close();
	}

	// Cubrid
	public static void setCertInfo_cubrid(String dbDriver, String dburl, String dbusr, String dbpwd, String dn, String file) throws Exception
	{
		Class.forName(dbDriver);
		Connection conn = DriverManager.getConnection(dburl, dbusr, dbpwd);

		StringBuffer query1 = new StringBuffer();

		query1.append("UPDATE SSO_CERT SET REVOC_DATE = SYSDATETIME, STATUS = 'N' ")
			.append("WHERE DN = ? AND STATUS = 'Y' ");

		PreparedStatement pstmt = conn.prepareStatement(query1.toString());
        pstmt.setString(1, dn);
		pstmt.executeUpdate();
        pstmt.close();

		StringBuffer query2 = new StringBuffer();

		query2.append("INSERT INTO SSO_CERT(DN, ISSUE_DATE, REVOC_DATE, STATUS, CERT_FILE) ")
			.append("VALUES(?, SYSDATETIME, NULL, 'Y', ?) ");

		pstmt = conn.prepareStatement(query2.toString());
        pstmt.setString(1, dn);
        pstmt.setString(2, file);
		pstmt.executeUpdate();
        pstmt.close();

		if (!conn.getAutoCommit())
			conn.commit();

		conn.close();
	}

	// PostgreSQL
	public static void setCertInfo_postgresql(String dbDriver, String dburl, String dbusr, String dbpwd, String dn, String file) throws Exception
	{
		Class.forName(dbDriver);
		Connection conn = DriverManager.getConnection(dburl, dbusr, dbpwd);

		StringBuffer query1 = new StringBuffer();

		query1.append("UPDATE SSO_CERT SET REVOC_DATE = SYSDATETIME, STATUS = 'N' ")
			.append("WHERE DN = ? AND STATUS = 'Y' ");

		PreparedStatement pstmt = conn.prepareStatement(query1.toString());
        pstmt.setString(1, dn);
		pstmt.executeUpdate();
        pstmt.close();

		StringBuffer query2 = new StringBuffer();

		query2.append("INSERT INTO SSO_CERT(DN, ISSUE_DATE, REVOC_DATE, STATUS, CERT_FILE) ")
			.append("VALUES(?, now(), NULL, 'Y', ?) ");

		pstmt = conn.prepareStatement(query2.toString());
        pstmt.setString(1, dn);
        pstmt.setString(2, file);
		pstmt.executeUpdate();
        pstmt.close();

		if (!conn.getAutoCommit())
			conn.commit();

		conn.close();
	}

	// MySQL
	public static void setCertInfo_mysql(String dbDriver, String dburl, String dbusr, String dbpwd, String dn, String file) throws Exception
	{
		Class.forName(dbDriver);
		Connection conn = DriverManager.getConnection(dburl, dbusr, dbpwd);

		StringBuffer query1 = new StringBuffer();

		query1.append("UPDATE SSO_CERT SET REVOC_DATE = now(), STATUS = 'N' ")
			.append("WHERE DN = ? AND STATUS = 'Y' ");

		PreparedStatement pstmt = conn.prepareStatement(query1.toString());
        pstmt.setString(1, dn);
		pstmt.executeUpdate();
        pstmt.close();

		StringBuffer query2 = new StringBuffer();

		query2.append("INSERT INTO SSO_CERT(DN, ISSUE_DATE, STATUS, CERT_FILE) ")
			.append("VALUES(?, now(), 'Y', ?) ");

		pstmt = conn.prepareStatement(query2.toString());
        pstmt.setString(1, dn);
        pstmt.setString(2, file);
		pstmt.executeUpdate();
        pstmt.close();

		if (!conn.getAutoCommit())
			conn.commit();

		conn.close();
	}

	private static String readPwdPattern(String format) throws Exception
	{
		String sInput = "";

		while (true) {
			Console console = System.console();
			console.printf(format);
			console.printf("> ");
			char[] pwdChars = console.readPassword();
			sInput = new String(pwdChars);

			if (sInput.equals("")) {
				String sCancel = "";

				Scanner scanner2 = new Scanner(System.in);
				System.out.printf("\nCancel Input (Y/N) ? ");
				sCancel = scanner2.nextLine();

				if (sCancel.equalsIgnoreCase("Y")) {
					throw new Exception("Cancel Input");
				}
			}
			else {
				if (Pattern.matches("^(?=.*[a-zA-Z])(?=.*[!@#$%^*+=-])(?=.*[0-9]).{9,16}$", sInput)) {
					break;
				}
				else {
					System.out.printf("\nInvalied Password Pattern.\n");
				}
			}
		}

		return sInput;
	}

	private static String readPassword(String format) throws Exception
	{
		String sInput = "";

		while (true) {
			Console console = System.console();
			console.printf(format);
			console.printf("> ");
			char[] pwdChars = console.readPassword();
			sInput = new String(pwdChars);

			if (sInput.equals("")) {
				String sCancel = "";

				Scanner scanner2 = new Scanner(System.in);
				System.out.printf("\nCancel Input (Y/N) ? ");
				sCancel = scanner2.nextLine();

				if (sCancel.equalsIgnoreCase("Y")) {
					throw new Exception("Cancel Input");
				}
			}
			else {
				break;
			}
		}

		return sInput;
	}

	private static String readLine(String format, boolean required) throws Exception
	{
		String sInput = "";

		while (true) {
			Scanner scanner = new Scanner(System.in);
			System.out.printf(format);
			System.out.printf("> ");
			sInput = scanner.nextLine().trim();

			if (sInput.equals("cancel")) {
				String sCancel = "";

				Scanner scanner2 = new Scanner(System.in);
				System.out.printf("\nCancel Input (Y/N) ? ");
				sCancel = scanner2.nextLine().trim();

				if (sCancel.equalsIgnoreCase("Y"))
					throw new Exception("Cancel Input");
			}
			else if (sInput.equals("") && required) {
				continue;
			}
			else {
				break;
			}
		}

		return sInput;
	}

	private static int readInteger(String format, int base, int min, int max) throws Exception
	{
		String sInput = "";
		int result = base;

		while (true) {
			Scanner scanner = new Scanner(System.in);
			System.out.printf(format);
			System.out.printf("> ");
			sInput = scanner.nextLine().trim();

			if (sInput.equals("cancel")) {
				String sCancel = "";

				Scanner scanner2 = new Scanner(System.in);
				System.out.printf("\nCancel Input (Y/N) ? ");
				sCancel = scanner2.nextLine().trim();

				if (sCancel.equalsIgnoreCase("Y")) {
					throw new Exception("Cancel Input");
				}
			}
			else if (sInput.equals("")) {
				break;
			}
			else {
				try {
					int nInput = Integer.parseInt(sInput);
					if (nInput >= min && nInput <= max) {
						result = nInput;
						break;
					}
					else {
						System.out.printf("\nInvalid Input\n");
					}
				}
				catch (Exception e) {
					System.out.printf("\nInvalid Input\n");
				}
			}
		}

		return result;
	}

	private static void outPrint(String format)
	{
		System.out.printf(format);
	}

	public static void main(String[] args)
	{
		try {
			outPrint("\n");
			outPrint("==============================================\n");
			outPrint("  Product   : " + SSOConfig.getTOE() + "\n");
			outPrint("  Version   : " + SSOConfig.getDetailVersion() + "\n");
			outPrint("  Component : " + SSOConfig.getElementVersion() + "\n");
			outPrint("  Developer : Dreamsecurity Co.,Ltd.\n");
			outPrint("==============================================\n");

			outPrint("\n>>> Start Generating Certificate  (Cancel: \"cancel\" Input)\n");

			String homepath = readLine("\nEnter Magic SSO Config Home Full Path : ex) /home/dreamsso\n", true);

			String dbDriver = "";
			String dburl = "";
			String dbusr = "";
			String dbpwd = "";

			String ldapUseYN = readLine("\nUse LDAP : (Y)es / (N)o ?  default) No\n", false);
			if (ldapUseYN.equals("")) {
				ldapUseYN = "N";
			}

			if (ldapUseYN.equalsIgnoreCase("N")) {
				dbDriver = readLine("\nEnter DB Driver Class Name : default) oracle.jdbc.driver.OracleDriver\n", false);
				if (dbDriver.equals("")) {
					dbDriver = "oracle.jdbc.driver.OracleDriver";
				}

				dburl = readLine("\nEnter Database Connection URL : ex) jdbc:oracle:thin:@192.168.10.2:1521:ORASID\n", true);
				dbusr = readLine("\nEnter Database Connection User Name : \n", true);
				dbpwd = readPassword("\nEnter Database Connection User Password : \n");
			}

			while (true) {
				String serverName = readLine("\nEnter the Server Name to use the certificate : ex) TEST_IDP\n", true);
				String useType = readLine("\nEnter Certificate Use for (E)ncryption / (S)ignature ? ", true);
				int period = readInteger("\nEnter Certificate Validity Period (year) : default) 1 (maximum 5 year)\n", 1, 1, 5);

				String password = readPwdPattern("\nEnter Private key certificate Password (9-16 characters include [a-zA-Z],[0-9],[!@#$%%^*+=-]) :\n");

				outPrint("\n>>> Generating Certificate.  Please Wait.....\n");

				if (useType.equalsIgnoreCase("S")) {
					serverName = serverName + "_Sig";
				}
				else {
					serverName = serverName + "_Enc";
				}

				KeyPair rootPair = genKeyPair(KEYPAIR_ALGORITHM, KEY_SIZE, "");

				X509Certificate caCert = generateRootCert(rootPair);

				KeyPair serverPair = genKeyPair(KEYPAIR_ALGORITHM, KEY_SIZE, "");

				X509Certificate serverCert = generatePublic(serverPair, caCert, serverName, useType, period);

				byte[] encPrivateKey = generatePrivate(serverPair.getPrivate(), password);

				String file = homepath + "/cert/CA/" + serverName;

				if (ldapUseYN.equalsIgnoreCase("N")) {
					if (dbDriver.indexOf("cubrid") >= 0) {
						setCertInfo_cubrid(dbDriver, dburl, dbusr, dbpwd, serverCert.getSubjectDN().getName(), file + ".der");
					}
					else if (dbDriver.indexOf("postgresql") >= 0) {
						setCertInfo_postgresql(dbDriver, dburl, dbusr, dbpwd, serverCert.getSubjectDN().getName(), file + ".der");
					}
					else if (dbDriver.indexOf("mysql") >= 0) {
						setCertInfo_mysql(dbDriver, dburl, dbusr, dbpwd, serverCert.getSubjectDN().getName(), file + ".der");
					}
					else {
						setCertInfo(dbDriver, dburl, dbusr, dbpwd, serverCert.getSubjectDN().getName(), file + ".der");
					}
				}

				FileOutputStream output_der = new FileOutputStream(new File(file + ".der"));
				output_der.write(serverCert.getEncoded());
				output_der.close();

				FileOutputStream output_key = new FileOutputStream(new File(file + ".key"));
				output_key.write(encPrivateKey);
				output_key.close();

				outPrint("\n>>> Certificate Generation Completed !!!\n");

				String another = readLine("\nGenerate Another Certificate : (C)ontinue / (E)nd ? ", true);

				if (another.equalsIgnoreCase("C")) {
					continue;
				}
				else {
					break;
				}
			}
		}
		catch (Exception e) {
			outPrint("\nGenerate Certificate Exception : " + e.getMessage() + "\n");
		}
	}
}