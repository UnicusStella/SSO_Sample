package com.dreamsecurity.sso.server.provider;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FilenameFilter;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.HashMap;
import java.util.List;

import com.dreamsecurity.jcaos.asn1.ASN1InputStream;
import com.dreamsecurity.jcaos.asn1.ASN1Object;
import com.dreamsecurity.jcaos.asn1.ASN1OctetString;
import com.dreamsecurity.jcaos.asn1.ASN1Sequence;
import com.dreamsecurity.jcaos.asn1.DEROctetString;
import com.dreamsecurity.jcaos.util.FileUtil;
import com.dreamsecurity.jcaos.util.encoders.Hex;
import com.dreamsecurity.sso.lib.dss.s2.metadata.Endpoint;
import com.dreamsecurity.sso.lib.jsn.JSONObject;
import com.dreamsecurity.sso.lib.slf.Logger;
import com.dreamsecurity.sso.lib.slf.LoggerFactory;
import com.dreamsecurity.sso.server.api.admin.AdminController;
import com.dreamsecurity.sso.server.client.ClientModel;
import com.dreamsecurity.sso.server.client.ClientRepository;
import com.dreamsecurity.sso.server.common.MStatus;
import com.dreamsecurity.sso.server.config.SSOConfig;
import com.dreamsecurity.sso.server.crypto.CryptoApiException;
import com.dreamsecurity.sso.server.exception.SSOException;
import com.dreamsecurity.sso.server.metadata.MetadataRepository;
import com.dreamsecurity.sso.server.session.SessionManager;
import com.dreamsecurity.sso.server.util.Util;

public class EnvironInform
{
	private static Logger log = LoggerFactory.getLogger(EnvironInform.class);

	private static EnvironInform instance = null;
	private int licenseStatus = 1;  // IDP License = 1: Check, 0: Success, -1: Failure

	private EnvironInform()
	{
		licenseInit();
	}

	public static EnvironInform getInstance()
	{
		if (instance == null) {
			synchronized (EnvironInform.class) {
				if (instance == null) {
					instance = new EnvironInform();
				}
			}
		}

		return instance;
	}

	public int getLicenseStatus()
	{
		return licenseStatus;
	}

	protected void setLicenseStatus(int licenseStatus)
	{
		this.licenseStatus = licenseStatus;
	}

	public void licenseInit()
	{
		// fileArr    : "saml_TEST_IDP.lic"
		// fileMap    : "saml_TEST_IDP.lic" = "TEST_IDP"
		// clientList : "TEST_IDP"
		ArrayList<String> fileArr = new ArrayList<String>();
		HashMap<String, String> fileMap = new HashMap<String, String>();
//		List<String> clientList = null;

		SSOConfig config = SSOConfig.getInstance();
		String licPath = config.getHomePath("license");

//		if (config.getBoolean("oidc.enable", false)) {
//			AdminController adminApi = new AdminController();
//			clientList = adminApi.getClientIdList();
//			clientList.add(config.getServerName());
//		}

		File dirFile = new File(licPath);
		File[] fileList = dirFile.listFiles( new FilenameFilter() {
			public boolean accept(File dir, String name) {
				return name.toLowerCase().endsWith(".lic");
			}
		});

		for (File tempFile : fileList) {
			if (tempFile.isFile()) {
				String temp = tempFile.getName();
				String temp1 = null;

				int i = temp.indexOf("saml_");
				int j = temp.lastIndexOf(".lic");

				if (i >= 0 && j >= 0) {
					if (temp.length() == (temp.substring(0, j).length() + 4)) {
						temp1 = temp.substring(5, j);

//						if (clientList == null || (clientList != null && clientList.contains(temp1))) {
							fileArr.add(temp);
							fileMap.put(temp, temp1);
//						}
					}
				}
			}
		}

		if (fileMap.size() == 0) {
			log.error("### MagicSSO SAML License File Not Found");
			return;
		}

		HashMap<String, String> licMap = (HashMap<String, String>) SessionManager.getInstance().getLicenseMap();
		licMap.clear();

		for (int i = 0; i < fileArr.size(); i++) {
			verifying(licPath + "/" + fileArr.get(i), (String) fileMap.get(fileArr.get(i)));
		}

		setLicenseStatus(1);
	}

	public void verifying(String pathFile, String provider)
	{
		byte[] lic = null;

		try {
			lic = FileUtil.read(pathFile);

			boolean bVerify = verifyLicense(lic);

			if (bVerify) {
			}
			else {
				HashMap<String, String> licMap = (HashMap<String, String>) SessionManager.getInstance().getLicenseMap();
				licMap.put(provider, "A");  // 서명 검증 오류
				return;
			}
		}
		catch (Exception e) {
			e.printStackTrace();
			HashMap<String, String> licMap = (HashMap<String, String>) SessionManager.getInstance().getLicenseMap();
			licMap.put(provider, "A");
			return;
		}

		ASN1InputStream asn1 = new ASN1InputStream(lic);
		ASN1Sequence seq = null;

		try {
			seq = (ASN1Sequence) asn1.readObject();
			asn1.close();
		}
		catch (IOException _io) {
			try {
				throw new CryptoApiException("The License File is Wrong.", _io);
			}
			catch (CryptoApiException e) {
				e.printStackTrace();
				HashMap<String, String> licMap = (HashMap<String, String>) SessionManager.getInstance().getLicenseMap();
				licMap.put(provider, "B");  // 정보 추출 오류
				return;
			}
		}

        /**  정식라이센스  ===================================
         * 0 Version
         * 1 Software
         * 2 CompName
         * 3 Serial Number
         * 4 
         * 5 ServreIP
         * 6 Validate
         * 7 Domain
         * 8 Signature
         * */
        
        /**  임시라이센스  ===================================
         * 0 Version
         * 1 Software
         * 2 CompName
         * 3 Serial Number
         * 4 
         * 5 
         * 6 Validate
         * 7 Signature
         * */
        
        /** 정식과 임시의 차이점
        *	Validate(유효기간) 존재 유무, 정식은 컬럼은 존재하나 값이 없음
        *	Domain 의 유무, 정식은 Domain 컬럼이있으나 임시는 컬럼 자체가 없음
        *	유효기간 존재 유무로 정식, 임시 구분
        *	임시라이센스일 경우 도메인 체크 패스
        *   정식인 경우, Domain 이 있으면 클라우드 서버
        *              ServreIP 가 있으면 고정 서버(다중화 체크)
        */

		HashMap<String, String> licMap = (HashMap<String, String>) SessionManager.getInstance().getLicenseMap();

		// 0번째 데이터 : 버전 (1)
		ASN1OctetString asnStr_0 = ASN1OctetString.getInstance(seq.getObjectAt(0));
		String str_0 = new String(asnStr_0.getOctets());
		if (!str_0.equalsIgnoreCase("1")) {
			licMap.put(provider, "C");  // 버전 오류
			return;
		}

		// 1번째 데이터 : 제품명 (MagicSSO SAML)
		ASN1OctetString asnStr_1 = ASN1OctetString.getInstance(seq.getObjectAt(1));
		String str_1 = new String(asnStr_1.getOctets());
		if (!str_1.equalsIgnoreCase("MagicSSO SAML")) {
			licMap.put(provider, "D");  // 제품명 오류
			return;
		}

		// 6번째 데이터 : 임시 라이센스 만료일
		ASN1OctetString asnStr_6 = ASN1OctetString.getInstance(seq.getObjectAt(6));
		String str_6 = new String(asnStr_6.getOctets());
		if (str_6 != null && str_6.length() >= 6) {
			String period = str_6;
			Calendar cal = Calendar.getInstance();
			int CY = cal.get(Calendar.YEAR);
			int CM = (cal.get(Calendar.MONTH) + 1);
			int CD = cal.get(Calendar.DAY_OF_MONTH);

			int SY = Integer.parseInt(0 + period.substring(0, 4));
			int SM = Integer.parseInt(0 + period.substring(5, 7));
			int SD = Integer.parseInt(0 + period.substring(8, 10));

			long diff = checkingDate(CY, CM, CD, SY, SM, SD);
			if (diff > 0) {
				log.debug("### {} 임시 라이센스 만료", provider);
				licMap.put(provider, "E");  // 만료된 라이센스
				return;
			}

			log.debug("### {} 임시 라이센스 만료 {}일 전", provider, (-1 * diff));
			licMap.put(provider, "N");  // 정상
			return;
		}

		// 5번째 데이터 : 정식 라이센스 서버 IP (IP_1;IP_2;IP_3...)
		ASN1OctetString asnStr_5 = ASN1OctetString.getInstance(seq.getObjectAt(5));
		String str_5 = new String(asnStr_5.getOctets());
		if (str_5 != null && !str_5.equals("")) {
			String[] div = str_5.split(";");
			if (div.length > 0)
				licMap.put(provider, str_5);
			else
				licMap.put(provider, "H");  // IP 정보 오류

			return;
		}

		// 7번째 데이터 : 정식 라이센스 도메인
		ASN1OctetString asnStr_7 = ASN1OctetString.getInstance(seq.getObjectAt(7));
		String str_7 = new String(asnStr_7.getOctets());
		if (str_7 != null && !str_7.equals("")) {
			try {
				String pureDomain = getProviderDomain(provider);

				//int k = str_7.indexOf(pureDomain);
				if (!Util.equals(str_7, ";", pureDomain, ";")) {
					log.debug("### {} 도메인 불일치 : {} / {}", provider, pureDomain, str_7);
					licMap.put(provider, "F");  // 도메인 불일치
					return;
				}

				licMap.put(provider, "N");
			}
			catch (Exception _e) {
				_e.printStackTrace();
				licMap.put(provider, "G");  // 서버 정보 없음
				return;
			}
		}
	}

	public static int checkingDate(int nYear1, int nMonth1, int nDate1, int nYear2, int nMonth2, int nDate2)
	{
		Calendar cal = Calendar.getInstance();
		int nTotalDate1 = 0, nTotalDate2 = 0, nDiffOfYear = 0, nDiffOfDay = 0;

		if (nYear1 > nYear2) {
			for (int i = nYear2; i < nYear1; i++) {
				cal.set(i, 12, 0);
				nDiffOfYear += cal.get(Calendar.DAY_OF_YEAR);
			}

			nTotalDate1 += nDiffOfYear;
		}
		else if (nYear1 < nYear2) {
			for (int i = nYear1; i < nYear2; i++) {
				cal.set(i, 12, 0);
				nDiffOfYear += cal.get(Calendar.DAY_OF_YEAR);
			}

			nTotalDate2 += nDiffOfYear;
		}

		cal.set(nYear1, nMonth1 - 1, nDate1);
		nDiffOfDay = cal.get(Calendar.DAY_OF_YEAR);
		nTotalDate1 += nDiffOfDay;

		cal.set(nYear2, nMonth2 - 1, nDate2);
		nDiffOfDay = cal.get(Calendar.DAY_OF_YEAR);
		nTotalDate2 += nDiffOfDay;

		return nTotalDate1 - nTotalDate2;
	}

	public static boolean verifyLicense(byte[] lic) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException,
			SignatureException
	{
		ASN1Sequence seq = ASN1Sequence.getInstance(ASN1Object.fromByteArray(lic));
		int count = seq.size();
		ByteArrayOutputStream bos = new ByteArrayOutputStream();

		for (int i = 0; i < count - 1; i++) {
			ASN1OctetString octet = DEROctetString.getInstance(seq.getObjectAt(i));
			bos.write(octet.getOctets());
		}

		byte[] tbsData = bos.toByteArray();
		byte[] signature = Hex.decode(DEROctetString.getInstance(seq.getObjectAt(count - 1)).getOctets());
		byte[] _pubkey = { (byte) 0x30, (byte) 0x5C, (byte) 0x30, (byte) 0x0D, (byte) 0x06, (byte) 0x09, (byte) 0x2A, (byte) 0x86, (byte) 0x48,
				(byte) 0x86, (byte) 0xF7, (byte) 0x0D, (byte) 0x01, (byte) 0x01, (byte) 0x01, (byte) 0x05, (byte) 0x00, (byte) 0x03, (byte) 0x4B,
				(byte) 0x00, (byte) 0x30, (byte) 0x48, (byte) 0x02, (byte) 0x41, (byte) 0x00, (byte) 0xA7, (byte) 0x77, (byte) 0xA0, (byte) 0xA2,
				(byte) 0x6C, (byte) 0xBD, (byte) 0xCA, (byte) 0xCB, (byte) 0xC1, (byte) 0x20, (byte) 0x3C, (byte) 0xA8, (byte) 0xF7, (byte) 0x9A,
				(byte) 0x5A, (byte) 0x60, (byte) 0x9F, (byte) 0xBC, (byte) 0x3F, (byte) 0x18, (byte) 0x9D, (byte) 0x98, (byte) 0x8A, (byte) 0x4E,
				(byte) 0xD7, (byte) 0x25, (byte) 0xE3, (byte) 0x07, (byte) 0x7A, (byte) 0x24, (byte) 0xC7, (byte) 0xD5, (byte) 0xB8, (byte) 0xF7,
				(byte) 0x1C, (byte) 0xDA, (byte) 0x02, (byte) 0x6A, (byte) 0xB8, (byte) 0xD3, (byte) 0xFD, (byte) 0x97, (byte) 0x8D, (byte) 0x00,
				(byte) 0x3A, (byte) 0xCA, (byte) 0xC0, (byte) 0xEA, (byte) 0x1E, (byte) 0x57, (byte) 0x76, (byte) 0xAF, (byte) 0x6C, (byte) 0x99,
				(byte) 0x0A, (byte) 0xD2, (byte) 0x30, (byte) 0x52, (byte) 0x21, (byte) 0x8A, (byte) 0x39, (byte) 0x6F, (byte) 0xCC, (byte) 0xE5,
				(byte) 0x02, (byte) 0x03, (byte) 0x01, (byte) 0x00, (byte) 0x01 };

		KeyFactory kf = KeyFactory.getInstance("RSA");
		X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(_pubkey);
		PublicKey pubkey = kf.generatePublic(pubKeySpec);

		Signature sign = Signature.getInstance("SHA1withRSA");
		sign.initVerify(pubkey);
		sign.update(tbsData);
		return sign.verify(signature);
	}

	private String getProviderDomain(String provider)
	{
		StringBuffer domain = new StringBuffer();

		List<String> uriList = getLocationURL(provider);

		if (uriList.size() > 0) {
			for (int i = 0; i < uriList.size(); i++) {
				String uri = Util.parseDomain(uriList.get(i));

				if (!Util.isEmpty(uri)) {
					if (domain.length() == 0)
						domain.append(uri);
					else
						domain.append(";" + uri);
				}
			}
		}

		return domain.toString();
	}

	private List<String> getLocationURL(String provider)
	{
		List<String> returnList = new ArrayList<String>();

		MetadataRepository metadata = MetadataRepository.getInstance();

		try {
			List<?> uriList;

			if (SSOConfig.getInstance().getServerName().equals(provider)) {
				uriList = (List<?>) metadata.getIDPDescriptor().getSingleSignOnServices();

				if (uriList.size() > 0)
					for (int i = 0; i < uriList.size(); i++)
						returnList.add(((Endpoint) uriList.get(i)).getLocation());
			}
			else {
				uriList = (List<?>) metadata.getSPDescriptor(provider).getAssertionConsumerServices();
				
				if (uriList.size() > 0) {
					for (int i = 0; i < uriList.size(); i++) {
						returnList.add(((Endpoint) uriList.get(i)).getLocation());
					}
				} else {
					ClientRepository clientRepository = ClientRepository.getInstance();
					ClientModel clientModel = clientRepository.getClient(provider);
					List<Object> list = clientModel.getRedirecturis();
					for (int i = 0; i < list.size(); i++) {
						returnList.add(URLDecoder.decode((String) list.get(i), "UTF-8"));
					}
				}
			}
		}
		catch (SSOException e) {
			e.printStackTrace();
		}
		catch (UnsupportedEncodingException e) {
			e.printStackTrace();
		}
		

		return returnList;
	}

	protected JSONObject checkLicense(String spName)
	{
		JSONObject result = new JSONObject();

		HashMap<String, String> licMap = (HashMap<String, String>) SessionManager.getInstance().getLicenseMap();
		String serverName = SSOConfig.getInstance().getServerName();

		// IDP Server License Check
		if (getLicenseStatus() == 1) {
			if (Util.isEmpty(serverName)) {
				log.error("### IDP Server Name Error");
				result.put("code", String.valueOf(MStatus.LICENSE_VERIFY));
				result.put("message", "IDP Server Name Error");
				result.put("data", "");
				return result;
			}

			String checkVal = licMap.get(serverName);

			if (checkVal == null || (checkVal.length() == 1 && !"N".equalsIgnoreCase(checkVal))) {
				setLicenseStatus(-1);
			}
			else if (checkVal.length() == 1 && "N".equalsIgnoreCase(checkVal)) {
				setLicenseStatus(0);
			}
			else if (checkVal.length() > 1) {
				String serverIP = Util.getServerIP();
				String[] div = serverIP.split(";");

				log.debug("### IDP Server  IP : {}", serverIP);
				log.debug("### IDP License IP : {}", checkVal);

				if (div.length > 0) {
					boolean check = false;

					for (int i = 0; i < div.length; i++) {
						if (checkVal.indexOf(div[i]) >= 0) {
							check = true;
							break;
						}
					}

					if (check) {
						setLicenseStatus(0);
					}
					else {
						setLicenseStatus(-1);
					}
				}
				else {
					setLicenseStatus(-1);
				}
			}
			else {
				setLicenseStatus(-1);
			}
		}

		if (getLicenseStatus() == -1) {
			log.error("### IDP Server [{}] License Error", serverName);
			result.put("code", String.valueOf(MStatus.LICENSE_VERIFY));
			result.put("message", "IDP Server [" + serverName + "] License Error");
			result.put("data", "");
			return result;
		}

		// SP Server License Check
		if (Util.isEmpty(spName)) {
			log.error("### SP Server Name Error");
			result.put("code", String.valueOf(MStatus.LICENSE_VERIFY));
			result.put("message", "SP Server Name Error");
			result.put("data", "");
			return result;
		}

		String checkVal = licMap.get(spName);

		if (checkVal == null || (checkVal.length() == 1 && !"N".equalsIgnoreCase(checkVal))) {
			log.error("### SP Server [{}] License Error", spName);
			result.put("code", String.valueOf(MStatus.LICENSE_VERIFY));
			result.put("message", "SP Server [" + spName + "] License Error");
			result.put("data", "");
		}
		else if (checkVal.length() == 1 && "N".equalsIgnoreCase(checkVal)) {
			result.put("code", String.valueOf(MStatus.SUCCESS));
			result.put("message", "SUCCESS");
			result.put("data", "");
		}
		else if (checkVal.length() > 1) {
			// SP IP check - AuthnRequest 복호화 후 처리
			result.put("code", String.valueOf(MStatus.SUCCESS));
			result.put("message", "SUCCESS");
			result.put("data", "");
		}
		else {
			log.error("### SP Server [{}] License Error", spName);
			result.put("code", String.valueOf(MStatus.LICENSE_VERIFY));
			result.put("message", "SP Server [" + spName + "] License Error");
			result.put("data", "");
		}

		return result;
	}

	public String getLicenseInfo(String id, int num)
	{
		byte[] lic = null;

		String filePath = SSOConfig.getInstance().getHomePath() + "/license/saml_" + id + ".lic";

		try {
			lic = FileUtil.read(filePath);
		}
		catch (FileNotFoundException e) {
			e.printStackTrace();
			return "Error";
		}
		catch (IOException e) {
			e.printStackTrace();
			return "Error";
		}

		ASN1InputStream asn1 = new ASN1InputStream(lic);
		ASN1Sequence seq = null;

		try {
			seq = (ASN1Sequence) asn1.readObject();
			asn1.close();
		}
		catch (IOException e) {
			e.printStackTrace();
			return "Error";
		}

		ASN1OctetString str = ASN1OctetString.getInstance(seq.getObjectAt(num));
		String contStr = new String(str.getOctets());

		if (!"".equals(contStr) && contStr.length() > 0) {
		}
		else {
			contStr = "";
		}

		return contStr;
	}

	public void setClientLicense(String id)
	{
		String licPath = SSOConfig.getInstance().getHomePath("license");

		verifying(licPath + "/saml_" + id + ".lic", id);
	}

	public void removeClientLicense(String id)
	{
		HashMap<String, String> licMap = (HashMap<String, String>) SessionManager.getInstance().getLicenseMap();
		licMap.remove(id);
	}
}