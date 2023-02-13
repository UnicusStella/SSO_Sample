package com.dreamsecurity.sso.agent.metadata;

import java.io.ByteArrayInputStream;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.Map;

import com.dreamsecurity.sso.lib.dss.s2.metadata.EntityDescriptor;
import com.dreamsecurity.sso.lib.dss.s2.metadata.KeyDescriptor;
import com.dreamsecurity.sso.lib.dss.s2.metadata.RoleDescriptor;
import com.dreamsecurity.sso.lib.dsx.security.credential.Credential;
import com.dreamsecurity.sso.lib.dsx.security.credential.UsageType;
import com.dreamsecurity.sso.lib.dsx.security.x509.BasicX509Credential;
import com.dreamsecurity.sso.lib.dsx.signature.KeyInfo;
import com.dreamsecurity.sso.lib.dsx.signature.X509Data;
import com.dreamsecurity.sso.lib.dsx.util.Base64;
import com.dreamsecurity.sso.agent.common.MStatus;
import com.dreamsecurity.sso.agent.exception.SSOException;
import com.dreamsecurity.sso.agent.log.Logger;
import com.dreamsecurity.sso.agent.log.LoggerFactory;

public class CredentialRepository
{
	private static Logger log = LoggerFactory.getInstance().getLogger(CredentialRepository.class);

	static Map<String, BasicX509Credential> credentialMap = new HashMap<String, BasicX509Credential>();

	public static Credential getCredential(String serverName, int type)
	{
		String mapKey = (type == MStatus.ENC_CERT ? serverName +"_E" : serverName +"_S");

		if (credentialMap.containsKey(mapKey)) {
			return (Credential) credentialMap.get(mapKey);
		}

		try {
			EntityDescriptor entityDescriptor = MetadataRepository.getInstance().getEntityDescriptor(serverName);
			RoleDescriptor roleDescriptor = entityDescriptor.getRoleDescriptors().get(0);
			String value = getX509CertStr(roleDescriptor, type);

			return createCredential(mapKey, Base64.decode(value));
		}
		catch (SSOException e) {
			log.error("### getCredential() SSOException : " + e.getErrorCode() + ", " + e.getMessage());
			e.printStackTrace();
		}

		return null;
	}

	private static String getX509CertStr(RoleDescriptor roleDescriptor, int type)
	{
		KeyDescriptor kds = null;

		if (type == MStatus.ENC_CERT) {
			if (roleDescriptor.getKeyDescriptors().get(0).getUse().equals(UsageType.ENCRYPTION))
				kds = roleDescriptor.getKeyDescriptors().get(0);
			else
				kds = roleDescriptor.getKeyDescriptors().get(1);
		}
		else {
			if (roleDescriptor.getKeyDescriptors().get(0).getUse().equals(UsageType.SIGNING))
				kds = roleDescriptor.getKeyDescriptors().get(0);
			else
				kds = roleDescriptor.getKeyDescriptors().get(1);
		}

		KeyInfo ki = kds.getKeyInfo();
		X509Data x509Data = ki.getX509Datas().get(0);

		String value = x509Data.getX509Certificates().get(0).getValue();
		value = value.replace("\n", "");
		return value;
	}

	public static Credential createCredential(String siteNm, X509Certificate cert)
	{
		if (credentialMap.containsKey(siteNm))
			return (Credential) credentialMap.get(siteNm);

		BasicX509Credential credential = new BasicX509Credential();
		credential.setEntityId(siteNm);
		credential.setEntityCertificate(cert);
		credential.setPublicKey(cert.getPublicKey());

		credentialMap.put(siteNm, credential);
		return credential;
	}

	public static Credential createCredential(String siteNm, byte[] certByte)
	{
		if (credentialMap.containsKey(siteNm))
			return (Credential) credentialMap.get(siteNm);

		BasicX509Credential credential = new BasicX509Credential();
		credential.setEntityId(siteNm);
		CertificateFactory certificateFactory = null;

		try {
			certificateFactory = CertificateFactory.getInstance("X509");
			X509Certificate cert = (X509Certificate) certificateFactory.generateCertificate(new ByteArrayInputStream(certByte));
			credential.setEntityCertificate(cert);
			credential.setPublicKey(cert.getPublicKey());
		}
		catch (CertificateException e) {
			e.printStackTrace();
			return null;
		}

		credentialMap.put(siteNm, credential);
		return credential;
	}

	public static void clearCredential()
	{
		credentialMap.clear();
		return;
	}
}