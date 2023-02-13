package com.dreamsecurity.sso.server.metadata;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileOutputStream;
import java.io.OutputStreamWriter;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import com.dreamsecurity.sso.lib.dss.s2.metadata.AssertionConsumerService;
import com.dreamsecurity.sso.lib.dss.s2.metadata.EntitiesDescriptor;
import com.dreamsecurity.sso.lib.dss.s2.metadata.EntityDescriptor;
import com.dreamsecurity.sso.lib.dss.s2.metadata.IDPSSODescriptor;
import com.dreamsecurity.sso.lib.dss.s2.metadata.KeyDescriptor;
import com.dreamsecurity.sso.lib.dss.s2.metadata.SPSSODescriptor;
import com.dreamsecurity.sso.lib.dss.s2.metadata.SingleLogoutService;
import com.dreamsecurity.sso.lib.dss.s2.metadata.SingleSignOnService;
import com.dreamsecurity.sso.lib.dsx.Configuration;
import com.dreamsecurity.sso.lib.dsx.security.SecurityException;
import com.dreamsecurity.sso.lib.dsx.security.SecurityHelper;
import com.dreamsecurity.sso.lib.dsx.security.credential.Credential;
import com.dreamsecurity.sso.lib.dsx.security.credential.UsageType;
import com.dreamsecurity.sso.lib.dsx.security.keyinfo.KeyInfoGenerator;
import com.dreamsecurity.sso.lib.jtm.DateTime;
import com.dreamsecurity.sso.lib.jtm.DateTimeZone;
import com.dreamsecurity.sso.server.config.SSOConfig;
import com.dreamsecurity.sso.server.crypto.CryptoApiException;
import com.dreamsecurity.sso.server.exception.SSOException;
import com.dreamsecurity.sso.server.util.SAMLUtil;
import com.dreamsecurity.sso.server.util.Util;

public class MetaGeneratorIDP
{
	public static final String SITE_NAME = "PROPERTY_SITE_NAME";
	public static final String SSO_LOCATION = "SSO_LOCATION";
	public static final String SLS_LOCATION = "SLS_LOCATION";
	public static final String E_CREDENTIAL = "E_CERT";
	public static final String S_CREDENTIAL = "S_CERT";
	public static final String ACS_LOCATION = "ACS_LOCATION";

	/***
	static {
		try {
			DefaultBootstrap.bootstrap();
		}
		catch (ConfigurationException e) {
			e.printStackTrace();
		}
	}
	***/

	public static EntityDescriptor generateSPDescriptor(String stsEntityId, String stsLocation, String stsLogoutLocation, Credential eCredential,
			Credential sCredential)
	{
		EntityDescriptor descriptor = (EntityDescriptor) SAMLUtil.buildXMLObject(EntityDescriptor.DEFAULT_ELEMENT_NAME);
		descriptor.setEntityID(stsEntityId);

		SPSSODescriptor desc = (SPSSODescriptor) SAMLUtil.buildXMLObject(SPSSODescriptor.DEFAULT_ELEMENT_NAME);

		desc.setAuthnRequestsSigned(new Boolean(true));
		desc.setWantAssertionsSigned(new Boolean(true));

		KeyDescriptor encryptionDescriptor = (KeyDescriptor) SAMLUtil.buildXMLObject(KeyDescriptor.DEFAULT_ELEMENT_NAME);
		encryptionDescriptor.setUse(UsageType.ENCRYPTION);

		KeyDescriptor signingDescriptor = (KeyDescriptor) SAMLUtil.buildXMLObject(KeyDescriptor.DEFAULT_ELEMENT_NAME);
		signingDescriptor.setUse(UsageType.SIGNING);

		try {
			KeyInfoGenerator eGen = SecurityHelper.getKeyInfoGenerator(eCredential, Configuration.getGlobalSecurityConfiguration(), null);
			encryptionDescriptor.setKeyInfo(eGen.generate(eCredential));

			KeyInfoGenerator sGen = SecurityHelper.getKeyInfoGenerator(sCredential, Configuration.getGlobalSecurityConfiguration(), null);
			signingDescriptor.setKeyInfo(sGen.generate(sCredential));
		}
		catch (SecurityException e) {
			e.printStackTrace();
		}

		desc.getKeyDescriptors().add(encryptionDescriptor);
		desc.getKeyDescriptors().add(signingDescriptor);

		String[] divide = stsLogoutLocation.split("\\^");
		for (int i = 0; i < divide.length; i++) {
			SingleLogoutService slo = (SingleLogoutService) SAMLUtil.buildXMLObject(SingleLogoutService.DEFAULT_ELEMENT_NAME);

			slo.setLocation(divide[i]);
			desc.getSingleLogoutServices().add(slo);
		}

		divide = stsLocation.split("\\^");
		for (int i = 0; i < divide.length; i++) {
			AssertionConsumerService acs = (AssertionConsumerService) SAMLUtil.buildXMLObject(AssertionConsumerService.DEFAULT_ELEMENT_NAME);

			if (i == 0)
				acs.setIsDefault(new Boolean(true));

			if (divide.length > 1)
				acs.setIndex(i);

			acs.setLocation(divide[i]);
			desc.getAssertionConsumerServices().add(acs);

			descriptor.getRoleDescriptors().add(desc);
		}

		return descriptor;
	}

	public static EntityDescriptor generateIdPDescriptor(String stsEntityId, String ssoLocation, String slsLocation, Credential eCredential,
			Credential sCredential)
	{
		EntityDescriptor descriptor = (EntityDescriptor) SAMLUtil.buildXMLObject(EntityDescriptor.DEFAULT_ELEMENT_NAME);
		descriptor.setEntityID(stsEntityId);

		IDPSSODescriptor desc = (IDPSSODescriptor) SAMLUtil.buildXMLObject(IDPSSODescriptor.DEFAULT_ELEMENT_NAME);

		KeyDescriptor encryptionDescriptor = (KeyDescriptor) SAMLUtil.buildXMLObject(KeyDescriptor.DEFAULT_ELEMENT_NAME);
		encryptionDescriptor.setUse(UsageType.ENCRYPTION);

		KeyDescriptor signingDescriptor = (KeyDescriptor) SAMLUtil.buildXMLObject(KeyDescriptor.DEFAULT_ELEMENT_NAME);
		signingDescriptor.setUse(UsageType.SIGNING);

		try {
			KeyInfoGenerator eGen = SecurityHelper.getKeyInfoGenerator(eCredential, Configuration.getGlobalSecurityConfiguration(), null);
			encryptionDescriptor.setKeyInfo(eGen.generate(eCredential));

			KeyInfoGenerator sGen = SecurityHelper.getKeyInfoGenerator(sCredential, Configuration.getGlobalSecurityConfiguration(), null);
			signingDescriptor.setKeyInfo(sGen.generate(sCredential));
		}
		catch (SecurityException e) {
			e.printStackTrace();
		}

		desc.getKeyDescriptors().add(encryptionDescriptor);
		desc.getKeyDescriptors().add(signingDescriptor);

		SingleSignOnService sso = (SingleSignOnService) SAMLUtil.buildXMLObject(SingleSignOnService.DEFAULT_ELEMENT_NAME);
		sso.setLocation(ssoLocation);
		desc.getSingleSignOnServices().add(sso);

		SingleLogoutService slo = (SingleLogoutService) SAMLUtil.buildXMLObject(SingleLogoutService.DEFAULT_ELEMENT_NAME);
		slo.setLocation(slsLocation);
		desc.getSingleLogoutServices().add(slo);

		descriptor.getRoleDescriptors().add(desc);
		return descriptor;
	}

	@SuppressWarnings("unchecked")
	public static EntitiesDescriptor generateDescriptor(String compcode, Map<String, Object> idpEntity, List<Object> spEntities)
			throws CryptoApiException, SSOException
	{
		EntitiesDescriptor parentDesc = (EntitiesDescriptor) SAMLUtil.buildXMLObject(EntitiesDescriptor.DEFAULT_ELEMENT_NAME);
		parentDesc.setValidUntil(new DateTime(DateTimeZone.UTC).plusYears(1));
		parentDesc.setName(compcode);

		String siteNm = (String) idpEntity.get(SITE_NAME);
		String ssoLocation = (String) idpEntity.get(SSO_LOCATION);
		String slsLocation = (String) idpEntity.get(SLS_LOCATION);
		Credential eCredential = (Credential) idpEntity.get(E_CREDENTIAL);
		Credential sCredential = (Credential) idpEntity.get(S_CREDENTIAL);

		EntityDescriptor idpDescriptor = generateIdPDescriptor(siteNm, ssoLocation, slsLocation, eCredential, sCredential);
		parentDesc.getEntityDescriptors().add(idpDescriptor);

		EntitiesDescriptor spDescs = (EntitiesDescriptor) SAMLUtil.buildXMLObject(EntitiesDescriptor.DEFAULT_ELEMENT_NAME);
		String acsLocation;
		Map<String, Object> spEntity;
		EntityDescriptor spDescriptor;

		for (int i = 0; i < spEntities.size(); i++) {
			spEntity = (Map<String, Object>) spEntities.get(i);
			siteNm = (String) spEntity.get(SITE_NAME);
			acsLocation = (String) spEntity.get(ACS_LOCATION);
			slsLocation = (String) spEntity.get(SLS_LOCATION);
			eCredential = (Credential) spEntity.get(E_CREDENTIAL);
			sCredential = (Credential) spEntity.get(S_CREDENTIAL);
			spDescriptor = generateSPDescriptor(siteNm, acsLocation, slsLocation, eCredential, sCredential);
			spDescs.getEntityDescriptors().add(spDescriptor);
		}

		parentDesc.getEntitiesDescriptors().add(spDescs);
		return parentDesc;
	}

	public int apply(ArrayList<?> idp, ArrayList<?> sp)
	{
		int rtn = 0;

		try {
			SSOConfig config = SSOConfig.getInstance();
			String certpath = config.getHomePath("/cert/");
			//System.out.println("homepath : " + certpath);

			String siteNm = (String) idp.get(0);
			String ssoLocation = (String) idp.get(1);
			String slsLocation = (String) idp.get(2);

			String idp_eCertFilePath = certpath + siteNm + "_Enc.der";
			String idp_sCertFilePath = certpath + siteNm + "_Sig.der";

			X509Certificate eCert = SAMLUtil.getCert(idp_eCertFilePath);
			X509Certificate sCert = SAMLUtil.getCert(idp_sCertFilePath);

			CredentialRepository.clearCredential();

			Credential eCredential = CredentialRepository.createCredential(siteNm + "_E", eCert);
			Credential sCredential = CredentialRepository.createCredential(siteNm + "_S", sCert);

			Map<String, Object> idpEntity = new HashMap<String, Object>();
			idpEntity.put(SITE_NAME, siteNm);
			idpEntity.put(SSO_LOCATION, ssoLocation);
			idpEntity.put(SLS_LOCATION, slsLocation);
			idpEntity.put(E_CREDENTIAL, eCredential);
			idpEntity.put(S_CREDENTIAL, sCredential);

			List<Object> spEntities = new ArrayList<Object>();
			int spCount = sp.size();

			for (int i = 0; i < spCount; i++) {
				ArrayList<?> spObj = (ArrayList<?>) sp.get(i);
				siteNm = (String) spObj.get(0);
				ssoLocation = (String) spObj.get(1);
				slsLocation = (String) spObj.get(2);

				String sp_eCertFilePath = certpath + siteNm + "_Enc.der";
				String sp_sCertFilePath = certpath + siteNm + "_Sig.der";

				eCert = SAMLUtil.getCert(sp_eCertFilePath);
				sCert = SAMLUtil.getCert(sp_sCertFilePath);

				eCredential = CredentialRepository.createCredential(siteNm + "_E", eCert);
				sCredential = CredentialRepository.createCredential(siteNm + "_S", sCert);

				Map<String, Object> spEntity = new HashMap<String, Object>();
				spEntity.put(SITE_NAME, siteNm);
				spEntity.put(ACS_LOCATION, ssoLocation);
				spEntity.put(SLS_LOCATION, slsLocation);
				spEntity.put(E_CREDENTIAL, eCredential);
				spEntity.put(S_CREDENTIAL, sCredential);
				spEntities.add(spEntity);
			}

			String xmlStr = "";
			EntitiesDescriptor descriptor = generateDescriptor("DREAM", idpEntity, spEntities);
			SAMLUtil.checkAndMarshall(descriptor);
			xmlStr = Util.domToStr(descriptor.getDOM().getOwnerDocument(), true);

			String metaFilename = SSOConfig.getInstance().getHomePath(SSOConfig.getInstance().getMetadataPath());
			File targetFile = new File(metaFilename);

			BufferedWriter output = new BufferedWriter(new OutputStreamWriter(new FileOutputStream(targetFile.getPath()), "UTF-8"));
			output.write(xmlStr);
			output.close();
			rtn = 1;
		}
		catch (Exception e) {
			rtn = -1;
			e.printStackTrace();
		}

		return rtn;
	}
}