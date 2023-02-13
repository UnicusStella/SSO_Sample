package com.dreamsecurity.sso.server.metadata;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import com.dreamsecurity.sso.lib.dss.Configuration;
import com.dreamsecurity.sso.lib.dss.DefaultBootstrap;
import com.dreamsecurity.sso.lib.dss.s2.metadata.EntitiesDescriptor;
import com.dreamsecurity.sso.lib.dss.s2.metadata.EntityDescriptor;
import com.dreamsecurity.sso.lib.dss.s2.metadata.IDPSSODescriptor;
import com.dreamsecurity.sso.lib.dss.s2.metadata.SPSSODescriptor;
import com.dreamsecurity.sso.lib.dsx.ConfigurationException;
import com.dreamsecurity.sso.lib.dsx.XMLObject;
import com.dreamsecurity.sso.lib.dsx.io.Unmarshaller;
import com.dreamsecurity.sso.lib.dsx.io.UnmarshallingException;
import com.dreamsecurity.sso.lib.dsx.parse.BasicParserPool;
import com.dreamsecurity.sso.lib.dsx.parse.XMLParserException;
import com.dreamsecurity.sso.lib.slf.Logger;
import com.dreamsecurity.sso.lib.slf.LoggerFactory;
import org.w3c.dom.Document;

import com.dreamsecurity.sso.server.config.SSOConfig;
import com.dreamsecurity.sso.server.exception.SSOException;

public class MetadataRepository
{
	private static Logger log = LoggerFactory.getLogger(MetadataRepository.class);

	private static MetadataRepository instance = null;

	private Map<String, Object> idpEntities = new HashMap<String, Object>();
	private Map<String, Object> spEntities = new HashMap<String, Object>();

	private long metaloadedtime = 0;
	private String compCode = null;

	private MetadataRepository() throws ConfigurationException
	{
		DefaultBootstrap.bootstrap();
	}

	public static MetadataRepository getInstance()
	{
		if (instance == null) {
			synchronized (MetadataRepository.class) {
				if (instance == null) {
					try {
						instance = new MetadataRepository();
					}
					catch (ConfigurationException e) {
						e.printStackTrace();
					}
				}
			}
		}

		SSOConfig config = SSOConfig.getInstance();
		loadMetadata(config.getHomePath(config.getString("metadata.path", "config/metadata.xml")));

		return instance;
	}

	public static boolean loadMetadata(String metadataFilePath)
	{
		BasicParserPool ppMgr = new BasicParserPool();
		ppMgr.setNamespaceAware(true);

		EntitiesDescriptor desc;

		try {
			File file = new File(metadataFilePath);
			if (instance.metaloadedtime >= file.lastModified()) {
				return true;
			}

			synchronized (instance) {
				if (instance.metaloadedtime != 0) {
					instance.idpEntities.clear();
					instance.spEntities.clear();
				}

				Document inCommonMDDoc = ppMgr.parse(new FileInputStream(file));
				Unmarshaller unmarshaller = Configuration.getUnmarshallerFactory().getUnmarshaller(inCommonMDDoc.getDocumentElement());
				XMLObject xmlObject = unmarshaller.unmarshall(inCommonMDDoc.getDocumentElement());
				if (!(xmlObject instanceof EntitiesDescriptor)) {
					return false;
				}

				desc = (EntitiesDescriptor) xmlObject;
				instance.compCode = desc.getName();
				List<?> idpDesc = desc.getEntityDescriptors();
				List<?> spDesc = desc.getEntitiesDescriptors();
				if (idpDesc.isEmpty() || spDesc.isEmpty()) {
					return false;
				}

				EntityDescriptor idpEntity = (EntityDescriptor) idpDesc.get(0);
				if (!(idpEntity.getRoleDescriptors().get(0) instanceof IDPSSODescriptor)) {
					return false;
				}

				instance.idpEntities.put(idpEntity.getEntityID(), idpEntity);
				EntityDescriptor spEntity;
				List<?> spEntities = ((EntitiesDescriptor) spDesc.get(0)).getEntityDescriptors();
				for (int i = 0; i < spEntities.size(); i++) {
					spEntity = (EntityDescriptor) spEntities.get(i);
					if (!(spEntity.getRoleDescriptors().get(0) instanceof SPSSODescriptor)) {
						continue;
					}
					// log.debug("### {} meta loaded", spEntity.getEntityID());
					instance.spEntities.put(spEntity.getEntityID(), spEntity);
				}

				instance.metaloadedtime = System.currentTimeMillis();
				return true;
			}
		}
		catch (XMLParserException e) {
			e.printStackTrace();
		}
		catch (FileNotFoundException e) {
			e.printStackTrace();
		}
		catch (UnmarshallingException e) {
			e.printStackTrace();
		}

		return false;
	}

	public EntityDescriptor getSelfEntity() throws SSOException
	{
		if (isIDP()) {
			return (EntityDescriptor) instance.idpEntities.values().iterator().next();
		}

		return getEntityDescriptor(SSOConfig.getInstance().getServerName());
	}

	protected EntityDescriptor getEntityDescriptor(String entityId) throws SSOException
	{
		if (instance.idpEntities.containsKey(entityId)) {
			return (EntityDescriptor) instance.idpEntities.get(entityId);
		}
		if (instance.spEntities.containsKey(entityId)) {
			return (EntityDescriptor) instance.spEntities.get(entityId);
		}

		// todo reload
		log.debug("### No matched entity descriptor ({})", entityId);
		throw new SSOException("No matched entity descriptor (" + entityId + ")");
	}

	public SPSSODescriptor getSPDescriptor(String providerName) throws SSOException
	{
		EntityDescriptor entityDescriptor = getEntityDescriptor(providerName);
		return ((SPSSODescriptor) entityDescriptor.getRoleDescriptors().get(0));
	}

	public IDPSSODescriptor getIDPDescriptor() throws SSOException
	{
		EntityDescriptor entityDescriptor = (EntityDescriptor) instance.idpEntities.values().iterator().next();
		return ((IDPSSODescriptor) entityDescriptor.getRoleDescriptors().get(0));
	}

	public String getCompCode()
	{
		return compCode;
	}

	public boolean isIDP()
	{
		try {
			EntityDescriptor entityDescriptor = instance.getEntityDescriptor(SSOConfig.getInstance().getServerName());
			return entityDescriptor.getRoleDescriptors().get(0) instanceof IDPSSODescriptor;
		}
		catch (SSOException e) {
			e.printStackTrace();
		}

		return false;
	}

	public String getIDPName()
	{
		EntityDescriptor entityDescriptor = (EntityDescriptor) instance.idpEntities.values().iterator().next();
		return entityDescriptor.getEntityID();
	}

	public List<String> getSPNames()
	{
		ArrayList<String> splist = new ArrayList<String>(instance.spEntities.keySet());

		Collections.sort(splist, new Comparator<String>()
		{
			public int compare(String o1, String o2)
			{
				return o1.compareTo(o2);
			}
		});

		return splist;
	}
}