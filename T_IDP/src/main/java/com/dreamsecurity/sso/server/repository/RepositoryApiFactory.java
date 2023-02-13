package com.dreamsecurity.sso.server.repository;

import com.dreamsecurity.sso.lib.slf.Logger;
import com.dreamsecurity.sso.lib.slf.LoggerFactory;

import com.dreamsecurity.sso.server.config.SSOConfig;
import com.dreamsecurity.sso.server.exception.SSOException;
import com.dreamsecurity.sso.server.util.Util;

public class RepositoryApiFactory
{
	private static Logger log = LoggerFactory.getLogger(RepositoryApiFactory.class);

	public void createRepository() throws SSOException
	{
		SSOConfig config = SSOConfig.getInstance();
		String className = config.getString("repository.class", "");

		if (Util.isEmpty(className)) {
			className = "com.dreamsecurity.sso.server.repository.api.DefaultRepositoryApi";
		}

		log.debug("### RepositoryAPI class : {}", className);

		try {
			Class<?> cls = Class.forName(className);
			RepositoryApi repositoryApi = (RepositoryApi) cls.newInstance();

			repositoryApi.create();
		}
		catch (Exception e) {
			log.error("### createRepository() Exception : {}", e.toString());
			throw new SSOException(e);
		}

		return;
	}
}