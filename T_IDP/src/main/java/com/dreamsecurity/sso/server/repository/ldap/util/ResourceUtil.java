package com.dreamsecurity.sso.server.repository.ldap.util;

import java.io.File;
import java.net.URL;

import org.xml.sax.InputSource;

import com.dreamsecurity.sso.lib.slf.Logger;
import com.dreamsecurity.sso.lib.slf.LoggerFactory;
import com.dreamsecurity.sso.server.config.SSOConfig;
import com.dreamsecurity.sso.server.repository.ldap.pool.LdapPoolLoader;

public class ResourceUtil
{
	private static Logger log = LoggerFactory.getLogger(ResourceUtil.class);

	private ResourceUtil()
	{
	}

	public static InputSource getInputSource(String uri)
	{
		InputSource inputSource = null;
		File ruleFile = new File(SSOConfig.getInstance().getHomePath(uri));

		log.debug("### Resource File path: {}", ruleFile.getAbsolutePath());

		try {
			if (ruleFile.exists()) {
				inputSource = new InputSource(ruleFile.toURL().openStream());
			}
			else {
				log.debug("### Resource File Not Found. Search from class-path: {}", uri);

				inputSource = new InputSource(LdapPoolLoader.class.getClassLoader().getResourceAsStream(uri));
			}
		}
		catch (Exception e) {
			log.error("### ResourceUtil getInputSource() Exception: {}", e.getMessage());
		}

		return inputSource;
	}

	public static URL getUrl(String uri)
	{
		URL url = null;
		File resourceFile = new File(SSOConfig.getInstance().getHomePath(uri));

		log.debug("### Resource File path: {}", resourceFile.getAbsolutePath());

		try {
			if (resourceFile.exists()) {
				url = resourceFile.toURL();
			}
			else {
				log.debug("### Resource File Not Found. Search from class-path: {}", uri);

				url = ResourceUtil.class.getClassLoader().getResource(uri);
			}
		}
		catch (Exception e) {
			log.error("### ResourceUtil getUrl() Exception: {}", e.getMessage());
		}

		return url;
	}
}