package com.dreamsecurity.sso.server.repository.ldap;

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.xml.parsers.SAXParser;
import javax.xml.parsers.SAXParserFactory;

import org.xml.sax.Attributes;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;
import org.xml.sax.XMLReader;
import org.xml.sax.helpers.DefaultHandler;

import com.dreamsecurity.sso.lib.cdg.Digester;
import com.dreamsecurity.sso.lib.cdg.xmlrules.DigesterLoader;
import com.dreamsecurity.sso.lib.cln.StringUtils;
import com.dreamsecurity.sso.lib.slf.Logger;
import com.dreamsecurity.sso.lib.slf.LoggerFactory;
import com.dreamsecurity.sso.server.repository.ldap.pool.LdapPoolLoader;
import com.dreamsecurity.sso.server.repository.ldap.util.ResourceUtil;

public class LdapQueryMapManager
{
	private static Logger log = LoggerFactory.getLogger(LdapPoolLoader.class);

	private static Map queryMap;

	static
	{
		queryMap = new HashMap();
	}

	private LdapQueryMapManager()
	{
	}

	public static LdapQueryMap getLdapQueryMap(String id)
	{
		return (LdapQueryMap) queryMap.get(id);
	}

	private static String getMapId(String id)
	{
		return StringUtils.substringBeforeLast(id, ".");
	}

	private static String getQueryId(String id)
	{
		return StringUtils.substringAfterLast(id, ".");
	}

	public static LdapSelect getLdapSelectQuery(String id)
	{
		return (LdapSelect) getLdapQuery(id, LdapQuery.QUERY_SELECT);
	}

	public static LdapInsert getLdapInsertQuery(String id)
	{
		return (LdapInsert) getLdapQuery(id, LdapQuery.QUERY_INSERT);
	}

	public static LdapUpdate getLdapUpdateQuery(String id)
	{
		return (LdapUpdate) getLdapQuery(id, LdapQuery.QUERY_UPDATE);
	}

	public static LdapDelete getLdapDeleteQuery(String id)
	{
		return (LdapDelete) getLdapQuery(id, LdapQuery.QUERY_DELETE);
	}

	private static LdapQuery getLdapQuery(String id, int queryType)
	{
		LdapQuery ldapQuery = null;
		String queryId = getQueryId(id);
		String mapId = getMapId(id);

		LdapQueryMap ldapQueryMap = (LdapQueryMap) queryMap.get(mapId);

		if (ldapQueryMap != null) {
			switch (queryType) {
			case LdapQuery.QUERY_SELECT:
				ldapQuery = ldapQueryMap.getSelect(queryId);
				break;
			case LdapQuery.QUERY_INSERT:
				ldapQuery = ldapQueryMap.getInsert(queryId);
				break;
			case LdapQuery.QUERY_UPDATE:
				ldapQuery = ldapQueryMap.getUpdate(queryId);
				break;
			case LdapQuery.QUERY_DELETE:
				ldapQuery = ldapQueryMap.getDelete(queryId);
				break;
			}

			if (ldapQuery == null) {
				log.error("### Does not exist {} of {}", queryId, mapId);
				throw new RuntimeException("Does not exist " + queryId + " of " + mapId);
			}
		}
		else {
			log.error("Does not exist {}", mapId);
			throw new RuntimeException("Does not exist " + mapId);
		}

		return ldapQuery;
	}

	public static void loadQueryMap(String ruleFilePath, String configFilePath)
	{
		try {
			SAXParserFactory saxParserFactory = SAXParserFactory.newInstance();
			// saxParserFactory.setValidating(Boolean.getBoolean("javax.xml.parsers.validation"));

			SAXParser saxParser = saxParserFactory.newSAXParser();
			XMLReader xmlReader = saxParser.getXMLReader();

			BizQueryMapsHandler handler = new BizQueryMapsHandler();
			xmlReader.setContentHandler(handler);
			xmlReader.setErrorHandler(new DefaultHandler());
			xmlReader.parse(ResourceUtil.getInputSource(configFilePath));

			List resourceList = handler.getResourceList();
			Digester ldapQueryMapDigester = DigesterLoader.createDigester(ResourceUtil.getInputSource(ruleFilePath));

			for (int i = 0, limit = resourceList.size(); i < limit; i++) {
				log.debug("### Loading {}", resourceList.get(i));

				InputSource inputSource = ResourceUtil.getInputSource((String) resourceList.get(i));

				if (inputSource == null) {
					new IOException("Does not exist " + resourceList.get(i));
				}

				LdapQueryMap ldapQueryMap = (LdapQueryMap) ldapQueryMapDigester.parse(inputSource);

				queryMap.put(ldapQueryMap.getId(), ldapQueryMap);

				log.debug("### {} Loading Complete.", resourceList.get(i));
			}
		}
		catch (Exception e) {
			log.error("### LdapQueryMapManager loadQueryMap() Exception: {}", e.getMessage());
			throw new RuntimeException(e);
		}
	}

	static class BizQueryMapsHandler extends DefaultHandler
	{
		private List resourceList = null;

		public void startDocument() throws SAXException
		{
			resourceList = new ArrayList();
		}

		public void startElement(String namespaceURI, String localName, String name, Attributes atts) throws SAXException
		{
			if ("queryMap".equals(name)) {
				resourceList.add(atts.getValue("resource"));
			}
		}

		public List getResourceList()
		{
			return resourceList;
		}
	}
}