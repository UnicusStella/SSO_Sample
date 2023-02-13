package com.dreamsecurity.sso.server.repository.ldap;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import netscape.ldap.LDAPAttribute;
import netscape.ldap.LDAPAttributeSet;
import netscape.ldap.LDAPCompareAttrNames;
import netscape.ldap.LDAPConnection;
import netscape.ldap.LDAPEntry;
import netscape.ldap.LDAPException;
import netscape.ldap.LDAPModification;
import netscape.ldap.LDAPModificationSet;
import netscape.ldap.LDAPSchema;
import netscape.ldap.LDAPSearchResults;
import netscape.ldap.LDAPv3;

import com.dreamsecurity.sso.lib.cbu.BeanMap;
import com.dreamsecurity.sso.lib.cbu.BeanUtils;
import com.dreamsecurity.sso.lib.cln.ArrayUtils;
import com.dreamsecurity.sso.lib.cln.text.StrSubstitutor;
import com.dreamsecurity.sso.lib.slf.Logger;
import com.dreamsecurity.sso.lib.slf.LoggerFactory;
import com.dreamsecurity.sso.server.repository.ldap.pool.LdapPool;
import com.dreamsecurity.sso.server.repository.ldap.pool.LdapPoolManager;
import com.dreamsecurity.sso.server.util.Util;

public class LdapQueryExecutor
{
	private static Logger log = LoggerFactory.getLogger(LdapQueryExecutor.class);

	private static final int ATTRIBUTE_REQUIRED = 0;
	private static final int ATTRIBUTE_OPTIONAL = 1;
	private static final int ATTRIBUTE_ALL = 2;

	private String poolName;
	private LdapPool ldapPool;

	public LdapQueryExecutor()
	{
	}

	public LdapQueryExecutor(String poolName)
	{
		this.poolName = poolName;
		ldapPool = (LdapPool) LdapPoolManager.getInstance().getPool(poolName);
	}

	public String getPoolName()
	{
		return poolName;
	}

	public LdapPool getldapPool()
	{
		return ldapPool;
	}

	private LDAPConnection getLdapConnection()
	{
		LDAPConnection ldConn;

		try {
			ldConn = (LDAPConnection) ldapPool.getConnection();
		}
		catch (Exception e) {
			log.error("### LdapQueryExecutor getLdapConnection() Exception: {}", e.getMessage());
			throw new RuntimeException(e);
		}

		return ldConn;
	}

	private Map selectOne(LdapSelect selectQuery, Object parameterObject)
	{
		Map resultMap = null;
		LDAPConnection ld = null;

		try {
			String base = selectQuery.getBase();
			String filter = selectQuery.getFilter();

			if (selectQuery.isSubstitute) {
				base = mappingParameterValues(base, parameterObject);
				log.debug("### [base] {}", base);

				filter = mappingParameterValues(filter, parameterObject);
				log.debug("### [filter] {}", filter);
			}

			ld = getLdapConnection();

			if (filter == null || "".equals(filter)) {
				resultMap = convertEntryIntoMap(selectQuery, ld.read(base, selectQuery.getAttributes()));
			}
			else {
				LDAPSearchResults ldRs = ld.search(base, selectQuery.getScope(), filter, selectQuery.getAttributes(), false);
				resultMap = convertEntryIntoMap(selectQuery, ldRs.next());
			}
		}
		catch (LDAPException le) {
			if (le.getLDAPResultCode() == LDAPException.NO_SUCH_OBJECT) {
				resultMap = Collections.EMPTY_MAP;
			}
			else {
				log.error("### LdapQueryExecutor selectOne() LDAPException: {}", le.getMessage());
				throw new RuntimeException(le);
			}
		}
		catch (Exception e) {
			log.error("### LdapQueryExecutor selectOne() Exception: {}", e.getMessage());
			throw new RuntimeException(e);
		}
		finally {
			releaseResource(ld);
		}

		return resultMap;
	}

	private List selectList(LdapSelect selectQuery, Object parameterObject)
	{
		List resultList = null;
		LDAPConnection ld = null;

		try {
			String base = selectQuery.getBase();
			String filter = selectQuery.getFilter();

			if (selectQuery.isSubstitute) {
				base = mappingParameterValues(base, parameterObject);
				log.debug("### [base] {}", base);

				filter = mappingParameterValues(filter, parameterObject);
				log.debug("### [filter] {}", filter);
			}

			if (filter == null || "".equals(filter)) {
				throw new RuntimeException("selectList에서는 Filter가 필수입니다.");
			}
			else {
				ld = getLdapConnection();
				LDAPSearchResults ldRs = ld.search(base, selectQuery.getScope(), filter, selectQuery.getAttributes(), false);

				if (selectQuery.isSort()) {
					ldRs.sort(new LDAPCompareAttrNames(selectQuery.getSortAttributeNames(), selectQuery.getSortAscendingValues()));
				}

				resultList = new ArrayList();

				if ("HashMap".equalsIgnoreCase(selectQuery.getResultClass())) {
					while (ldRs.hasMoreElements()) {
						resultList.add(convertEntryIntoMap(selectQuery, ldRs.next()));
					}
				}
				else {
					while (ldRs.hasMoreElements()) {
						Object bean = getBean(selectQuery.getResultClass());
						BeanUtils.populate(bean, convertEntryIntoMap(selectQuery, ldRs.next()));

						resultList.add(bean);
					}
				}
			}
		}
		catch (LDAPException le) {
			if (le.getLDAPResultCode() == LDAPException.NO_SUCH_OBJECT) {
				resultList = Collections.EMPTY_LIST;
			}
			else {
				log.error("### LdapQueryExecutor selectList() LDAPException: {}", le.getMessage());
				throw new RuntimeException(le);
			}
		}
		catch (Exception e) {
			log.error("### LdapQueryExecutor selectList() Exception: {}", e.getMessage());
			throw new RuntimeException(e);
		}
		finally {
			releaseResource(ld);
		}

		return resultList;
	}

	private int selectCount(LdapSelect selectQuery, Object parameterObject)
	{
		int resultCount = 0;
		LDAPConnection ld = null;

		try {
			String base = selectQuery.getBase();
			String filter = selectQuery.getFilter();

			if (selectQuery.isSubstitute) {
				base = mappingParameterValues(base, parameterObject);
				log.debug("### [base] {}", base);

				filter = mappingParameterValues(filter, parameterObject);
				log.debug("### [filter] {}", filter);
			}

			if (filter == null || "".equals(filter)) {
				throw new RuntimeException("selectCount에서는 Filter가 필수입니다.");
			}
			else {
				ld = getLdapConnection();
				LDAPSearchResults ldRs = ld.search(base, selectQuery.getScope(), filter, selectQuery.getAttributes(), false);
				resultCount = ldRs.getCount();
			}
		}
		catch (LDAPException le) {
			if (le.getLDAPResultCode() == LDAPException.NO_SUCH_OBJECT) {
				resultCount = 0;
			}
			else {
				log.error("### LdapQueryExecutor selectCount() LDAPException: {}", le.getMessage());
				throw new RuntimeException(le);
			}
		}
		catch (Exception e) {
			log.error("### LdapQueryExecutor selectCount() Exception: {}", e.getMessage());
			throw new RuntimeException(e);
		}
		finally {
			releaseResource(ld);
		}

		log.debug("### [{}] result: count {}", selectQuery.getId(), resultCount);

		return resultCount;
	}

	public Map queryForMap(String id)
	{
		return queryForMap(id, null);
	}

	public Object queryForObject(String id)
	{
		return queryForMap(id, null);
	}

	public Map queryForMap(String id, Object parameterObject)
	{
		LdapSelect selectQuery = LdapQueryMapManager.getLdapSelectQuery(id);

		return queryForMap(selectQuery, parameterObject);
	}

	public Map queryForMap(LdapSelect selectQuery, Object parameterObject)
	{
		Map resultMap = null;

		log.debug("### [{}]", selectQuery.getId());

		resultMap = selectOne(selectQuery, parameterObject);

		log.debug("### [{}] result: {}", selectQuery.getId(), resultMap);

		return resultMap;
	}

	public Object queryForObject(String id, Object parameterObject)
	{
		LdapSelect selectQuery = LdapQueryMapManager.getLdapSelectQuery(id);

		return queryForObject(selectQuery, parameterObject);
	}

	public Object queryForObject(LdapSelect selectQuery, Object parameterObject)
	{
		log.debug("### [{}]", selectQuery.getId());

		Map resultMap = selectOne(selectQuery, parameterObject);

		Object bean = null;

		try {
			bean = getBean(selectQuery.getResultClass());
			BeanUtils.populate(bean, resultMap);
		}
		catch (Exception e) {
			log.error("### LdapQueryExecutor queryForObject() Exception: {}", e.getMessage());
			throw new RuntimeException(e);
		}

		log.debug("### [{}] result: {}", selectQuery.getId(), bean);

		return bean;
	}

	public List queryForList(String id)
	{
		return queryForList(id, null);
	}

	public List queryForList(String id, Object parameterObject)
	{
		LdapSelect selectQuery = LdapQueryMapManager.getLdapSelectQuery(id);

		return queryForList(selectQuery, parameterObject);
	}

	public List queryForList(LdapSelect selectQuery, Object parameterObject)
	{
		log.debug("### [{}]", selectQuery.getId());

		List resultList = selectList(selectQuery, parameterObject);

		log.debug("### [{}] result: {}", selectQuery.getId(), resultList.size());

		return resultList;
	}

	public int queryForCount(String id, Object parameterObject)
	{
		LdapSelect selectQuery = LdapQueryMapManager.getLdapSelectQuery(id);

		return selectCount(selectQuery, parameterObject);
	}

	public void addData(String id, Object parameterObject)
	{
		LdapInsert insertQuery = LdapQueryMapManager.getLdapInsertQuery(id);

		addData(insertQuery, parameterObject);
	}

	public void addData(LdapInsert insertQuery, Object parameterObject)
	{
		LDAPConnection ld = null;

		log.debug("### [{}]", insertQuery.getId());

		try {
			Map parameterMap = changeToMap(parameterObject);
			LDAPAttributeSet attributeSet = new LDAPAttributeSet();
			LDAPAttribute objectClass = null;

			// Query XML에 정의된 object class를 먼저 설정하고 없으면 parameter에 있는 것을 사용.
			List objectClassList = insertQuery.getObjectClassList();

			if (objectClassList != null && objectClassList.size() > 0) {
				objectClass = createLdapAttribute("objectclass", objectClassList);
				attributeSet.add(objectClass);
			}

			int limit = 0;

			if (insertQuery.getAttributes() != null) {
				limit = insertQuery.getAttributes().length;
			}

			for (int i = 0; i < limit; i++) {
				String attributeName = insertQuery.getAttribute(i);
				String aliasName = insertQuery.getAliasOfAttribute(attributeName);

				Object attributeValue = pullOutAttributeValue(insertQuery, aliasName, parameterMap);

				if (attributeValue == null) {
					log.debug("### {}'s attribute value is not exist. skip!", attributeName);
					continue;
				}
				else {
					if (Util.isEmpty((String) attributeValue)) {
						log.debug("### {}'s attribute value is empty. skip!", attributeName);
						continue;
					}
				}

				LDAPAttribute attribute = createLdapAttribute(attributeName, attributeValue);

				log.debug("### binding [{}, {}] : {}", aliasName, attributeName, ArrayUtils.toString(attribute.getStringValueArray()));

				attributeSet.add(attribute);

				if ("objectclass".equalsIgnoreCase(attributeName)) {
					objectClass = attribute;
				}
			}

			if (objectClass == null || objectClass.getStringValueArray().length < 1) {
				throw new RuntimeException("Necessary Attribute[objectClass] is empty");
			}

			String base = insertQuery.getBase();

			if (insertQuery.isSubstitute) {
				base = mappingParameterValues(base, parameterObject);
				log.debug("### [base] {}", base);
			}

			ld = getLdapConnection();
			ld.add(new LDAPEntry(base, attributeSet));

			log.debug("### [{}] Success Insert Data", insertQuery.getId());
		}
		catch (LDAPException le) {
			if (le.getLDAPResultCode() == LDAPException.OBJECT_CLASS_VIOLATION) {
				log.error("### Necessary Attribute is empty");
				throw new RuntimeException(le);
			}
			else if (le.getLDAPResultCode() == LDAPException.ENTRY_ALREADY_EXISTS) {
				log.error("### Duplicated Data Exist");
				throw new RuntimeException(le);
			}
			else {
				log.error("### LdapQueryExecutor addData() LDAPException: {}", le.getMessage());
				throw new RuntimeException(le);
			}
		}
		catch (Exception e) {
			log.error("### LdapQueryExecutor addData() Exception: {}", e.getMessage());
			throw new RuntimeException(e);
		}
		finally {
			releaseResource(ld);
		}
	}

	public void modifyData(String id, Object parameterObject)
	{
		LdapUpdate updateQuery = LdapQueryMapManager.getLdapUpdateQuery(id);

		modifyData(updateQuery, parameterObject);
	}

	public void modifyData(LdapUpdate updateQuery, Object parameterObject)
	{
		LDAPConnection ld = null;

		log.debug("### [{}]", updateQuery.getId());

		try {
			Map parameterMap = this.changeToMap(parameterObject);
			LDAPModificationSet modificationSet = new LDAPModificationSet();

			for (int i = 0, limit = updateQuery.getAttributeList().size(); i < limit; i++) {
				String attributeName = updateQuery.getAttribute(i);
				String aliasName = updateQuery.getAliasOfAttribute(attributeName);

				if (updateQuery.getAttributeModificationType(i) == LDAPModification.DELETE) {
					log.debug("### {} binding [{}]", updateQuery.getAttributeModificationTypeString(i), aliasName);

					modificationSet.add(updateQuery.getAttributeModificationType(i), new LDAPAttribute(attributeName));
				}
				else {
					Object attributeValue = pullOutAttributeValue(updateQuery, aliasName, parameterMap);

					if (attributeValue == null) {
						log.debug("### {}'s attribute value is not exist. skip!", attributeName);
						continue;
					}
					else {
						if (Util.isEmpty((String) attributeValue)) {
							log.debug("### DELETE binding [{}] change modification type", aliasName);

							modificationSet.add(LDAPModification.DELETE, new LDAPAttribute(attributeName));
						}
						else {
							LDAPAttribute attribute = createLdapAttribute(attributeName, attributeValue);

							log.debug("### {} binding [{}] : {}", updateQuery.getAttributeModificationTypeString(i), aliasName,
									ArrayUtils.toString(attribute.getStringValueArray()));

							modificationSet.add(updateQuery.getAttributeModificationType(i), attribute);
						}
					}
				}
			}

			if (modificationSet.size() < 1) {
				log.info("### Modification Attribute is empty.");
				return;
			}

			String base = updateQuery.getBase();

			if (updateQuery.isSubstitute) {
				base = mappingParameterValues(base, parameterObject);
				log.debug("### [base] {}", base);
			}

			ld = getLdapConnection();
			ld.modify(base, modificationSet);

			log.debug("### [{}] Success Update Data", updateQuery.getId());
		}
		catch (LDAPException le) {
			if (le.getLDAPResultCode() == LDAPException.NO_SUCH_ATTRIBUTE) {
				log.error("### Does not exist attribute");
			}

			log.error("### LdapQueryExecutor modifyData() LDAPException: {}", le.getMessage());

			throw new RuntimeException(le);
		}
		catch (Exception e) {
			log.error("### LdapQueryExecutor modifyData() Exception: {}", e.getMessage());

			throw new RuntimeException(e);
		}
		finally {
			releaseResource(ld);
		}
	}

	public void deleteData(String id, Object parameterObject)
	{
		LdapDelete deleteQuery = LdapQueryMapManager.getLdapDeleteQuery(id);

		deleteData(deleteQuery, parameterObject);
	}

	public void deleteData(LdapDelete deleteQuery, Object parameterObject)
	{
		LDAPConnection ld = null;

		log.debug("### [{}]", deleteQuery.getId());

		try {
			String base = deleteQuery.getBase();

			if (deleteQuery.isSubstitute) {
				base = mappingParameterValues(base, parameterObject);
				log.debug("### [base] {}", base);
			}

			ld = getLdapConnection();

			if (deleteQuery.isCascade()) {
				deleteCascade(ld, base);
			}
			else {
				ld.delete(base);

				log.debug("### [{}] Success Delete Data", deleteQuery.getId());
			}
		}
		catch (Exception e) {
			log.error("### LdapQueryExecutor deleteData() Exception: {}", e.getMessage());

			throw new RuntimeException(e);
		}
		finally {
			releaseResource(ld);
		}
	}

	private void deleteCascade(LDAPConnection ld, String dn)
	{
		try {
			LDAPSearchResults ldRs = ld.search(dn, LDAPConnection.SCOPE_ONE, "objectclass=*", new String[] { LDAPv3.NO_ATTRS }, false);

			while (ldRs.hasMoreElements()) {
				LDAPEntry entry = ldRs.next();
				deleteCascade(ld, entry.getDN());
			}

			ld.delete(dn);

			log.debug("### Success Delete Data: {} >>", dn);
		}
		catch (Exception e) {
			log.error("### LdapQueryExecutor deleteCascade() Exception: {}", e.getMessage());

			throw new RuntimeException(e);
		}
	}

	private Object pullOutAttributeValue(LdapQuery ldapQuery, String attributeName, Map targetMap)
	{
		Object attributeValue = null;

		for (Iterator iterator = targetMap.keySet().iterator(); iterator.hasNext();) {
			String key = (String) iterator.next();

			if (attributeName.equalsIgnoreCase(key)) {
				attributeValue = targetMap.get(key);
				break;
			}
		}

		// 값이 없으면 기본값 설정.
		if (attributeValue == null) {
			attributeValue = ldapQuery.getDefaultValueOfAttribute(attributeName);
		}

		return attributeValue;
	}

	private LDAPAttribute createLdapAttribute(String attributeName, Object attributeValue)
	{
		LDAPAttribute attribute = null;

		if (attributeValue == null) {
			throw new RuntimeException(attributeName + "'s Value is null.");
		}
		else if (attributeValue instanceof String) {
			attribute = new LDAPAttribute(attributeName, (String) attributeValue);
		}
		else if (attributeValue instanceof String[]) {
			attribute = new LDAPAttribute(attributeName, (String[]) attributeValue);
		}
		else if (attributeValue instanceof List) {
			attribute = new LDAPAttribute(attributeName, Util.list2StringArray((List) attributeValue));
		}
		else if (attributeValue instanceof Number) {
			attribute = new LDAPAttribute(attributeName, attributeValue.toString());
		}
		else {
			throw new RuntimeException("Not support data type.(" + attributeName + ", " + attributeValue.getClass().getName() + ")");
		}

		return attribute;
	}

	private Map changeToMap(Object targetObject)
	{
		Map targetMap = null;

		if (targetObject instanceof Map) {
			targetMap = (Map) targetObject;
		}
		else {
			targetMap = new BeanMap(targetObject);
		}

		return targetMap;
	}

	public String[] getObjectClassNames(String dn)
	{
		String[] objectClassNames = null;
		LDAPConnection ld = null;

		try {
			log.debug("### dn: {}", dn);

			ld = getLdapConnection();
			LDAPEntry entry = ld.read(dn);

			if (entry != null) {
				objectClassNames = entry.getAttribute("objectclass").getStringValueArray();
			}

			log.debug("#### result: {}", ArrayUtils.toString(objectClassNames));
		}
		catch (LDAPException le) {
			if (le.getLDAPResultCode() == LDAPException.INVALID_DN_SYNTAX) {

			}
			else {
				log.error("### LdapQueryExecutor getObjectClassNames() LDAPException: {}", le.getMessage());
				throw new RuntimeException(le);
			}
		}
		catch (Exception e) {
			log.error("### LdapQueryExecutor getObjectClassNames() Exception: {}", e.getMessage());
			throw new RuntimeException(e);
		}
		finally {
			releaseResource(ld);
		}

		return objectClassNames;
	}

	public String getBaseDnOfSite()
	{
		return "";
	}

	public String[] getAttributeNames(String objectClassName, int attributeType)
	{
		String[] attributeNames = null;
		LDAPConnection ld = null;

		try {
			LDAPSchema schema = new LDAPSchema();
			ld = getLdapConnection();
			schema.fetchSchema(ld);
			List attributeNameList = new ArrayList();
			Enumeration[] enumerations = null;

			if (attributeType == ATTRIBUTE_REQUIRED) {
				enumerations = new Enumeration[1];
				enumerations[0] = schema.getObjectClass(objectClassName).getRequiredAttributes();
			}
			else if (attributeType == ATTRIBUTE_OPTIONAL) {
				enumerations = new Enumeration[1];
				enumerations[0] = schema.getObjectClass(objectClassName).getOptionalAttributes();
			}
			else if (attributeType == ATTRIBUTE_ALL) {
				enumerations = new Enumeration[2];
				enumerations[0] = schema.getObjectClass(objectClassName).getRequiredAttributes();
				enumerations[1] = schema.getObjectClass(objectClassName).getOptionalAttributes();
			}

			for (int i = 0, limit = enumerations.length; i < limit; i++) {
				while (enumerations[i].hasMoreElements()) {
					attributeNameList.add(enumerations[i].nextElement());
				}
			}

			attributeNames = Util.list2StringArray(attributeNameList);
		}
		catch (LDAPException le) {
			log.error("### LdapQueryExecutor getAttributeNames() LDAPException: {}", le.getMessage());

			throw new RuntimeException(le);
		}
		catch (Exception e) {
			log.error("### LdapQueryExecutor getAttributeNames() Exception: {}", e.getMessage());

			throw new RuntimeException(e);
		}
		finally {
			releaseResource(ld);
		}

		return attributeNames;
	}

	public String[] getRequiredAttributes(String objectClassName)
	{
		log.debug("### Object Class Name: {}", objectClassName);
		String[] requiredAttributes = getAttributeNames(objectClassName, ATTRIBUTE_REQUIRED);
		log.debug("### Result: {}", ArrayUtils.toString(requiredAttributes));

		return requiredAttributes;
	}

	public String[] getOptionalAttributes(String objectClassName)
	{
		log.debug("### Object Class Name: {}", objectClassName);
		String[] optionalAttributes = getAttributeNames(objectClassName, ATTRIBUTE_OPTIONAL);
		log.debug("### Result: {}", ArrayUtils.toString(optionalAttributes));

		return optionalAttributes;
	}

	public String[] getAllAttributes(String objectClassName)
	{
		log.debug("### Object Class Name: {}", objectClassName);
		String[] attributes = getAttributeNames(objectClassName, ATTRIBUTE_ALL);
		log.debug("### Result: {}", ArrayUtils.toString(attributes));

		return attributes;
	}

	private void releaseResource(LDAPConnection ld)
	{
		try {
			ldapPool.releaseConnection(ld);
		}
		catch (Exception e) {
			log.error("### LdapQueryExecutor releaseResource() Exception: {}", e.getMessage());

			throw new RuntimeException(e);
		}
	}

	/**
	 * 값 매핑이 필요한 문자열에 값을 매핑한다. 예 : (&amp;(objectclass=#objectclass#)(cn=#cn#)) => (&amp;(objectclass=eamappl)(cn=APPL000005)) parameterObject는 맵 계열
	 * 객체나 Bean 유형의 객체여야 함. 맵을 경우 parameterObject.get("objectclass"), parameterObject.get("cn")으로 값을 가져올 수 있어야 함. Bean일 경우
	 * parameterObject.getObjectclass(), parameterObject.getCn() 과 같은 메서드가 정의되어 있어야 함.
	 *
	 * @param origin
	 *            값 매핑이 필요한 문자열
	 * @param parameterObject
	 *            매핑할 값이 있는 객체
	 * @return 값이 매핑된 문자열을 리턴한다.
	 * @author 주정민
	 * @create-date 2009. 3. 19.
	 */
	private String mappingParameterValues(String origin, Object parameterObject)
	{
		Map parameterMap = null;
		String resultString = origin;

		if (origin != null && parameterObject != null) {
			if (parameterObject instanceof String || parameterObject instanceof Number) {
				resultString = changeAllParameter(origin, parameterObject);
			}
			else {
				parameterMap = changeToMap(parameterObject);

				StrSubstitutor strSubstitutor = new StrSubstitutor(parameterMap, "#", "#");
				resultString = strSubstitutor.replace(origin);
			}
		}

		return resultString;
	}

	private String changeAllParameter(String origin, Object parameterObject)
	{
		int startIndex = -1;
		int endIndex = 0;
		StringBuffer originString = new StringBuffer(origin);

		while ((startIndex = originString.indexOf("#", endIndex + 1)) > -1) {
			endIndex = originString.indexOf("#", startIndex + 1);
			originString.replace(startIndex, endIndex + 1, parameterObject.toString());
		}

		return originString.toString();
	}

	private Map convertEntryIntoMap(LdapQuery ldapQuery, LDAPEntry entry)
	{
		Map resultMap = null;

		if (entry != null) {
			resultMap = new HashMap();
			//resultMap.put("dn", entry.getDN());

			Enumeration enumeration = entry.getAttributeSet().getAttributes();

			while (enumeration.hasMoreElements()) {
				LDAPAttribute attribute = (LDAPAttribute) enumeration.nextElement();
				String attributeName = ldapQuery.getAliasOfAttribute(attribute.getName());
				String[] attributeValues = attribute.getStringValueArray();

				if (attributeValues.length == 1) {
					resultMap.put(attributeName, attributeValues[0]);
				}
				else {
					resultMap.put(attributeName, Arrays.asList(attributeValues));
				}
			}

			// 기본값 설정
			List attributeList = ldapQuery.getAttributeList();

			for (int i = 0, limit = attributeList.size(); i < limit; i++) {
				LdapQueryAttribute attribute = (LdapQueryAttribute) attributeList.get(i);

				if (!resultMap.containsKey(attribute.getAttributeName()) && !resultMap.containsKey(attribute.getAliasName())) {
					// 조회된 결과가 없으므로 기본값을 설정한다.
					if (attribute.getDefaultValue() != null) {
						resultMap.put(ldapQuery.getAliasOfAttribute(attribute.getAttributeName()), attribute.getDefaultValue());
					}
				}
			}
		}
		else {
			resultMap = Collections.EMPTY_MAP;
		}

		return resultMap;
	}

	private Object getBean(String clazz) throws Exception
	{
		return Class.forName(clazz).newInstance();
	}
}