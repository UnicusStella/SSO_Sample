package com.dreamsecurity.sso.server.repository.ldap.pool;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;

import netscape.ldap.LDAPConnection;
import netscape.ldap.LDAPException;
import netscape.ldap.LDAPSearchConstraints;

import com.dreamsecurity.sso.lib.cpl.PoolableObjectFactory;
import com.dreamsecurity.sso.lib.slf.Logger;
import com.dreamsecurity.sso.lib.slf.LoggerFactory;
import com.dreamsecurity.sso.server.crypto.CryptoApiException;
import com.dreamsecurity.sso.server.crypto.SSOCryptoApi;

public class LdapConnectionFactory implements PoolableObjectFactory
{
	private static Logger log = LoggerFactory.getLogger(LdapConnectionFactory.class);

	private String host = null;
	private int port = 0;
	private String authId = null;
	private String authPassword = null;

	public LdapConnectionFactory()
	{
	}

	public LdapConnectionFactory(String host, int port, String authId, String authPassword)
	{
		this.host = host;
		this.port = port;
		this.authId = authId;
		this.authPassword = authPassword;
	}

	public String getHost()
	{
		return host;
	}

	public void setHost(String host)
	{
		this.host = host;
	}

	public int getPort()
	{
		return port;
	}

	public void setPort(int port)
	{
		this.port = port;
	}

	public String getAuthId() throws CryptoApiException
	{
		return new String(SSOCryptoApi.getInstance().decryptSym(authId));
	}

	public void setAuthId(String authId)
	{
		this.authId = authId;
	}

	public String getAuthPassword() throws CryptoApiException
	{
		return new String(SSOCryptoApi.getInstance().decryptSym(authPassword));
	}

	public void setAuthPassword(String authPassword)
	{
		this.authPassword = authPassword;
	}

	public void activateObject(Object connection) throws Exception
	{
		log.debug("### LDAP activateObject: {} ({})", connection, connection.hashCode());
	}

	public void destroyObject(Object connection) throws Exception
	{
		if (connection == null) {
			return;
		}

		log.debug("### LDAP activateObject: {} ({})", connection, connection.hashCode());

		if (connection instanceof LDAPConnection) {
			LDAPConnection conn = (LDAPConnection) connection;

			if (conn.isConnected()) {
				try {
					conn.disconnect();
				}
				catch (LDAPException e) {
					log.error("### LDAP disconnect() Exception: {}", e.getMessage());
				}
			}
		}
	}

	public Object makeObject() throws Exception
	{
		LDAPConnection ld = new LDAPConnection();

		try {
			if (!socConnectionTest())
				throw new Exception(new StringBuffer(" LDAP Server connection FAIL. ( ").append(getHost()).append(" : ").append(getPort())
						.append(" )").toString());
			ld.connect(3, getHost(), getPort(), getAuthId(), getAuthPassword());
			LDAPSearchConstraints conns = ld.getSearchConstraints();

			conns.setBatchSize(0);
			conns.setMaxResults(10000);

			ld.setSearchConstraints(conns);
			// BizRepositoryPoolCherokySupport.setModtime(BizRepositoryPoolCherokySupport.getLastFilemodtime());
		}
		catch (LDAPException le) {
			log.error("### LDAP makeObject() LDAPException: {}", le.getMessage());
		}
		catch (Exception e) {
			log.error("### LDAP makeObject() Exception: {}", e.getMessage());
		}

		log.debug("### LDAP makeObject: {} ({})", ld, ld.hashCode());

		return ld;
	}

	public boolean socConnectionTest()
	{
		Socket socket = null;
		try {
			log.info(new StringBuffer("### LDAP Server Socket Connetion Test ").append(getHost()).append(" : ").append(getPort()).toString());

			InetSocketAddress isd = new InetSocketAddress(getHost(), getPort());
			socket = new Socket();
			socket.connect(isd, 4000);

			log.info("### LDAP Server connection check SUCCESS ");
			return true;
		}
		catch (IOException e) {
			log.error("### LDAP socConnectionTest() IOException: {}", e.getMessage());
			return false;
		}
		finally {
			try {
				socket.close();
				socket = null;
			}
			catch (IOException e) {
			}
		}

	}

	public void passivateObject(Object connection) throws Exception
	{
		//log.debug("### LDAP passivateObject: {} ({})", connection, connection.hashCode());
	}

	public boolean validateObject(Object connection)
	{
		log.debug("### LDAP validateObject: {} ({})", connection, connection.hashCode());

		return ((LDAPConnection) connection).isConnected();
	}
}