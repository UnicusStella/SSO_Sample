package com.dreamsecurity.sso.agent.client;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.Reader;
import java.util.ArrayList;
import java.util.List;

import com.dreamsecurity.sso.agent.config.SSOConfig;
import com.dreamsecurity.sso.lib.jsn.JSONArray;
import com.dreamsecurity.sso.lib.jsn.JSONObject;
import com.dreamsecurity.sso.lib.jsn.parser.JSONParser;

public class ClientRepository
{
	private static ClientRepository instance = null;

	private ClientModel clientModel = new ClientModel();
	private long loadedtime = 0;

	private ClientRepository()
	{
	}

	public static ClientRepository getInstance()
	{
		try {
			if (instance == null) {
				synchronized (ClientRepository.class) {
					if (instance == null) {
						instance = new ClientRepository();
					}
				}
			}
		}
		catch (Exception e) {
			return null;
		}

		SSOConfig config = SSOConfig.getInstance();
		String oidcConfigPath = (String) config.getProperty("oidc.setting");
		oidcConfigPath = config.getHomePath(oidcConfigPath);

		loadClient(oidcConfigPath);

		return instance;
	}

	public static boolean loadClient(String path)
	{
		try {
			File file = new File(path);

			if (instance.loadedtime >= file.lastModified()) {
				return true;
			}

			synchronized (instance) {
				JSONParser parser = new JSONParser();
				Reader reader = null;

				try {
					reader = new FileReader(path);
				}
				catch (FileNotFoundException e) {
					e.printStackTrace();
				}

				JSONObject jsonObject = null;
				jsonObject = (JSONObject) parser.parse(reader);

				JSONArray scopesJsonArray = new JSONArray();
				JSONArray redirectUrisJsonArray = new JSONArray();

				List<Object> scopes = new ArrayList<Object>();
				List<Object> redirecturis = new ArrayList<Object>();

				String clientId = (String) jsonObject.get("clientId");
				String protocol = (String) jsonObject.get("protocol");
				String secret = (String) jsonObject.get("secret");
				String responseType = (String) jsonObject.get("responseType");
				String grantType = (String) jsonObject.get("grantType");
				String nonceEnabled = (String) jsonObject.get("nonceEnabled").toString();
				String pkceEnabled = (String) jsonObject.get("pkceEnabled").toString();
				String refreshTokenEnabled = (String) jsonObject.get("refreshTokenEnabled").toString();
				String authEndpoint = (String) jsonObject.get("authEndpoint");
				String tokenEndpoint = (String) jsonObject.get("tokenEndpoint");
				String logoutEndpoint = (String) jsonObject.get("logoutEndpoint");
				String introspectEndpoint = (String) jsonObject.get("introspectEndpoint");
				String userinfoEndpoint = (String) jsonObject.get("userinfoEndpoint");
				String publicKey = (String) jsonObject.get("publicKey");
				String issuer = (String) jsonObject.get("issuer");

				scopesJsonArray = (JSONArray) jsonObject.get("scopes");
				redirectUrisJsonArray = (JSONArray) jsonObject.get("redirectUris");

				for (int i = 0; i < scopesJsonArray.size(); i++) {
					scopes.add(scopesJsonArray.get(i));
				}

				for (int i = 0; i < redirectUrisJsonArray.size(); i++) {
					redirecturis.add(redirectUrisJsonArray.get(i));
				}

				instance.clientModel.setId(clientId);
				instance.clientModel.setProtocol(protocol);
				instance.clientModel.setSecret(secret);
				instance.clientModel.setResponseType(responseType);
				instance.clientModel.setGrantType(grantType);
				instance.clientModel.setNonce(nonceEnabled);
				instance.clientModel.setPkce(pkceEnabled);
				instance.clientModel.setRefreshTokenUse(refreshTokenEnabled);
				instance.clientModel.setAuthEndpoint(authEndpoint);
				instance.clientModel.setTokenEndpoint(tokenEndpoint);
				instance.clientModel.setIntrospectEndpoint(introspectEndpoint);
				instance.clientModel.setUserinfoEndpoint(userinfoEndpoint);
				instance.clientModel.setLogoutEndpoint(logoutEndpoint);
				instance.clientModel.setRedirecturis(redirecturis);
				instance.clientModel.setScopes(scopes);
				instance.clientModel.setServerCert(publicKey);
				instance.clientModel.setIssuer(issuer);

				instance.loadedtime = System.currentTimeMillis();
			}
		}
		catch (Exception e) {
			e.printStackTrace();
		}

		return false;
	}

	public ClientModel getClientModel()
	{
		return clientModel;
	}
}