package com.dreamsecurity.sso.server.client;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import com.dreamsecurity.sso.server.api.admin.AdminController;
import com.dreamsecurity.sso.server.api.admin.vo.ClientVO;
import com.dreamsecurity.sso.server.ha.SyncEvent;

public class ClientRepository
{
	private static ClientRepository instance = null;

	private boolean loaded = false;
	private Map<String, ClientModel> clientEntities = new HashMap<String, ClientModel>();

	public static final int EVENT_OIDC_CLIENT_RELOAD = 12;

	private ClientRepository()
	{
		loadClient();
	}

	public static ClientRepository getInstance()
	{
		if (instance == null) {
			synchronized (ClientRepository.class) {
				if (instance == null) {
					instance = new ClientRepository();
				}
			}
		}
		return instance;
	}

	public void loadClient()
	{
		synchronized (ClientRepository.class) {
			if (loaded) {
				clientEntities.clear();
			}

			AdminController adminApi = new AdminController();
			List<Object> clientList = adminApi.listClientInfo();

			if (clientList == null) {
				loaded = false;
				return;
			}

			for (int i = 0; i < clientList.size(); i++) {
				ClientModel clientModel = new ClientModel();
				ClientVO clientVO = (ClientVO) clientList.get(i);

				clientModel.setClientInfo(clientVO);

				List<Object> redirecturis = adminApi.listClientRedirect(clientVO.getId());
				clientModel.setRedirecturis(redirecturis);

				List<Object> scopes = adminApi.listClientScope(clientVO.getId());
				clientModel.setScopes(scopes);

				clientEntities.put(clientVO.getId(), clientModel);
			}

			loaded = true;
		}
		return;
	}

	public boolean addClient(String id, String name, String protocol, String enabled, String secret, String nonce,
			String pkce, String refreshUse, String codeLifespan, String tokenLifespan, String refreshLifespan,
			String responseType, String grantType, String[] redirectUriList, String []scopeList)
	{
		if (this.clientEntities.containsKey(id)) {
			this.clientEntities.remove(id);
		}

		ClientModel clientModel = new ClientModel();
		ClientVO clientVO = new ClientVO();
		clientVO.setId(id);
		clientVO.setName(name);
		clientVO.setProtocol(protocol);
		clientVO.setEnabled(enabled);
		clientVO.setSecret(secret);
		clientVO.setResponseType(responseType);
		clientVO.setGrantType(grantType);
		clientVO.setNonce(nonce);
		clientVO.setPkce(pkce);
		clientVO.setRefreshTokenUse(refreshUse);
		clientVO.setCodeLifespan(codeLifespan);
		clientVO.setTokenLifespan(tokenLifespan);
		clientVO.setRefreshTokenLifespan(refreshLifespan);

		clientModel.setClientInfo(clientVO);

		List<Object> scopes = new ArrayList<Object>();
		List<Object> redirecturis = new ArrayList<Object>();

		for (int i = 0; i < scopeList.length; i++) {
			scopes.add(scopeList[i]);
		}

		for (int i = 0; i < redirectUriList.length; i++) {
			redirecturis.add(redirectUriList[i]);
		}

		clientModel.setScopes(scopes);
		clientModel.setRedirecturis(redirecturis);

		clientEntities.put(clientVO.getId(), clientModel);
		return true;
	}

	public boolean removeClient(String id)
	{
		if (this.clientEntities.containsKey(id)) {
			this.clientEntities.remove(id);
		}

		return true;
	}

	public ClientModel getClient(String id)
	{
		ClientModel clientModel = null;
		clientModel = clientEntities.get(id);
		return clientModel;
	}

	public void applyEvents(SyncEvent event)
	{
		if (event == null) {
			return;
		}

		switch (event.getEventid()) {
		case EVENT_OIDC_CLIENT_RELOAD:
			instance.loadClient();
			return;
		}
	}
}