package com.dreamsecurity.sso.agent.crypto;

import java.util.LinkedList;

import com.dreamsecurity.jcaos.x509.X509Certificate;
import com.dreamsecurity.sso.agent.api.AuditVO;

public interface CryptoApi
{
	public int init(LinkedList<AuditVO> auditList);

	public void clearKey();

	public String getProviderName();

	public int getStatus();

	public byte[] getRandom(int size, String algorithm) throws CryptoApiException;

	public byte[] digest(byte[] input, String algorithm) throws CryptoApiException;

	public byte[] hmac(byte[] key, byte[] input, String algorithm) throws CryptoApiException;

	public byte[] hmacByDEK(byte[] input, String algorithm) throws CryptoApiException;

	public String decryptByDEK(String input) throws CryptoApiException;

	public byte[] encrypt(byte[] key, byte[] iv, byte[] input, String algorithm, String cipherAlgorithm) throws CryptoApiException;

	public byte[] decrypt(byte[] key, byte[] iv, byte[] input, String algorithm, String cipherAlgorithm) throws CryptoApiException;

	public byte[] encrypt(byte[] key, byte[] input, String algorithm, String cipherAlgorithm) throws CryptoApiException;

	public byte[] decrypt(byte[] key, byte[] input, String algorithm, String cipherAlgorithm) throws CryptoApiException;

	public byte[] encryptPrivateKey(byte[] key, byte[] input, String algorithm) throws CryptoApiException;

	public byte[] decryptPrivateKey(byte[] key, byte[] input, String algorithm) throws CryptoApiException;

	public byte[] encryptPublicKey(byte[] key, byte[] input, String algorithm) throws CryptoApiException;

	public byte[] decryptPublicKey(byte[] key, byte[] input, String algorithm) throws CryptoApiException;

	public byte[] signature(byte[] key, byte[] input, String algorithm) throws CryptoApiException;

	public void verify(byte[] key, byte[] signature, byte[] input, String algorithm) throws CryptoApiException;

	public byte[] generateSignedEnvelopedData(byte[] enckey, byte[] signkey, byte[] privatekey, byte[] input) throws CryptoApiException;

	public byte[] processSignedEnvelopedData(byte[] verifykey, byte[] privatekey, byte[] input) throws CryptoApiException;

	public SSOSecretKey generateSecretKey(String algorithm, String randomAlgorithm) throws CryptoApiException;
}