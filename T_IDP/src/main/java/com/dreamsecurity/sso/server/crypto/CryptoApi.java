package com.dreamsecurity.sso.server.crypto;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.LinkedList;

import com.dreamsecurity.jcaos.cms.SignedData;
import com.dreamsecurity.jcaos.x509.X509Certificate;
import com.dreamsecurity.sso.server.api.audit.vo.AuditVO;

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

	public KeyPair genKeyPair(String algorithm, int keyLen, String curvedName) throws CryptoApiException;

	public X509Certificate generatePublic(KeyPair serverPair, X509Certificate caCert, PrivateKey caPrivate, String cnName, String useType, int period) throws CryptoApiException;

	public byte[] generatePrivate(PrivateKey priKey, byte[] key) throws CryptoApiException;

	public String encryptByDEK(String input) throws CryptoApiException;

	public byte[] decryptByDEK(String input) throws CryptoApiException;

	public byte[] encrypt(byte[] key, byte[] iv, byte[] input, String algorithm, String cipherAlgorithm) throws CryptoApiException;

	public byte[] decrypt(byte[] key, byte[] iv, byte[] input, String algorithm, String cipherAlgorithm) throws CryptoApiException;

	public byte[] encrypt(byte[] key, byte[] input, String algorithm, String cipherAlgorithm) throws CryptoApiException;

	public byte[] decrypt(byte[] key, byte[] input, String algorithm, String cipherAlgorithm) throws CryptoApiException;

	public byte[] encryptPrivateKey(byte[] key, byte[] input, String algorithm) throws CryptoApiException;

	public byte[] decryptPrivateKey(byte[] key, byte[] input, String algorithm) throws CryptoApiException;

	public byte[] encryptPublicKey(byte[] key, byte[] input, String algorithm) throws CryptoApiException;

	public byte[] encryptPublicKey(PublicKey pubKey, byte[] input, String algorithm) throws CryptoApiException;

	public byte[] decryptPublicKey(byte[] key, byte[] input, String algorithm) throws CryptoApiException;

	public byte[] signature(byte[] key, byte[] input, String algorithm) throws CryptoApiException;

	public void verify(byte[] key, byte[] signature, byte[] input, String algorithm) throws CryptoApiException;

	public byte[] signature(PrivateKey priKey, byte[] input, String algorithm) throws CryptoApiException;

	public void verify(PublicKey pubKey, byte[] signature, byte[] input, String algorithm) throws CryptoApiException;

	public byte[] generateSignedEnvelopedData(byte[] enccert, byte[] signcert, byte[] privatekey, byte[] input) throws CryptoApiException;

	public byte[] processSignedEnvelopedData(byte[] verifycert, byte[] privatekey, byte[] input) throws CryptoApiException;

	public SignedData processSignedData(byte[] input) throws CryptoApiException;

	public SSOSecretKey generateSecretKey(String algorithm, String randomAlgorithm) throws CryptoApiException;
}