package org.apache.client;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManagerFactory;

import org.apache.http.NameValuePair;
import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.config.Registry;
import org.apache.http.config.RegistryBuilder;
import org.apache.http.conn.socket.ConnectionSocketFactory;
import org.apache.http.conn.socket.PlainConnectionSocketFactory;
import org.apache.http.conn.ssl.NoopHostnameVerifier;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.impl.conn.PoolingHttpClientConnectionManager;
import org.apache.http.message.BasicNameValuePair;
import org.apache.nifi.annotation.lifecycle.OnScheduled;
import org.apache.nifi.components.PropertyDescriptor;
import org.apache.nifi.processor.AbstractProcessor;
import org.apache.nifi.processor.ProcessContext;
import org.apache.nifi.processor.ProcessSession;
import org.apache.nifi.processor.exception.ProcessException;
import org.apache.nifi.ssl.SSLContextService;
import org.apache.nifi.ssl.SSLContextService.ClientAuth;

public abstract class AbstractHttpClientProcessor extends AbstractProcessor {

	public static final PropertyDescriptor URL_ENDPOINT = new PropertyDescriptor.Builder().name("URL Endpoint")
			.description("The URL Endpoint for the Https/TLS call").required(true).build();
	public static final PropertyDescriptor PROP_SSL_CONTEXT_SERVICE = new PropertyDescriptor.Builder()
			.name("SSL Context Service")
			.description(
					"The SSL Context Service used to provide client certificate information for TLS/SSL (https) connections."
							+ " It is also used to connect to HTTPS Proxy.")
			.required(true).identifiesControllerService(SSLContextService.class).build();

	private URI endpoint;
	private CloseableHttpClient client;

	@Override
	protected List<PropertyDescriptor> getSupportedPropertyDescriptors() {
		return Arrays.asList(URL_ENDPOINT, PROP_SSL_CONTEXT_SERVICE);
	}

	@OnScheduled
	public void setUpClient(final ProcessContext context) throws KeyManagementException, NoSuchAlgorithmException,
			KeyStoreException, CertificateException, IOException, UnrecoverableKeyException {
		this.endpoint = URI.create(context.getProperty(URL_ENDPOINT).getValue());

		final SSLContextService sslService = context.getProperty(PROP_SSL_CONTEXT_SERVICE)
				.asControllerService(SSLContextService.class);

		final SSLContext sslContext = sslService.createSSLContext(ClientAuth.REQUIRED);

		final KeyManagerFactory keyManagerFactory = KeyManagerFactory
				.getInstance(KeyManagerFactory.getDefaultAlgorithm());
		final TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance("X509");
		// initialize the KeyManager array to null and we will overwrite later if a
		// keystore is loaded
		KeyManager[] keyManagers = null;

		// we will only initialize the keystore if properties have been supplied by the
		// SSLContextService
		if (sslService.isKeyStoreConfigured()) {
			final String keystoreLocation = sslService.getKeyStoreFile();
			final String keystorePass = sslService.getKeyStorePassword();
			final String keystoreType = sslService.getKeyStoreType();

			// prepare the keystore
			final KeyStore keyStore = KeyStore.getInstance(keystoreType);

			try (FileInputStream keyStoreStream = new FileInputStream(keystoreLocation)) {
				keyStore.load(keyStoreStream, keystorePass.toCharArray());
			}

			keyManagerFactory.init(keyStore, keystorePass.toCharArray());
			keyManagers = keyManagerFactory.getKeyManagers();
		}

		// we will only initialize the truststure if properties have been supplied by
		// the SSLContextService
		if (sslService.isTrustStoreConfigured()) {
			// load truststore
			final String truststoreLocation = sslService.getTrustStoreFile();
			final String truststorePass = sslService.getTrustStorePassword();
			final String truststoreType = sslService.getTrustStoreType();

			KeyStore truststore = KeyStore.getInstance(truststoreType);
			truststore.load(new FileInputStream(truststoreLocation), truststorePass.toCharArray());
			trustManagerFactory.init(truststore);
		}

		// if keystore properties were not supplied, the keyManagers array will be null
		sslContext.init(keyManagers, trustManagerFactory.getTrustManagers(), new SecureRandom());

		final SSLSocketFactory sslSocketFactory = sslContext.getSocketFactory();

		SSLConnectionSocketFactory sslConnectionSocketFactory = new SSLConnectionSocketFactory(sslSocketFactory,
				SSLConnectionSocketFactory.getDefaultHostnameVerifier());
		Registry<ConnectionSocketFactory> registry = RegistryBuilder.<ConnectionSocketFactory>create()
				.register("http", PlainConnectionSocketFactory.getSocketFactory())
				.register("https", SSLConnectionSocketFactory.getSocketFactory()).build();
		final PoolingHttpClientConnectionManager clientConnectionManager = new PoolingHttpClientConnectionManager(
				registry);
		clientConnectionManager.setMaxTotal(100);
		clientConnectionManager.setDefaultMaxPerRoute(20);

		this.client = HttpClients.custom().setSSLContext(sslContext)
				.setSSLHostnameVerifier(NoopHostnameVerifier.INSTANCE).setSSLSocketFactory(sslConnectionSocketFactory)
				.setConnectionManager(clientConnectionManager).build();
	}

	@Override
	public void onTrigger(final ProcessContext context, final ProcessSession session) throws ProcessException {
		// Setup request
		HttpPost httpPost = new HttpPost(endpoint);

		// Optional, setup credentials
		// UsernamePasswordCredentials creds = new UsernamePasswordCredentials("John",
		// "pass");
		// httpPost.addHeader(new BasicScheme().authenticate(creds, httpPost, null));

		// Setup Headers
		httpPost.setHeader("Accept", "application/xml");

		// Setup Body
		List<NameValuePair> params = new ArrayList<>();
		params.add(new BasicNameValuePair("username", "John"));
		params.add(new BasicNameValuePair("password", "pass"));
		try {
			httpPost.setEntity(new UrlEncodedFormEntity(params));
		} catch (UnsupportedEncodingException e) {
			throw new ProcessException("Something...", e);
		}

		// Perform request
		try (CloseableHttpResponse response = client.execute(httpPost)) {
			response.getStatusLine().getStatusCode();

		} catch (ClientProtocolException e) {
			throw new ProcessException("Something else...", e);
		} catch (IOException e) {
			throw new ProcessException("Something otherwise...", e);
		}
	}
}
