package oidc_rp;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.AuthorizationCodeGrant;
import com.nimbusds.oauth2.sdk.GeneralException;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.SerializeException;
import com.nimbusds.oauth2.sdk.TokenRequest;
import com.nimbusds.oauth2.sdk.auth.ClientSecretBasic;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.AuthenticationResponseParser;
import com.nimbusds.openid.connect.sdk.AuthenticationSuccessResponse;
import com.nimbusds.openid.connect.sdk.Nonce;
import com.nimbusds.openid.connect.sdk.OIDCTokenResponse;
import com.nimbusds.openid.connect.sdk.SubjectType;
import com.nimbusds.openid.connect.sdk.UserInfoRequest;
import com.nimbusds.openid.connect.sdk.UserInfoSuccessResponse;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata;
import spark.Request;
import spark.Response;
import spark.Session;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.Arrays;
import java.util.Date;

/**
 *
 * @author Rebecka Gulliksson, rebecka.gulliksson@umu.se
 * @author Ondrej Velisek, ondrejvelisek@gmail.com
 */
public class Client {

	private ClientID clientID;
	private Secret clientSecret;
	private URI clientRedirectionURI;
	private Scope requestedScopes;
	private OIDCProviderMetadata providerMetadata;

	public Client()
			throws ParseException, URISyntaxException, IOException,
			SerializeException {

		// TODO set client registered information

		clientID = new ClientID("client");
		clientSecret = new Secret("secret");
		clientRedirectionURI = new URI("http://sp.example.org:8090/callback");

		requestedScopes = new Scope("openid", "profile", "email");

		// TODO set provider configuration

		providerMetadata = new OIDCProviderMetadata(
				new Issuer("https://perun.elixir-czech.cz/oidc/"),
				Arrays.asList(SubjectType.PUBLIC),
				new URI("https://perun.elixir-czech.cz/oidc/jwk")
		);
		providerMetadata.setAuthorizationEndpointURI(new URI("https://perun.elixir-czech.cz/oidc/authorize"));
		providerMetadata.setTokenEndpointURI(new URI("https://perun.elixir-czech.cz/oidc/token"));
		providerMetadata.setUserInfoEndpointURI(new URI("https://perun.elixir-czech.cz/oauth/rpc/json/oidcManager/userinfo"));


	}

	public String authenticate(Request req, Response res)
			throws URISyntaxException, SerializeException {
		// session object that can be used to store state between requests
		Session session = req.session();

		// TODO make authentication request

		State state = new State(); /* Generate random string securely */
		Nonce nonce = new Nonce(); /* Generate random string securely */

		AuthenticationRequest authReq = new AuthenticationRequest.Builder(
				new ResponseType("code"), /* Response type, defines which flow to use */
				requestedScopes, /* Requested scopes, defines which user claims you want to receive */
				clientID, /* Client ID, defines which client ELIXIR AAI will use */
				clientRedirectionURI  /* Redirect URI, defines callback where ELIXIR AAI will send the user after authentication */
		)
				.endpointURI(providerMetadata.getAuthorizationEndpointURI()) /* Authorization endpoint, where user will be redirected to authenticate */
				.state(state) /* State, has to match before and after user authenticates on ELIXIR AAI */
				.nonce(nonce) /* Nonce, has to match before and user authenticates with value in received ID Token */
				.build();

		// TODO save state and nonce for security reasons. (Replay/CSRF attacks)

		/* store object to session, can be obtained by req.session().attribute("attribute name") */
		session.attribute("state", state);
		session.attribute("nonce", nonce);

		res.redirect(authReq.toURI().toString());
		return null;
	}

	public String callback(Request req, Response res)
			throws IOException {
		// Authorization/Authentication response
		String url = req.url() + "?" + req.raw().getQueryString();

		try {

			// TODO parse authentication response from url

			AuthenticationSuccessResponse authRes;
			authRes = (AuthenticationSuccessResponse) AuthenticationResponseParser.parse(new URI(url));

			AuthorizationCode authCode = authRes.getAuthorizationCode();

			// TODO validate the 'state' parameter
			/*
			Use  authRes.getState()  and  req.session().attribute("Attribute name")
			Do not forget to use  Object::equals(Object object)  to properly check equality in Java
			*/
			if (!authRes.getState().equals(req.session().attribute("state"))) {
				throw new SecurityException("State does not equal. Possible attack.");
			}

			// TODO make token request

			TokenRequest tokenReq = new TokenRequest(
					null, /* Token endpoint URI, where ELIXIR AAI authenticates your client */
					new ClientSecretBasic(null, null), /* Client ID, Client Secret */
					new AuthorizationCodeGrant(null, null) /* Authorization code, your client redirect URI */
			);

			OIDCTokenResponse tokenRes = OIDCTokenResponse.parse(tokenReq.toHTTPRequest().send());

			// TODO validate the ID Token according to the OpenID Connect spec (sec 3.1.3.7.)

			SignedJWT idToken = (SignedJWT) tokenRes.getOIDCTokens().getIDToken();

			/*
			use prepared  validateIDToken(ID Token, Provider Metadata, Client ID, Nonce)  method to validate ID Token
			Check the method itself
			Obtain Nonce from session
			*/
			validateIDToken(null, null, null, null);

			BearerAccessToken accessToken = (BearerAccessToken) tokenRes.getOIDCTokens().getAccessToken();

			// TODO make userinfo request

			UserInfoRequest userInfoReq = new UserInfoRequest(
					null, /* ELIXIR AAI User info endpoint URL, where your client can obtain current user claims */
					null /* Access token, used by ELIXIR AAI to authorize client */
			);
			UserInfoSuccessResponse userInfoRes = UserInfoSuccessResponse.parse(userInfoReq.toHTTPRequest().send());

			UserInfo userInfo = userInfoRes.getUserInfo();

			// Print html page with obtained values
			return WebServer.successPage(authCode, accessToken, idToken, userInfo);

		} catch (URISyntaxException | java.text.ParseException | JOSEException | GeneralException e) {
			e.printStackTrace();
			return e.toString();
		}

	}



	public void validateIDToken(SignedJWT idToken, OIDCProviderMetadata providerMetadata, ClientID clientID, Nonce nonce) throws IOException, java.text.ParseException, JOSEException, GeneralException {

		// This is not full secure implementation of section ID Token validation of OIDC specification. Do not use it in production.

		JWKSet keySet = JWKSet.load(providerMetadata.getJWKSetURI().toURL());
		RSAKey key = (RSAKey) keySet.getKeyByKeyId("rsa1");
		idToken.verify(new RSASSAVerifier(key));

		if (!providerMetadata.getIssuer().getValue().equals(idToken.getJWTClaimsSet().getIssuer())) {
			throw new GeneralException("invalid ID Token. Issuer mismatch.");
		}

		if (!clientID.getValue().equals(idToken.getJWTClaimsSet().getAudience().get(0))) {
			throw new GeneralException("invalid ID Token. Client ID mismatch.");
		}

		if (!nonce.getValue().equals(idToken.getJWTClaimsSet().getStringClaim("nonce"))) {
			// TODO not sending by ELIXIR AAI
			//throw new GeneralException("invalid ID Token. Nonce mismatch. Possible attack.");
		}

		if (idToken.getJWTClaimsSet().getExpirationTime().before(new Date())) {
			throw new GeneralException("invalid ID Token. Token expired.");
		}

		if (Math.abs(idToken.getJWTClaimsSet().getIssueTime().compareTo(new Date())) > 60000) {
			throw new GeneralException("invalid ID Token. Issued date Too far from now.");
		}

	}

}
