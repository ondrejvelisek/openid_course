package oidc_rp;

import static spark.Spark.exception;
import static spark.Spark.get;
import static spark.Spark.port;

import java.io.IOException;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.text.MessageFormat;

import com.nimbusds.jwt.JWT;
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.SerializeException;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;

/**
 * Skeleton code for building an OpenID Connect Public Client.
 *
 * Using the Spark (http://sparkjava.com/) as the webserver, and Nimbus OAauth
 * (http://connect2id.com/products/nimbus-oauth-openid-connect-sdk) for OpenID
 * Connect support.
 *
 * @author Rebecka Gulliksson, rebecka.gulliksson@umu.se
 * @author Ondrej Velisek, ondrejvelisek@gmail.com
 *
 */
public class WebServer {

	/**
	 * Which port (on localhost) the RP listens to for the redirect URI.
	 */
	public static int SERVER_PORT = 8090;

	public static void main(String[] args) throws ParseException, IOException,
			URISyntaxException, SerializeException {
		Client client = new Client();

		/*** webserver setup ***/
		port(SERVER_PORT);

		/*** webserver routes ***/
		get("/", (req, res) -> readFromFile("index.html"));

		get("/authenticate", client::authenticate);

		/*
		 * where the authentication response from the provider is received
		 */
		get("/callback", client::callback);

		/* default handling if a requested file can not be found */
		exception(IOException.class, (e, request, response) -> {
			response.status(404);
			response.body("Resource not found: " + e);
		});
	}

	/**
	 * Build HTML summary of a successful authentication flow.
	 *
	 * @param authCode
	 *            authorization code obtained from authentication response
	 * @param accessToken
	 *            response to the token request
	 * @param idToken
	 *            claims from the id token
	 * @param userInfo
	 *            response to the user info request
	 * @return response containing HTML formatted summary.
	 */
	public static String successPage(
			AuthorizationCode authCode,
			AccessToken accessToken,
			JWT idToken,
			UserInfo userInfo
	) throws IOException, java.text.ParseException {

		StringBuilder idTokenString = new StringBuilder();
		idTokenString.append(idToken.getJWTClaimsSet().toJSONObject().toJSONString());
		idTokenString.append("\n\n");
		idTokenString.append(idToken.getParsedString());

		String userInfoString = userInfo.toJSONObject().toJSONString();

		String successPage = readFromFile("success_page.html");
		return MessageFormat.format(successPage, authCode, accessToken,
				idTokenString, userInfoString);
	}

	/**
	 * Read all data from a file.
	 *
	 * @param path path of the file
	 * @return All data from the file.
	 * @throws IOException
	 */
	public static String readFromFile(String path) throws IOException {
		return new String(Files.readAllBytes(Paths.get(".").resolve(Paths
				.get(path))), StandardCharsets.UTF_8);
	}
}
