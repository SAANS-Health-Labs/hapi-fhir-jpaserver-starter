package ca.uhn.fhir.jpa.starter;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.Date;
import org.mindrot.jbcrypt.BCrypt;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.mongodb.client.MongoClient;
import com.mongodb.client.MongoClients;
import com.mongodb.client.MongoCollection;
import com.mongodb.client.MongoDatabase;
import org.bson.Document;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.env.ConfigurableEnvironment;
import org.springframework.stereotype.Component;

@Component
public class AuthServer extends HttpServlet {

	private final ConfigurableEnvironment environment;

	@Autowired
	public AuthServer(ConfigurableEnvironment environment) {
		this.environment = environment;
	}

	@Override
	protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws IOException {

		String mongoDBUri = EnvironmentHelper.getMongoDBUri(environment);

		MongoClient mongoClient = MongoClients.create(mongoDBUri);
		BufferedReader reader = req.getReader();
		StringBuilder requestBody = new StringBuilder();
		String line;
		while ((line = reader.readLine()) != null) {
			requestBody.append(line);
		}
		ObjectMapper objectMapper = new ObjectMapper();
		try {
			JsonNode rootNode = objectMapper.readTree(requestBody.toString());
			String email = rootNode.get("email").asText();
			String password = rootNode.get("password").asText();
			resp.setContentType("application/json");
			PrintWriter out = resp.getWriter();
			try {
				MongoDatabase database = mongoClient.getDatabase("fhir-svc");
				MongoCollection<Document> usersCollection = database.getCollection("users");
				try {
					Document userDoc = usersCollection.find(new Document("email",email)).first();
					if (userDoc != null) {
						String storedPassword = userDoc.getString("password");
						if (BCrypt.checkpw(password, storedPassword)) {
							String token = createToken(email);
							out.println("{ \"status\": \"success\", \"token\": \"" + token + "\" }");
						} else {
							resp.setStatus(HttpServletResponse.SC_BAD_REQUEST);
							resp.getWriter().println("{ \"error\": \"Invalid Password\" }");
						}
					} else {
						resp.setStatus(HttpServletResponse.SC_BAD_REQUEST);
						resp.getWriter().println("{ \"error\": \"User not found\" }");
					}
				}catch (Exception e) {
					e.printStackTrace();
				}
				mongoClient.close();
			} catch (Exception e) {
				resp.setStatus(HttpServletResponse.SC_BAD_REQUEST);
				out.println("{ \"status\": \"error\", \"message\": \"" + e.getMessage() + "\" }");
			}
		} catch (Exception e) {
			resp.setStatus(HttpServletResponse.SC_BAD_REQUEST);
			resp.getWriter().println("{ \"error\": \"Invalid JSON data\" }");
		}
	}

	@Override
	protected void doPut(HttpServletRequest req, HttpServletResponse resp) throws IOException {
		resp.setContentType("application/json");
		PrintWriter out = resp.getWriter();

		try {
			BufferedReader reader = req.getReader();
			StringBuilder requestBody = new StringBuilder();
			String line;
			while ((line = reader.readLine()) != null) {
				requestBody.append(line);
			}

			ObjectMapper objectMapper = new ObjectMapper();
			JsonNode rootNode = objectMapper.readTree(requestBody.toString());

			String username = rootNode.get("username").asText();
			String password = rootNode.get("password").asText();
			String email = rootNode.get("email").asText();

			String mongoDBUri = EnvironmentHelper.getMongoDBUri(environment);

			MongoClient mongoClient = MongoClients.create(mongoDBUri);
			MongoDatabase database = mongoClient.getDatabase("fhir-svc");
			MongoCollection<Document> usersCollection = database.getCollection("users");

			// Check if the username already exists in the database
			Document existingUser = usersCollection.find(new Document("email", email)).first();

			if (existingUser == null) {
				// Hash the password before storing it in the database
				String hashedPassword = BCrypt.hashpw(password, BCrypt.gensalt());

				Document newUser = new Document("email", email)
					.append("password", hashedPassword).append("username",username);

				usersCollection.insertOne(newUser);

				out.println("{ \"status\": \"success\", \"message\": \"User registered successfully\" }");
			} else {
				resp.setStatus(HttpServletResponse.SC_BAD_REQUEST);
				resp.getWriter().println("{ \"error\": \"Username already exists\" }");
			}

			mongoClient.close();
		} catch (Exception e) {
			resp.setStatus(HttpServletResponse.SC_BAD_REQUEST);
			out.println("{ \"status\": \"error\", \"message\": \"" + e.getMessage() + "\" }");
		}
	}
	private String createToken(String username) {
		String secret = EnvironmentHelper.getEncryptionSecret(environment);
		String issuer = EnvironmentHelper.getEncryptionIssuer(environment);
		Algorithm algorithm = Algorithm.HMAC256(secret);
        return JWT.create()
			.withSubject(username)
			.withIssuer(issuer)
			.withExpiresAt(new Date(System.currentTimeMillis() + 3600000))
			.sign(algorithm);
	}
}
