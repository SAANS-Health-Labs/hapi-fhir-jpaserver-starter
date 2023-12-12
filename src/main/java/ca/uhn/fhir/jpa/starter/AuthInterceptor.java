package ca.uhn.fhir.jpa.starter;

import ca.uhn.fhir.interceptor.api.Pointcut;
import ca.uhn.fhir.rest.server.exceptions.AuthenticationException;
import ca.uhn.fhir.rest.server.interceptor.auth.AuthorizationInterceptor;
import ca.uhn.fhir.rest.api.server.RequestDetails;
import ca.uhn.fhir.rest.server.interceptor.auth.PolicyEnum;
import io.micrometer.core.instrument.util.StringUtils;
import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import org.springframework.stereotype.Component;

import java.util.Date;
import org.springframework.core.env.ConfigurableEnvironment;

@Component
public class AuthInterceptor extends AuthorizationInterceptor {

	private final ConfigurableEnvironment environment;

	public AuthInterceptor(ConfigurableEnvironment environment){
		super();
		this.environment = environment;
		this.setDefaultPolicy(PolicyEnum.ALLOW);
	}
	private static final org.slf4j.Logger ourLog = org.slf4j.LoggerFactory.getLogger(BaseJpaRestfulServer.class);
	@Override
	public void incomingRequestPreHandled(RequestDetails theRequest, Pointcut thePointcut) {
		if (!isAuthenticated(theRequest)) {
			throw new AuthenticationException("Authentication failed");
		}
    }

	private boolean isAuthenticated(RequestDetails theRequestDetails) {
		String authorizationHeader = theRequestDetails.getHeader("Authorization");
		return StringUtils.isNotBlank(authorizationHeader) && isValidToken(authorizationHeader);
	}

	private boolean isValidToken(String authorizationHeader) {
		try {
			String secret = EnvironmentHelper.getEncryptionSecret(environment);
			String issuer = EnvironmentHelper.getEncryptionIssuer(environment);
			Algorithm algorithm = Algorithm.HMAC256(secret);
			DecodedJWT decodedJWT = JWT.require(algorithm)
				.withIssuer(issuer)
				.build()
				.verify(authorizationHeader);
			if (decodedJWT.getExpiresAt() != null && decodedJWT.getExpiresAt().before(new Date())) {
				ourLog.error("Token expired");
				return false;
			}
			return true;

		} catch (Exception e) {
			ourLog.error(String.valueOf(e));
			return false;
		}
	}
}
