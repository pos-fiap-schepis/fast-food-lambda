package fastfood;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.logging.Logger;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import software.amazon.awssdk.services.cognitoidentityprovider.CognitoIdentityProviderClient;
import software.amazon.awssdk.services.cognitoidentityprovider.model.AdminConfirmSignUpRequest;
import software.amazon.awssdk.services.cognitoidentityprovider.model.AdminCreateUserRequest;
import software.amazon.awssdk.services.cognitoidentityprovider.model.AdminCreateUserResponse;
import software.amazon.awssdk.services.cognitoidentityprovider.model.AdminGetUserRequest;
import software.amazon.awssdk.services.cognitoidentityprovider.model.AdminGetUserResponse;
import software.amazon.awssdk.services.cognitoidentityprovider.model.AdminInitiateAuthRequest;
import software.amazon.awssdk.services.cognitoidentityprovider.model.AdminInitiateAuthResponse;
import software.amazon.awssdk.services.cognitoidentityprovider.model.AuthFlowType;
import software.amazon.awssdk.services.cognitoidentityprovider.model.ChallengeNameType;
import software.amazon.awssdk.services.cognitoidentityprovider.model.RespondToAuthChallengeRequest;
import software.amazon.awssdk.services.cognitoidentityprovider.model.UserNotFoundException;

/**
 * Handler for requests to Lambda function.
 */
public class App implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    String userPoolId =  System.getenv("userPoolId");
    String appClientId = System.getenv("appClientId");

    String clientSecret = System.getenv("clientSecret");

    String defaultUser = System.getenv("defaultUser");
    String defaultPassword = System.getenv("defaultPassword");

    Logger logger = Logger.getLogger(App.class.getName());

    public APIGatewayProxyResponseEvent handleRequest(final APIGatewayProxyRequestEvent input, final Context context) {
        Map<String, String> headers = new HashMap<>();
        headers.put("Content-Type", "application/json");
        headers.put("X-Custom-Header", "application/json");
        APIGatewayProxyResponseEvent response = new APIGatewayProxyResponseEvent()
                .withHeaders(headers);

        Map<String, String> queryStringParameters = input.getQueryStringParameters();

        if (queryStringParameters == null) {
            return retornarAccesTokenUserDefault(response);
        }

        String cpf = queryStringParameters.get("cpf");
        if (Objects.isNull(cpf) || cpf.isEmpty()) {
            return retornarAccesTokenUserDefault(response);
        }

        AdminGetUserResponse usuario = obterUsuarioCognito(cpf);
        String accessToken = gerarAccesToken(cpf, usuario);

        try {
            String output = String.format("{ \"access_token\": \"%s\" }", accessToken);

            return response
                    .withStatusCode(200)
                    .withBody(output);
        } catch (Exception e) {
            return response
                    .withBody("{}")
                    .withStatusCode(500);
        }
    }

    private String gerarAccesToken(String user, AdminGetUserResponse usuario) {
        String accessToken;
        if (Objects.isNull(usuario)) {
            AdminCreateUserResponse responseSignup = inserirUsuarioCognito(user);
            changePasswordAndConfirmUser(user, defaultPassword);
            accessToken = obterTokenCognito(responseSignup.user().username());
        } else {
            accessToken = obterTokenCognito(usuario.username());
        }
        return accessToken;
    }

    private APIGatewayProxyResponseEvent retornarAccesTokenUserDefault(APIGatewayProxyResponseEvent response) {
        AdminGetUserResponse usuario = obterUsuarioCognito(defaultUser);
        String accessToken = gerarAccesToken(defaultUser, usuario);

        String output = String.format("{ \"access_token\": \"%s\" }", accessToken);

        return response
                .withStatusCode(200)
                .withBody(output);
    }

    public String obterTokenCognito(String user) {
        CognitoIdentityProviderClient cognitoClient = CognitoIdentityProviderClient.create();

        AdminInitiateAuthRequest authRequest = getAuthenticationRequest(user);
        AdminInitiateAuthResponse authResponse = cognitoClient.adminInitiateAuth(authRequest);

        return authResponse.authenticationResult().accessToken();
    }

    private AdminInitiateAuthRequest getAuthenticationRequest(String user) {
        return AdminInitiateAuthRequest.builder()
                .userPoolId(userPoolId)
                .clientId(appClientId)
                .authFlow(AuthFlowType.ADMIN_NO_SRP_AUTH)
                .authParameters(Map.of("USERNAME", user, "PASSWORD", defaultPassword,
                        "SECRET_HASH", calculateSecretHash(appClientId, clientSecret, user)))
                .build();
    }

    public AdminGetUserResponse obterUsuarioCognito(String cpf) {
        try {
            CognitoIdentityProviderClient cognitoClient = CognitoIdentityProviderClient.create();

            AdminGetUserRequest getUserRequest = AdminGetUserRequest.builder()
                    .userPoolId(userPoolId)
                    .username(cpf)
                    .build();

            return cognitoClient.adminGetUser(getUserRequest);
        } catch (UserNotFoundException e) {
            logger.info("Usuário não encontrado");
            return null;
        }
    }

    public AdminCreateUserResponse inserirUsuarioCognito(String cpf) {
        CognitoIdentityProviderClient cognitoClient = CognitoIdentityProviderClient.create();

        AdminCreateUserRequest createUserRequest = AdminCreateUserRequest.builder()
                .userPoolId(userPoolId)
                .username(cpf)
                .temporaryPassword(defaultPassword)
                .build();

        return cognitoClient.adminCreateUser(createUserRequest);
    }

    public String calculateSecretHash(String userPoolClientId, String userPoolClientSecret, String userName) {
        String data = userName + userPoolClientId;
        SecretKeySpec secretKey = new SecretKeySpec(
                userPoolClientSecret.getBytes(StandardCharsets.UTF_8),
                "HmacSHA256"
        );
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(secretKey);
            byte[] rawHmac = mac.doFinal(data.getBytes(StandardCharsets.UTF_8));
            return Base64.getEncoder().encodeToString(rawHmac);
        } catch (Exception e) {
            throw new RuntimeException("Error while calculating secret hash", e);
        }
    }

    public void changePasswordAndConfirmUser(String username, String newPassword) {
        CognitoIdentityProviderClient cognitoClient = CognitoIdentityProviderClient.create();

        AdminInitiateAuthRequest authRequest = getAuthenticationRequest(username);

        AdminInitiateAuthResponse authResponse = cognitoClient.adminInitiateAuth(authRequest);

        if (authResponse.challengeName() == ChallengeNameType.NEW_PASSWORD_REQUIRED) {
            RespondToAuthChallengeRequest challengeRequest = RespondToAuthChallengeRequest.builder()
                    .clientId(appClientId)
                    .challengeName(ChallengeNameType.NEW_PASSWORD_REQUIRED)
                    .session(authResponse.session())
                    .challengeResponses(Map.of(
                            "USERNAME", username,
                            "NEW_PASSWORD", newPassword,
                            "SECRET_HASH", calculateSecretHash(appClientId, clientSecret, username)
                    ))
                    .build();

            cognitoClient.respondToAuthChallenge(challengeRequest);
        }
    }
}
