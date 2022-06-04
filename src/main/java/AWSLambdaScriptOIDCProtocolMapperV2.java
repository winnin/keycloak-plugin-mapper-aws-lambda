import org.jboss.logging.Logger;
import org.keycloak.common.Profile;
import org.keycloak.models.ClientSessionContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.ProtocolMapperContainerModel;
import org.keycloak.models.ProtocolMapperModel;
import org.keycloak.models.RealmModel;
import org.keycloak.models.ScriptModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.protocol.ProtocolMapperConfigException;
import org.keycloak.protocol.ProtocolMapperUtils;
import org.keycloak.protocol.oidc.mappers.*;
import org.keycloak.provider.EnvironmentDependentProviderFactory;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.provider.ProviderConfigurationBuilder;
import org.keycloak.representations.AccessTokenResponse;
import org.keycloak.representations.IDToken;
import org.keycloak.scripting.EvaluatableScriptAdapter;
import org.keycloak.scripting.ScriptCompilationException;
import org.keycloak.scripting.ScriptingProvider;

import java.util.List;

public class AWSLambdaScriptOIDCProtocolMapperV2 extends AbstractOIDCProtocolMapper implements OIDCAccessTokenMapper, OIDCIDTokenMapper, UserInfoTokenMapper,
        OIDCAccessTokenResponseMapper, EnvironmentDependentProviderFactory {

    public static final String PROVIDER_ID = "oidc-script-based-protocol-mapper-aws-lambda-v2";

    private static final Logger LOGGER = Logger.getLogger(AWSLambdaScriptOIDCProtocolMapperV2.class);

    public static final String SCRIPT = "script";

    public static final String AWS_DEFAULT_CREDENTIALS = "aws.default";

    public static final String ACCESS_KEY = "aws.access.key";

    public static final String SECRET_KEY = "aws.secret.key";

    public static final String REGION = "aws.region";

    private static final List<ProviderConfigProperty> configProperties;

    private static final AWSLambda lambda;

    static {

        lambda = new AWSLambda();

        configProperties = ProviderConfigurationBuilder.create()
                .property()
                .name(AWS_DEFAULT_CREDENTIALS)
                .type(ProviderConfigProperty.BOOLEAN_TYPE)
                .label("Use current credentials")
                .defaultValue(lambda.supportCurrentCredentials())
                .add()
                .property()
                .name(ACCESS_KEY)
                .type(ProviderConfigProperty.PASSWORD)
                .label("AWS Access Key")
                .add()
                .property()
                .name(SECRET_KEY)
                .type(ProviderConfigProperty.PASSWORD)
                .label("AWS Secret Access key")
                .add()
                .property()
                .name(REGION)
                .type(ProviderConfigProperty.STRING_TYPE)
                .label("AWS Region")
                .add()
                .property()
                .name(SCRIPT)
                .type(ProviderConfigProperty.SCRIPT_TYPE)
                .label("Script")
                .helpText(
                        "Script to compute the claim value. \n" + //
                                " Available variables: \n" + //
                                " 'user' - the current user.\n" + //
                                " 'realm' - the current realm.\n" + //
                                " 'token' - the current token.\n" + //
                                " 'userSession' - the current userSession.\n" + //
                                " 'keycloakSession' - the current keycloakSession.\n" + //
                                " 'lambda' - the lambda instance from aws\n" //
                )
                .defaultValue("/**\n" + //
                        " * Available variables: \n" + //
                        " * user - the current user\n" + //
                        " * realm - the current realm\n" + //
                        " * token - the current token\n" + //
                        " * userSession - the current userSession\n" + //
                        " * keycloakSession - the current keycloakSession\n" + //
                        " * lambda - the lambda instance from aws\n" + //
                        " */\n\n\n//insert your code here..." //
                )
                .add()
                .property()
                .name(ProtocolMapperUtils.MULTIVALUED)
                .label(ProtocolMapperUtils.MULTIVALUED_LABEL)
                .helpText(ProtocolMapperUtils.MULTIVALUED_HELP_TEXT)
                .type(ProviderConfigProperty.BOOLEAN_TYPE)
                .defaultValue(false)
                .add()
                .build();

        OIDCAttributeMapperHelper.addAttributeConfig(configProperties, UserPropertyMapper.class);
    }

    public List<ProviderConfigProperty> getConfigProperties() {
        return configProperties;
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public String getDisplayType() {
        return "Script Mapper with AWS lambda v2";
    }

    @Override
    public String getDisplayCategory() {
        return TOKEN_MAPPER_CATEGORY;
    }

    @Override
    public String getHelpText() {
        return "Evaluates a JavaScript function to produce a token claim based on context information.";
    }

    @Override
    public boolean isSupported() {
        return Profile.isFeatureEnabled(Profile.Feature.SCRIPTS);
    }

    @Override
    public int getPriority() {
        return ProtocolMapperUtils.PRIORITY_SCRIPT_MAPPER;
    }

    @Override
    protected void setClaim(IDToken token, ProtocolMapperModel mappingModel, UserSessionModel userSession, KeycloakSession keycloakSession, ClientSessionContext clientSessionCtx) {
        Object claimValue = evaluateScript(token, mappingModel, userSession, keycloakSession);
        OIDCAttributeMapperHelper.mapClaim(token, mappingModel, claimValue);
    }

    @Override
    protected void setClaim(AccessTokenResponse accessTokenResponse, ProtocolMapperModel mappingModel, UserSessionModel userSession,
                            KeycloakSession keycloakSession, ClientSessionContext clientSessionCtx) {
        Object claimValue = evaluateScript(accessTokenResponse, mappingModel, userSession, keycloakSession);
        OIDCAttributeMapperHelper.mapClaim(accessTokenResponse, mappingModel, claimValue);
    }

    private Object evaluateScript(Object tokenBinding, ProtocolMapperModel mappingModel, UserSessionModel userSession, KeycloakSession keycloakSession) {
        UserModel user = userSession.getUser();
        String scriptSource = getScriptCode(mappingModel);

        RealmModel realm = userSession.getRealm();

        ScriptingProvider scripting = keycloakSession.getProvider(ScriptingProvider.class);
        ScriptModel scriptModel = scripting.createScript(realm.getId(), ScriptModel.TEXT_JAVASCRIPT, "token-mapper-script_" + mappingModel.getName(), scriptSource, null);

        EvaluatableScriptAdapter script = scripting.prepareEvaluatableScript(scriptModel);

        String defaultCredentials = mappingModel.getConfig().get(AWS_DEFAULT_CREDENTIALS);
        String accessKey = mappingModel.getConfig().get(ACCESS_KEY);
        String privateKey = mappingModel.getConfig().get(SECRET_KEY);
        String region = mappingModel.getConfig().get(REGION);

        if (defaultCredentials.equals("true")) {
            lambda.builder();
        } else {
            lambda.builder(region, accessKey, privateKey);
        }

        Object claimValue;
        try {
            claimValue = script.eval((bindings) -> {
                bindings.put("lambda", lambda);
                bindings.put("user", user);
                bindings.put("realm", realm);
                if (tokenBinding instanceof IDToken) {
                    bindings.put("token", tokenBinding);
                } else if (tokenBinding instanceof AccessTokenResponse) {
                    bindings.put("tokenResponse", tokenBinding);
                }
                bindings.put("userSession", userSession);
                bindings.put("keycloakSession", keycloakSession);
            });
        } catch (Exception ex) {
            LOGGER.error("Error during execution of ProtocolMapper script", ex);
            claimValue = null;
        }

        return claimValue;
    }

    @Override
    public void validateConfig(KeycloakSession session, RealmModel realm, ProtocolMapperContainerModel client, ProtocolMapperModel mapperModel) throws ProtocolMapperConfigException {

        String scriptCode = getScriptCode(mapperModel);
        String defaultCredentials = mapperModel.getConfig().get(AWS_DEFAULT_CREDENTIALS);
        String accessKey = mapperModel.getConfig().get(ACCESS_KEY);
        String privateKey = mapperModel.getConfig().get(SECRET_KEY);
        String region = mapperModel.getConfig().get(REGION);

        if (!lambda.supportCurrentCredentials() || (defaultCredentials != null && defaultCredentials.equals("false"))) {
            if (region == null || region.isEmpty()) {
                throw new ProtocolMapperConfigException("error", "{0}", "Region is required out of aws");
            }

            if ((accessKey == null || accessKey.isEmpty()) || (privateKey == null || privateKey.isEmpty())) {
                throw new ProtocolMapperConfigException("error", "{0}", "Credentials are required out of aws");
            }

            if (defaultCredentials != null && defaultCredentials.equals("true")) {
                throw new ProtocolMapperConfigException("error", "{0}", "Current credentials not supported");
            }
        }

        ScriptingProvider scripting = session.getProvider(ScriptingProvider.class);
        ScriptModel scriptModel = scripting.createScript(realm.getId(), ScriptModel.TEXT_JAVASCRIPT, mapperModel.getName() + "-script", scriptCode, "");

        try {
            scripting.prepareEvaluatableScript(scriptModel);
        } catch (ScriptCompilationException ex) {
            throw new ProtocolMapperConfigException("error", "{0}", ex.getMessage());
        }

        lambda.reset();
    }

    protected String getScriptCode(ProtocolMapperModel mapperModel) {
        return mapperModel.getConfig().get(SCRIPT);
    }

    public static ProtocolMapperModel create(String name,
                                             String userAttribute,
                                             String tokenClaimName, String claimType,
                                             boolean accessToken, boolean idToken, String script, boolean multiValued) {
        ProtocolMapperModel mapper = OIDCAttributeMapperHelper.createClaimMapper(name, userAttribute,
                tokenClaimName, claimType,
                accessToken, idToken,
                script);

        mapper.getConfig().put(ProtocolMapperUtils.MULTIVALUED, String.valueOf(multiValued));

        return mapper;
    }
}
