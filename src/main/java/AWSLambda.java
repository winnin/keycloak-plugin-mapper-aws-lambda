import org.jboss.logging.Logger;
import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.services.lambda.LambdaClient;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.lambda.model.InvokeRequest;
import software.amazon.awssdk.services.lambda.model.LambdaException;

public class AWSLambda {
    private static final Logger LOGGER = Logger.getLogger(AWSLambdaScriptOIDCProtocolMapperV2.class);

    private static final String AWS_REGION = System.getenv("AWS_REGION");

    private static final String AWS_ACCESS_KEY_ID = System.getenv("AWS_ACCESS_KEY_ID");

    private static final String AWS_SECRET_ACCESS_KEY = System.getenv("AWS_SECRET_ACCESS_KEY");

    private LambdaClient awsLambda;

    public void builder() {
        if (awsLambda == null) {
            Region awsRegion = Region.of(AWS_REGION);
            AwsBasicCredentials basicCredentials = AwsBasicCredentials.create(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY);
            awsLambda = LambdaClient.builder().region(awsRegion).credentialsProvider(StaticCredentialsProvider.create(basicCredentials)).build();
        }
    }

    public void builder(String region, String accessKey, String privateKey) {
        if (awsLambda == null) {
            Region awsRegion = Region.of(region);
            AwsBasicCredentials basicCredentials = AwsBasicCredentials.create(accessKey, privateKey);
            awsLambda = LambdaClient.builder().region(awsRegion).credentialsProvider(StaticCredentialsProvider.create(basicCredentials)).build();
        }
    }

    public void reset() {
        awsLambda = null;
    }

    public Boolean supportCurrentCredentials() {
        return AWS_REGION != null && AWS_ACCESS_KEY_ID != null && AWS_SECRET_ACCESS_KEY != null;
    }

    public String invoke(String functionName, String input) {
        try {
            SdkBytes payload = SdkBytes.fromUtf8String(input);

            InvokeRequest request = InvokeRequest.builder()
                    .functionName(functionName)
                    .payload(payload)
                    .build();

            return awsLambda.invoke(request).payload().asUtf8String();
        } catch (LambdaException e) {
            LOGGER.error("Error during execution of lambda", e);
        }

        return null;
    }
}
