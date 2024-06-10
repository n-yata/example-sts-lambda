package example.micronaut;

import java.nio.charset.StandardCharsets;

import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.ByteArrayEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;

import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.fasterxml.jackson.databind.ObjectMapper;

import io.github.acm19.aws.interceptor.http.AwsRequestSigningApacheInterceptor;
import io.micronaut.function.aws.MicronautRequestHandler;
import jakarta.inject.Inject;
import software.amazon.awssdk.auth.credentials.AwsSessionCredentials;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.auth.signer.Aws4UnsignedPayloadSigner;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.sts.StsClient;
import software.amazon.awssdk.services.sts.model.AssumeRoleRequest;
import software.amazon.awssdk.services.sts.model.AssumeRoleResponse;

// ★その他参考
// sigv4ライブラリで実装
// https://github.com/aws-samples/sigv4-signing-examples/blob/main/no-sdk/java/AWSSigner.java
// sigv4aライブラリで実装
// https://github.com/aws-samples/sigv4a-signing-examples/blob/main/java/src/main/java/com/sigv4aSigning/SigV4ASign.java
public class FunctionRequestHandler
        extends MicronautRequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    @Inject
    private ObjectMapper objectMapper;

    @Override
    public APIGatewayProxyResponseEvent execute(APIGatewayProxyRequestEvent requestEvent) {

        APIGatewayProxyResponseEvent responseEvent = new APIGatewayProxyResponseEvent();

        // TODO 正しいのに変更
        String roleArn = "arn:aws:iam::123456789012:role/YourRole";
        String roleSessionName = "your-session-name";
        String apiUrl = "https://your-api-id.execute-api.region.amazonaws.com/your-stage/your-resource";
        Region region = Region.AP_NORTHEAST_1;

        // Create STS client
        StsClient stsClient = StsClient.builder()
                .region(region)
                .build();

        // Assume role
        AssumeRoleRequest assumeRoleRequest = AssumeRoleRequest.builder()
                .roleArn(roleArn)
                .roleSessionName(roleSessionName)
                .build();
        AssumeRoleResponse assumeRoleResponse = stsClient.assumeRole(assumeRoleRequest);

        // ★試しその1 Credentialsにセッショントークンを含める
        AwsSessionCredentials temporaryCredentials = AwsSessionCredentials.create(
                assumeRoleResponse.credentials().accessKeyId(),
                assumeRoleResponse.credentials().secretAccessKey(),
                assumeRoleResponse.credentials().sessionToken());

        var interceptor = new AwsRequestSigningApacheInterceptor(
                "execute-api",
                Aws4UnsignedPayloadSigner.create(),
                StaticCredentialsProvider.create(temporaryCredentials),
                Region.AP_NORTHEAST_1.id());

        CloseableHttpClient client = HttpClients.custom()
                .addInterceptorLast(interceptor)
                .build();

        // Prepare payload for POST request
        String payload = "{\"key1\":\"value1\", \"key2\":\"value2\"}";

        var httpPost = new HttpPost(apiUrl);
        httpPost.addHeader("content-type", "application/json");

        // ★試しその2 ヘッダーにセッショントークンを含める
        //        httpPost.addHeader("content-type", "application/json");

        httpPost.setEntity(new ByteArrayEntity(payload.getBytes(StandardCharsets.UTF_8)));

        try (var response = client.execute(httpPost)) {
            System.out.println(new String(response.getEntity().getContent().readAllBytes()));
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        //        // ★NGその1 PostToConnectionRequestはWebSocket利用時のクラス 
        //        // Create ApiGateway client with temporary credentials
        //        ApiGatewayClient apiGatewayClient = ApiGatewayClient.builder()
        //                .region(region)
        //                .credentialsProvider(StaticCredentialsProvider.create(temporaryCredentials))
        //                .httpClient(ApacheHttpClient.builder().build())
        //                .overrideConfiguration(ClientOverrideConfiguration.builder().build())
        //                .build();
        //        try {
        //            URI endpoint = new URI(apiUrl);
        //
        //            // Create POST request
        //            PostToConnectionRequest postRequest = PostToConnectionRequest.builder()
        //                    .connectionId(endpoint.toString())
        //                    .data(SdkBytes.fromString(payload, StandardCharsets.UTF_8))
        //                    .build();
        //
        //            // Send request to API Gateway
        //            PostToConnectionResponse postResponse = apiGatewayClient.postToConnection(postRequest);
        //
        //            // Output the response status code
        //            System.out.println("Response Status Code: " + postResponse.sdkHttpResponse().statusCode());
        //
        //        } catch (URISyntaxException e) {
        //            e.printStackTrace();
        //        }
        //
        //        // ★NGその2 ApacheHttpClientを利用、ある程度あっていそうだけどCledencial情報をうまくHttpClientに埋め込めない
        //        // Create HTTP client
        //        SdkHttpClient httpClient = ApacheHttpClient.builder().build();
        //        ClientOverrideConfiguration overrideConfiguration = ClientOverrideConfiguration.builder().build();
        //
        //        try {
        //            URI endpoint = new URI(apiUrl);
        //            SdkHttpFullRequest request = SdkHttpFullRequest.builder()
        //                    .uri(endpoint)
        //                    .method(SdkHttpMethod.GET)
        //                    .headers(new HashMap<String, List<String>>() {
        //                        {
        //                            put("Accept", Collections.singletonList("application/json"));
        //                        }
        //                    })
        //                    .build();
        //
        //            // Sign request with temporary credentials
        //            SdkHttpFullResponse response = httpClient.prepareRequest(request, overrideConfiguration,
        //                    StaticCredentialsProvider.create(temporaryCredentials)).join();
        //
        //            String responseBody = new String(response.content().orElse(ByteBuffer.wrap(new byte[0])).array(),
        //                    StandardCharsets.UTF_8);
        //            System.out.println("Response: " + responseBody);
        //
        //        } catch (URISyntaxException e) {
        //            e.printStackTrace();
        //        }
        //
        //        try {
        //            FuncRequest req = objectMapper.readValue(requestEvent.getBody(), FuncRequest.class);
        //            FuncResponse res = runProcess(req);
        //
        //            responseEvent.setStatusCode(200);
        //            responseEvent.setBody(objectMapper.writeValueAsString(res));
        //
        //        } catch (Exception e) {
        //            e.printStackTrace();
        //            responseEvent.setStatusCode(500);
        //            JSONObject obj = new JSONObject();
        //            obj.put("error", "error");
        //            responseEvent.setBody(obj.toString());
        //        }
        return responseEvent;
    }
}
