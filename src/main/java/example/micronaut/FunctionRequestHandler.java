package example.micronaut;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Locale;
import java.util.TimeZone;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.fasterxml.jackson.databind.ObjectMapper;

import io.micronaut.function.aws.MicronautRequestHandler;
import jakarta.inject.Inject;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.sts.StsClient;
import software.amazon.awssdk.services.sts.model.AssumeRoleRequest;
import software.amazon.awssdk.services.sts.model.AssumeRoleResponse;

// sigv4ライブラリで実装 ←これでうまくいった
// https://github.com/aws-samples/sigv4-signing-examples/blob/main/no-sdk/java/AWSSigner.java
// sigv4aライブラリで実装
// https://github.com/aws-samples/sigv4a-signing-examples/blob/main/java/src/main/java/com/sigv4aSigning/SigV4ASign.java
public class FunctionRequestHandler
        extends MicronautRequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    @Inject
    private ObjectMapper objectMapper;

    private static final String RESTAPIHOST = System.getenv("https://example.com");
    private static final String RESTAPIPATH = System.getenv("/path/to-resource");

    private static final String METHOD = "GET";
    private static final String SERVICE = "execute-api";
    private static final String REGION = Region.AP_NORTHEAST_1.id();
    private static final String ALGORITHM = "AWS4-HMAC-SHA256";

    @Override
    public APIGatewayProxyResponseEvent execute(APIGatewayProxyRequestEvent requestEvent) {

        try {
            return run(requestEvent);
        } catch (NoSuchAlgorithmException | IOException e) {
            // TODO 自動生成された catch ブロック
            e.printStackTrace();
        }

        return null;
    }

    private APIGatewayProxyResponseEvent run(APIGatewayProxyRequestEvent requestEvent)
            throws NoSuchAlgorithmException, IOException {

        APIGatewayProxyResponseEvent responseEvent = new APIGatewayProxyResponseEvent();

        // TODO 正しいのに変更
        String roleArn = "arn:aws:iam::123456789012:role/YourRole";
        String roleSessionName = "your-session-name";

        // Create STS client
        StsClient stsClient = StsClient.builder()
                .region(Region.AP_NORTHEAST_1)
                .build();

        // Assume role
        AssumeRoleRequest assumeRoleRequest = AssumeRoleRequest.builder()
                .roleArn(roleArn)
                .roleSessionName(roleSessionName)
                .build();
        AssumeRoleResponse assumeRoleResponse = stsClient.assumeRole(assumeRoleRequest);
        String accessKeyId = assumeRoleResponse.credentials().accessKeyId();
        String secretAccessKey = assumeRoleResponse.credentials().secretAccessKey();
        String sessionToken = assumeRoleResponse.credentials().sessionToken();

        // Create a datetime object for signing
        SimpleDateFormat dateFormat = new SimpleDateFormat("yyyyMMdd'T'HHmmss'Z'", Locale.US);
        dateFormat.setTimeZone(TimeZone.getTimeZone("UTC"));
        String amzDate = dateFormat.format(new Date());
        String dateStamp = amzDate.substring(0, 8);

        // Create the canonical request
        String canonicalUri = RESTAPIPATH;
        String canonicalQuerystring = ""; // TODO クエリパラメータがある場合はここに追加
        String canonicalHeaders = "host:" + RESTAPIHOST + "\n";
        String signedHeaders = "host";
        String payloadHash = sha256Hex(""); // TODO リクエストボディがある場合はここに追加
        String canonicalRequest = METHOD + "\n" + canonicalUri + "\n" + canonicalQuerystring + "\n" + canonicalHeaders
                + "\n" + signedHeaders + "\n" + payloadHash;

        // Create the string to sign
        String credentialScope = dateStamp + "/" + REGION + "/" + SERVICE + "/" + "aws4_request";
        String hashedCanonicalRequest = sha256Hex(canonicalRequest);
        String stringToSign = ALGORITHM + "\n" + amzDate + "\n" + credentialScope + "\n" + hashedCanonicalRequest;

        // Sign the string
        byte[] signingKey = getSignatureKey(secretAccessKey, dateStamp, REGION, SERVICE);
        String signature = hmacSha256Hex(signingKey, stringToSign);

        // Add signing information to the request
        String authorizationHeader = ALGORITHM + " " + "Credential=" + accessKeyId + "/" + credentialScope + ", "
                + "SignedHeaders=" + signedHeaders + ", " + "Signature=" + signature;

        // Make the request
        URL url = new URL("https://" + RESTAPIHOST + canonicalUri);
        HttpURLConnection con = (HttpURLConnection) url.openConnection();
        con.setRequestMethod(METHOD);
        con.setRequestProperty("Host", RESTAPIHOST);
        con.setRequestProperty("x-amz-date", amzDate);
        con.setRequestProperty("x-amz-security-token", sessionToken);
        con.setRequestProperty("Authorization", authorizationHeader);

        // Print the response
        int responseCode = con.getResponseCode();
        if (responseCode == HttpURLConnection.HTTP_OK) {
            String responseBody = new String(con.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
            System.out.println(responseBody);
        } else {
            String responseBody = new String(con.getErrorStream().readAllBytes(), StandardCharsets.UTF_8);
            System.out.println(responseBody);
        }

        return responseEvent;
    }

    private static byte[] getSignatureKey(String key, String dateStamp, String regionName, String serviceName)
            throws NoSuchAlgorithmException {
        byte[] kSecret = ("AWS4" + key).getBytes(StandardCharsets.UTF_8);
        byte[] kDate = hmacSha256(kSecret, dateStamp);
        byte[] kRegion = hmacSha256(kDate, regionName);
        byte[] kService = hmacSha256(kRegion, serviceName);
        return hmacSha256(kService, "aws4_request");
    }

    private static String hmacSha256Hex(byte[] key, String data) throws NoSuchAlgorithmException {
        return bytesToHex(hmacSha256(key, data));
    }

    private static byte[] hmacSha256(byte[] key, String data) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(key, "HmacSHA256"));
            return mac.doFinal(data.getBytes(StandardCharsets.UTF_8));
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Error: HmacSHA256 algorithm not available", e);
        } catch (InvalidKeyException e) {
            throw new RuntimeException("Error: Invalid key for HmacSHA256", e);
        }
    }

    private static String sha256Hex(String data) throws NoSuchAlgorithmException {
        return bytesToHex(MessageDigest.getInstance("SHA-256").digest(data.getBytes(StandardCharsets.UTF_8)));
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder result = new StringBuilder();
        for (byte b : bytes) {
            result.append(String.format("%02x", b));
        }
        return result.toString();
    }

    /**
     * 結局うまくいかなかっ試したち
     */
    void tmp() {
        //        String apiUrl = "https://your-api-id.execute-api.region.amazonaws.com/your-stage/your-resource";
        //        Region region = Region.AP_NORTHEAST_1;
        //        
        // ★試しその1 Credentialsにセッショントークンを含める
        //        AwsSessionCredentials temporaryCredentials = AwsSessionCredentials.create(
        //                assumeRoleResponse.credentials().accessKeyId(),
        //                assumeRoleResponse.credentials().secretAccessKey(),
        //                assumeRoleResponse.credentials().sessionToken());
        //
        //        var interceptor = new AwsRequestSigningApacheInterceptor(
        //                "execute-api",
        //                Aws4UnsignedPayloadSigner.create(),
        //                StaticCredentialsProvider.create(temporaryCredentials),
        //                Region.AP_NORTHEAST_1.id());
        //
        //        CloseableHttpClient client = HttpClients.custom()
        //                .addInterceptorLast(interceptor)
        //                .build();
        //
        //        // Prepare payload for POST request
        //        String payload = "{\"key1\":\"value1\", \"key2\":\"value2\"}";
        //
        //        var httpPost = new HttpPost(apiUrl);
        //        httpPost.addHeader("content-type", "application/json");
        //
        //        // ★試しその2 ヘッダーにセッショントークンを含める
        //        //        httpPost.addHeader("content-type", "application/json");
        //
        //        httpPost.setEntity(new ByteArrayEntity(payload.getBytes(StandardCharsets.UTF_8)));
        //
        //        try (var response = client.execute(httpPost)) {
        //            System.out.println(new String(response.getEntity().getContent().readAllBytes()));
        //        } catch (Exception e) {
        //            throw new RuntimeException(e);
        //        }
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
    }
}
