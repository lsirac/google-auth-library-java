/*
 * Copyright 2021 Google LLC
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *    * Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 *    * Redistributions in binary form must reproduce the above
 * copyright notice, this list of conditions and the following disclaimer
 * in the documentation and/or other materials provided with the
 * distribution.
 *
 *    * Neither the name of Google LLC nor the names of its
 * contributors may be used to endorse or promote products derived from
 * this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

package com.google.auth.oauth2;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.Assert.assertTrue;

import com.google.api.client.http.GenericUrl;
import com.google.api.client.http.HttpRequest;
import com.google.api.client.http.HttpRequestFactory;
import com.google.api.client.http.HttpResponse;
import com.google.api.client.http.UrlEncodedContent;
import com.google.api.client.http.javanet.NetHttpTransport;
import com.google.api.client.json.GenericJson;
import com.google.api.client.json.JsonObjectParser;
import com.google.api.client.json.gson.GsonFactory;
import com.google.api.client.json.jackson2.JacksonFactory;
import com.google.api.client.util.GenericData;
import com.google.auth.http.HttpCredentialsAdapter;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;
import org.junit.Rule;
import org.junit.Test;
import org.junit.contrib.java.lang.system.EnvironmentVariables;

public class ITWorkloadIdentityFederation {

  private static final String CLOUD_PLATFORM_SCOPE =
      "https://www.googleapis.com/auth/cloud-platform";

  private static final String SERVICE_ACCOUNT_EMAIL =
      "it-service-account@gcloud-devel.iam.gserviceaccount.com";
  private static final String GCS_BUCKET_NAME = "byoid-it-bucket";

  private static final String PROJECT_NUMBER = "1016721519174";
  private static final String POOL_ID = "pool-1";
  private static final String OIDC_PROVIDER_ID = "oidc-1";
  private static final String AWS_PROVIDER_ID = "aws-1";
  private static final String AWS_ROLE_NAME = "ci-java-test";
  private static final String AWS_ROLE_ARN = "arn:aws:iam::027472800722:role/ci-java-test";

  @Rule public final EnvironmentVariables environmentVariables = new EnvironmentVariables();

  @Test
  public void identityPoolCredentials() throws IOException {
    GenericJson json = readResource("azure_credentials.json");
    json.put("credential_source", buildFileBasedCredentialSource());

    IdentityPoolCredentials identityPoolCredentials =
        (IdentityPoolCredentials)
            ExternalAccountCredentials.fromJson(json, OAuth2Utils.HTTP_TRANSPORT_FACTORY);
    callGcs(identityPoolCredentials);
  }

  @Test
  public void awsCredentials() throws Exception {
    String audience =
        String.format(
            "//iam.googleapis.com/projects/%s/locations/global/workloadIdentityPools/%s/providers/%s",
            PROJECT_NUMBER, POOL_ID, AWS_PROVIDER_ID);

    String idToken = generateGoogleIdToken(audience);

    String url =
        String.format(
            "https://sts.amazonaws.com/?Action=AssumeRoleWithWebIdentity"
                + "&Version=2011-06-15&DurationSeconds=3600&RoleSessionName=%s"
                + "&RoleArn=%s&WebIdentityToken=%s",
            AWS_ROLE_NAME, AWS_ROLE_ARN, idToken);

    HttpRequestFactory requestFactory = new NetHttpTransport().createRequestFactory();
    HttpRequest request = requestFactory.buildGetRequest(new GenericUrl(url));

    JsonObjectParser parser = new JsonObjectParser(GsonFactory.getDefaultInstance());
    request.setParser(parser);

    HttpResponse response = request.execute();
    String rawXml = response.parseAsString();

    String awsAccessKeyId = getXmlValueByTagName(rawXml, "AccessKeyId");
    String awsSecretAccessKey = getXmlValueByTagName(rawXml, "SecretAccessKey");
    String awsSessionToken = getXmlValueByTagName(rawXml, "SessionToken");

    AwsCredentials awsCredentials =
        (AwsCredentials)
            AwsCredentials.fromJson(
                readResource("aws_credentials.json"), OAuth2Utils.HTTP_TRANSPORT_FACTORY);

    environmentVariables.set("AWS_ACCESS_KEY_ID", awsAccessKeyId);
    environmentVariables.set("AWS_SECRET_ACCESS_KEY", awsSecretAccessKey);
    environmentVariables.set("Token", awsSessionToken);
    environmentVariables.set("AWS_REGION", "us-east-2");

    callGcs(awsCredentials);
  }

  private void callGcs(GoogleCredentials credentials) throws IOException {
    String url = "https://storage.googleapis.com/storage/v1/b/" + GCS_BUCKET_NAME;

    HttpCredentialsAdapter credentialsAdapter = new HttpCredentialsAdapter(credentials);
    HttpRequestFactory requestFactory =
        new NetHttpTransport().createRequestFactory(credentialsAdapter);
    HttpRequest request = requestFactory.buildGetRequest(new GenericUrl(url));

    JsonObjectParser parser = new JsonObjectParser(JacksonFactory.getDefaultInstance());
    request.setParser(parser);

    HttpResponse response = request.execute();
    assertTrue(response.isSuccessStatusCode());
  }

  private String generateGoogleIdToken(String audience) throws IOException {
    GoogleCredentials googleCredentials =
        GoogleCredentials.getApplicationDefault().createScoped(CLOUD_PLATFORM_SCOPE);

    HttpCredentialsAdapter credentialsAdapter = new HttpCredentialsAdapter(googleCredentials);
    HttpRequestFactory requestFactory =
        new NetHttpTransport().createRequestFactory(credentialsAdapter);

    String url =
        String.format(
            "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/%s:generateIdToken",
            SERVICE_ACCOUNT_EMAIL);

    GenericData data = new GenericData();
    data.set("audience", audience);
    data.set("includeEmail", true);
    UrlEncodedContent content = new UrlEncodedContent(data);

    HttpRequest request = requestFactory.buildPostRequest(new GenericUrl(url), content);

    JsonObjectParser parser = new JsonObjectParser(GsonFactory.getDefaultInstance());
    request.setParser(parser);

    HttpResponse response = request.execute();

    GenericData responseData = response.parseAs(GenericData.class);

    return (String) responseData.get("token");
  }

  private Map<String, String> buildFileBasedCredentialSource() throws IOException {
    String audience =
        String.format(
            "//iam.googleapis.com/projects/%s/locations/global/workloadIdentityPools/%s/providers/%s",
            PROJECT_NUMBER, POOL_ID, OIDC_PROVIDER_ID);
    String idToken = generateGoogleIdToken(audience);

    File file = File.createTempFile("ITByoid", /* suffix= */ null, /* directory= */ null);
    file.deleteOnExit();

    OAuth2Utils.writeInputStreamToFile(
        new ByteArrayInputStream(idToken.getBytes(StandardCharsets.UTF_8)), file.getAbsolutePath());

    Map<String, String> map = new HashMap<>();
    map.put("file", file.getAbsolutePath());
    return map;
  }

  static GenericJson readResource(String resourceName) throws IOException {
    InputStream stream =
        ITWorkloadIdentityFederation.class.getClassLoader().getResourceAsStream(resourceName);

    JsonObjectParser parser = new JsonObjectParser(GsonFactory.getDefaultInstance());

    return parser.parseAndClose(stream, UTF_8, GenericJson.class);
  }

  private String getXmlValueByTagName(String rawXml, String tagName) {
    int startIndex = rawXml.indexOf("<" + tagName + ">");
    int endIndex = rawXml.indexOf("</" + tagName + ">", startIndex);

    if (startIndex >= 0 && endIndex > startIndex) {
      return rawXml.substring(startIndex + tagName.length() + 2, endIndex);
    }
    return null;
  }
}
