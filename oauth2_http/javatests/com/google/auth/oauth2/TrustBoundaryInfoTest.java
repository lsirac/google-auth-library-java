/*
 * Copyright 2024 Google LLC
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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import com.google.api.client.http.HttpStatusCodes;
import com.google.api.client.http.LowLevelHttpRequest;
import com.google.api.client.http.LowLevelHttpResponse;
import com.google.api.client.json.GenericJson;
import com.google.api.client.json.JsonFactory;
import com.google.api.client.json.gson.GsonFactory;
import com.google.api.client.testing.http.MockHttpTransport;
import com.google.api.client.testing.http.MockLowLevelHttpRequest;
import com.google.api.client.testing.http.MockLowLevelHttpResponse;
import com.google.auth.http.HttpTransportFactory;
import java.io.IOException;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Tests for {@link TrustBoundaryInfo}. */
@RunWith(JUnit4.class)
public class TrustBoundaryInfoTest {

  private static final String TEST_ACCESS_TOKEN = "test-access-token";
  private static final String TEST_LOOKUP_URL = "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/test@example.com/allowedLocations";
  private static final String TEST_ENCODED_LOCATIONS = "0xA30";
  private static final List<String> TEST_LOCATIONS = Arrays.asList("us-central1", "us-east1", "europe-west1", "asia-east1");
  private static final JsonFactory JSON_FACTORY = GsonFactory.getDefaultInstance();

  @Test
  public void constructor_works() {
    HttpTransportFactory transportFactory = new MockHttpTransportFactory();
    TrustBoundaryInfo trustBoundaryInfo = new TrustBoundaryInfo(transportFactory);
    
    assertNotNull(trustBoundaryInfo);
    assertNull(trustBoundaryInfo.getAllowedLocations());
    assertNull(trustBoundaryInfo.getEncodedAllowedLocations());
  }
  
  @Test
  public void lookupTrustBoundary_nullLookupUrl_returnsNull() throws IOException {
    HttpTransportFactory transportFactory = new MockHttpTransportFactory();
    TrustBoundaryInfo trustBoundaryInfo = new TrustBoundaryInfo(transportFactory);
    
    GoogleCredentials credentials = GoogleCredentials.create(
        AccessToken.newBuilder().setTokenValue(TEST_ACCESS_TOKEN).build());
    
    assertNull(trustBoundaryInfo.lookupTrustBoundary(credentials, credentials.getAccessToken(), null));
  }
  
  @Test
  public void lookupTrustBoundary_validResponse_success() throws IOException {
    // Create a mock HTTP transport that returns a valid trust boundary response
    MockHttpTransport transport = new MockHttpTransport() {
      @Override
      public LowLevelHttpRequest buildRequest(String method, String url) throws IOException {
        return new MockLowLevelHttpRequest() {
          @Override
          public LowLevelHttpResponse execute() throws IOException {
            GenericJson responseJson = new GenericJson();
            responseJson.setFactory(JSON_FACTORY);
            responseJson.put("locations", TEST_LOCATIONS);
            responseJson.put("encodedLocations", TEST_ENCODED_LOCATIONS);
            
            MockLowLevelHttpResponse response = new MockLowLevelHttpResponse();
            response.setStatusCode(HttpStatusCodes.STATUS_CODE_OK);
            response.setContentType("application/json");
            response.setContent(responseJson.toString());
            return response;
          }
        };
      }
    };
    
    HttpTransportFactory transportFactory = () -> transport;
    TrustBoundaryInfo trustBoundaryInfo = new TrustBoundaryInfo(transportFactory);
    
    GoogleCredentials credentials = GoogleCredentials.create(
        AccessToken.newBuilder().setTokenValue(TEST_ACCESS_TOKEN).build());
    
    trustBoundaryInfo.lookupTrustBoundary(credentials, credentials.getAccessToken(), TEST_LOOKUP_URL);
    
    assertEquals(TEST_LOCATIONS, trustBoundaryInfo.getAllowedLocations());
    assertEquals(TEST_ENCODED_LOCATIONS, trustBoundaryInfo.getEncodedAllowedLocations());
  }
  
  @Test
  public void lookupTrustBoundary_invalidResponse_returnsNull() throws IOException {
    // Create a mock HTTP transport that returns an invalid response
    MockHttpTransport transport = new MockHttpTransport() {
      @Override
      public LowLevelHttpRequest buildRequest(String method, String url) throws IOException {
        return new MockLowLevelHttpRequest() {
          @Override
          public LowLevelHttpResponse execute() throws IOException {
            GenericJson responseJson = new GenericJson();
            responseJson.setFactory(JSON_FACTORY);
            // Missing required fields
            
            MockLowLevelHttpResponse response = new MockLowLevelHttpResponse();
            response.setStatusCode(HttpStatusCodes.STATUS_CODE_OK);
            response.setContentType("application/json");
            response.setContent(responseJson.toString());
            return response;
          }
        };
      }
    };
    
    HttpTransportFactory transportFactory = () -> transport;
    TrustBoundaryInfo trustBoundaryInfo = new TrustBoundaryInfo(transportFactory);
    
    GoogleCredentials credentials = GoogleCredentials.create(
        AccessToken.newBuilder().setTokenValue(TEST_ACCESS_TOKEN).build());
    
    assertNull(trustBoundaryInfo.lookupTrustBoundary(credentials, credentials.getAccessToken(), TEST_LOOKUP_URL));
  }
  
  @Test
  public void lookupTrustBoundary_invalidJson_returnsNull() throws IOException {
    // Create a mock HTTP transport that returns invalid JSON
    MockHttpTransport transport = new MockHttpTransport() {
      @Override
      public LowLevelHttpRequest buildRequest(String method, String url) throws IOException {
        return new MockLowLevelHttpRequest() {
          @Override
          public LowLevelHttpResponse execute() throws IOException {
            MockLowLevelHttpResponse response = new MockLowLevelHttpResponse();
            response.setStatusCode(HttpStatusCodes.STATUS_CODE_OK);
            response.setContentType("application/json");
            response.setContent("invalid json");
            return response;
          }
        };
      }
    };
    
    HttpTransportFactory transportFactory = () -> transport;
    TrustBoundaryInfo trustBoundaryInfo = new TrustBoundaryInfo(transportFactory);
    
    GoogleCredentials credentials = GoogleCredentials.create(
        AccessToken.newBuilder().setTokenValue(TEST_ACCESS_TOKEN).build());
    
    try {
      trustBoundaryInfo.lookupTrustBoundary(credentials, credentials.getAccessToken(), TEST_LOOKUP_URL);
      fail("Expected GoogleAuthException");
    } catch (GoogleAuthException e) {
      // Expected exception
    }
  }
  
  @Test
  public void lookupTrustBoundary_serverError_throwsException() throws IOException {
    // Create a mock HTTP transport that returns a server error
    MockHttpTransport transport = new MockHttpTransport() {
      @Override
      public LowLevelHttpRequest buildRequest(String method, String url) throws IOException {
        return new MockLowLevelHttpRequest() {
          @Override
          public LowLevelHttpResponse execute() throws IOException {
            MockLowLevelHttpResponse response = new MockLowLevelHttpResponse();
            response.setStatusCode(HttpStatusCodes.STATUS_CODE_SERVER_ERROR);
            return response;
          }
        };
      }
    };
    
    HttpTransportFactory transportFactory = () -> transport;
    TrustBoundaryInfo trustBoundaryInfo = new TrustBoundaryInfo(transportFactory);
    
    GoogleCredentials credentials = GoogleCredentials.create(
        AccessToken.newBuilder().setTokenValue(TEST_ACCESS_TOKEN).build());
    
    try {
      trustBoundaryInfo.lookupTrustBoundary(credentials, credentials.getAccessToken(), TEST_LOOKUP_URL);
      fail("Expected GoogleAuthException");
    } catch (GoogleAuthException e) {
      // Expected exception
    }
  }
  
  @Test
  public void lookupTrustBoundary_networkError_throwsException() throws IOException {
    // Create a mock HTTP transport that throws an IOException
    MockHttpTransport transport = new MockHttpTransport() {
      @Override
      public LowLevelHttpRequest buildRequest(String method, String url) throws IOException {
        return new MockLowLevelHttpRequest() {
          @Override
          public LowLevelHttpResponse execute() throws IOException {
            throw new IOException("Network error");
          }
        };
      }
    };
    
    HttpTransportFactory transportFactory = () -> transport;
    TrustBoundaryInfo trustBoundaryInfo = new TrustBoundaryInfo(transportFactory);
    
    GoogleCredentials credentials = GoogleCredentials.create(
        AccessToken.newBuilder().setTokenValue(TEST_ACCESS_TOKEN).build());
    
    try {
      trustBoundaryInfo.lookupTrustBoundary(credentials, credentials.getAccessToken(), TEST_LOOKUP_URL);
      fail("Expected GoogleAuthException");
    } catch (GoogleAuthException e) {
      // Expected exception
    }
  }
  
  @Test
  public void addTrustBoundaryToRequestMetadata_addsHeader() throws IOException {
    // Use mocked HTTP response and lookup to set the cached data
    MockHttpTransport transport = new MockHttpTransport() {
      @Override
      public LowLevelHttpRequest buildRequest(String method, String url) throws IOException {
        return new MockLowLevelHttpRequest() {
          @Override
          public LowLevelHttpResponse execute() throws IOException {
            GenericJson responseJson = new GenericJson();
            responseJson.setFactory(JSON_FACTORY);
            responseJson.put("locations", TEST_LOCATIONS);
            responseJson.put("encodedLocations", TEST_ENCODED_LOCATIONS);
            
            MockLowLevelHttpResponse response = new MockLowLevelHttpResponse();
            response.setStatusCode(HttpStatusCodes.STATUS_CODE_OK);
            response.setContentType("application/json");
            response.setContent(responseJson.toString());
            return response;
          }
        };
      }
    };
    
    HttpTransportFactory mockTransportFactory = () -> transport;
    TrustBoundaryInfo trustBoundaryInfo = new TrustBoundaryInfo(mockTransportFactory);
    
    GoogleCredentials credentials = GoogleCredentials.create(
        AccessToken.newBuilder().setTokenValue(TEST_ACCESS_TOKEN).build());
    
    trustBoundaryInfo.lookupTrustBoundary(credentials, credentials.getAccessToken(), TEST_LOOKUP_URL);
    
    // Test that the header is added to request metadata
    Map<String, List<String>> requestMetadata = new HashMap<>();
    trustBoundaryInfo.addTrustBoundaryToRequestMetadata(requestMetadata);
    
    assertTrue(requestMetadata.containsKey("x-goog-allowed-resources"));
    assertEquals(Collections.singletonList(TEST_ENCODED_LOCATIONS), requestMetadata.get("x-goog-allowed-resources"));
  }
  
  @Test
  public void addTrustBoundaryToRequestMetadata_nullMetadata_doesNotThrow() {
    HttpTransportFactory transportFactory = new MockHttpTransportFactory();
    TrustBoundaryInfo trustBoundaryInfo = new TrustBoundaryInfo(transportFactory);
    
    // Should not throw when metadata is null
    trustBoundaryInfo.addTrustBoundaryToRequestMetadata(null);
  }
  
  @Test
  public void clearCache_removesData() throws IOException {
    // Use mocked HTTP response and lookup to set the cached data
    MockHttpTransport transport = new MockHttpTransport() {
      @Override
      public LowLevelHttpRequest buildRequest(String method, String url) throws IOException {
        return new MockLowLevelHttpRequest() {
          @Override
          public LowLevelHttpResponse execute() throws IOException {
            GenericJson responseJson = new GenericJson();
            responseJson.setFactory(JSON_FACTORY);
            responseJson.put("locations", TEST_LOCATIONS);
            responseJson.put("encodedLocations", TEST_ENCODED_LOCATIONS);
            
            MockLowLevelHttpResponse response = new MockLowLevelHttpResponse();
            response.setStatusCode(HttpStatusCodes.STATUS_CODE_OK);
            response.setContentType("application/json");
            response.setContent(responseJson.toString());
            return response;
          }
        };
      }
    };
    
    HttpTransportFactory mockTransportFactory = () -> transport;
    TrustBoundaryInfo trustBoundaryInfo = new TrustBoundaryInfo(mockTransportFactory);
    
    GoogleCredentials credentials = GoogleCredentials.create(
        AccessToken.newBuilder().setTokenValue(TEST_ACCESS_TOKEN).build());
    
    trustBoundaryInfo.lookupTrustBoundary(credentials, credentials.getAccessToken(), TEST_LOOKUP_URL);
    
    // Verify data is present
    assertEquals(TEST_LOCATIONS, trustBoundaryInfo.getAllowedLocations());
    assertEquals(TEST_ENCODED_LOCATIONS, trustBoundaryInfo.getEncodedAllowedLocations());
    
    // Clear cache and verify data is removed
    trustBoundaryInfo.clearCache();
    
    assertNull(trustBoundaryInfo.getAllowedLocations());
    assertNull(trustBoundaryInfo.getEncodedAllowedLocations());
  }
  
  private static class MockHttpTransportFactory implements HttpTransportFactory {
    MockHttpTransport transport = new MockHttpTransport();

    @Override
    public MockHttpTransport create() {
      return transport;
    }
  }
} 