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

import com.google.api.client.http.GenericUrl;
import com.google.api.client.http.HttpRequest;
import com.google.api.client.http.HttpRequestFactory;
import com.google.api.client.http.HttpResponse;
import com.google.api.client.json.GenericJson;
import com.google.api.client.json.JsonFactory;
import com.google.api.client.json.JsonObjectParser;
import com.google.api.client.util.Key;
import com.google.auth.http.HttpTransportFactory;
import com.google.common.annotations.VisibleForTesting;
import java.io.IOException;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;
import java.util.logging.Logger;
import javax.annotation.Nullable;

/**
 * Handles trust boundary information lookup and caching.
 *
 * <p>Trust boundaries define which regions an identity can access resources from. This class
 * provides methods to lookup, cache, and retrieve trust boundary information for a credential.
 */
public class TrustBoundaryInfo {

  private static final Logger LOGGER = Logger.getLogger(TrustBoundaryInfo.class.getName());
  private static final String ALLOWED_LOCATIONS_HEADER = "x-goog-allowed-resources";

  // Response structure for trust boundary lookup
  public static class TrustBoundaryResponse extends GenericJson {
    @Key("locations")
    private List<String> locations;

    @Key("encodedLocations")
    private String encodedLocations;

    public String getEncodedLocations() {
      return encodedLocations;
    }

    public void setEncodedLocations(String encodedLocations) {
      this.encodedLocations = encodedLocations;
    }
  }

  private final HttpTransportFactory transportFactory;
  private final OAuth2Credentials credentials;
  private final String lookupUrl;
  private final AtomicReference<TrustBoundaryResponse> cachedResponse = new AtomicReference<>();

  /**
   * Creates a new TrustBoundaryInfo instance with the given credentials and lookup URL.
   *
   * @param credentials The credentials to use for trust boundary lookups
   * @param transportFactory The HTTP transport factory to use for requests
   * @param lookupUrl The URL to use for trust boundary lookups
   */
  public TrustBoundaryInfo(
      OAuth2Credentials credentials, HttpTransportFactory transportFactory) {
    this.credentials = credentials;
    this.transportFactory = transportFactory;
    this.lookupUrl = credentials.getTrustBoundaryLookupEndpointUrl();
  }

  /**
   * Looks up trust boundary information for the credentials provided at initialization.
   *
   * @return The trust boundary response, or null if the lookup fails
   * @throws IOException If there is an error making the request
   */
  @Nullable
  public TrustBoundaryResponse lookupTrustBoundary() throws IOException {
    if (lookupUrl == null) {
      return null;
    }

    if (cachedResponse.get() != null) {
      return cachedResponse.get();
    }

    // Get the current access token from credentials
    AccessToken accessToken = credentials.getAccessToken();
    if (accessToken == null || accessToken.getTokenValue() == null) {
      LOGGER.warning("No access token available for trust boundary lookup");
      return null;
    }

    HttpRequestFactory requestFactory = transportFactory.create().createRequestFactory();
    HttpRequest request = requestFactory.buildGetRequest(new GenericUrl(lookupUrl));

    // Set up parser
    JsonFactory jsonFactory = OAuth2Utils.JSON_FACTORY;
    request.setParser(new JsonObjectParser(jsonFactory));

    // Add authorization header
    request.getHeaders().setAuthorization("Bearer " + accessToken.getTokenValue());

    try {
      HttpResponse response = request.execute();
      if (response.getStatusCode() == 200) {
        try {
          TrustBoundaryResponse trustBoundaryResponse = response.parseAs(TrustBoundaryResponse.class);
          
          // Check if the response contains the required fields
          if ((trustBoundaryResponse.locations == null || trustBoundaryResponse.locations.isEmpty()) && 
              trustBoundaryResponse.encodedLocations == null) {
            LOGGER.warning("Trust boundary response is missing required fields");
            return null;
          }
          
          cachedResponse.set(trustBoundaryResponse);
          return trustBoundaryResponse;
        } catch (IOException e) {
          // Handle JSON parsing errors
          LOGGER.warning("Failed to parse trust boundary response: " + e.getMessage());
          throw new GoogleAuthException(true, e);
        }
      } else {
        LOGGER.warning(
            "Trust boundary lookup failed with status code: " + response.getStatusCode());
      }
    } catch (IOException e) {
      LOGGER.warning("Trust boundary lookup failed: " + e.getMessage());
      throw new GoogleAuthException(true, e);
    }

    return null;
  }

  /**
   * Adds trust boundary information to the given request metadata if available.
   *
   * @param requestMetadata The request metadata to add trust boundary information to
   * @return The updated request metadata with trust boundary information
   */
  public Map<String, List<String>> addTrustBoundaryToRequestMetadata(Map<String, List<String>> requestMetadata) {
    TrustBoundaryResponse response = cachedResponse.get();

    Map<String, List<String>> newRequestMetadata = new HashMap<>(requestMetadata);
    if (response != null && response.getEncodedLocations() != null) {
      requestMetadata.put(
          ALLOWED_LOCATIONS_HEADER, java.util.Collections.singletonList(response.getEncodedLocations()));
    }
    return Collections.unmodifiableMap(newRequestMetadata);
  }

  /**
   * Returns the list of allowed locations from the trust boundary information.
   *
   * @return The list of allowed locations, or null if not available
   */
  @Nullable
  public List<String> getAllowedLocations() {
    TrustBoundaryResponse response = cachedResponse.get();
    return response != null ? response.locations : null;
  }

  /**
   * Returns the encoded allowed locations from the trust boundary information.
   *
   * @return The encoded allowed locations, or null if not available
   */
  @Nullable
  public String getEncodedAllowedLocations() {
    TrustBoundaryResponse response = cachedResponse.get();
    return response != null ? response.getEncodedLocations() : null;
  }

  /**
   * Clears the cached trust boundary information.
   */
  public void clearCache() {
    cachedResponse.set(null);
  }

  /**
   * Refreshes the trust boundary information using the current credentials.
   *
   * <p>This clears the cached response and performs a new lookup to ensure
   * the latest trust boundary information is retrieved.
   *
   * @throws IOException If there is an error retrieving the trust boundary information
   */
  public void refreshTrustBoundary() throws IOException {
    // Clear the cached response to force a fresh lookup
    cachedResponse.set(null);
    
    // Perform a new lookup with the current credentials
    lookupTrustBoundary();
  }
} 