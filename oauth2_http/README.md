# Google Auth Library - OAuth2 HTTP Module (`google-auth-library-oauth2-http`)

This module is a core component of the Google Auth Library for Java. It provides implementations for various OAuth2 credential types and the mechanisms to authenticate to Google Cloud services and other Google APIs.

## Overview

The `google-auth-library-oauth2-http` module enables authentication using:

*   **Application Default Credentials (ADC):** Automatically finds credentials in various environments (e.g., environment variables, gcloud SDK, Compute Engine, App Engine, Cloud Shell).
*   **Service Account Credentials:** Authenticates as a service account using a private key (JSON or PKCS8). Supports JWT signing for token acquisition and can be used for domain-wide delegation.
*   **User Credentials:** Authenticates as an end-user, typically using a refresh token obtained from an OAuth2 consent flow.
*   **Compute Engine Credentials:** Fetches credentials from the Google Compute Engine metadata server.
*   **App Engine Credentials:** Fetches credentials in the Google App Engine environment.
*   **Impersonated Credentials:** Allows a service account or user to impersonate another service account.
*   **External Account Credentials (Workload Identity Federation & Workforce Identity Federation):**
    *   **Identity Pool Credentials:** Authenticates using credentials from external identity providers (IdPs) that support OpenID Connect (OIDC) or SAML 2.0, by exchanging a third-party token for a Google access token via the Security Token Service (STS). This includes file-sourced, URL-sourced, and executable-sourced subject tokens.
    *   **AWS Credentials:** A specialized flow for authenticating workloads running on Amazon Web Services (AWS) by exchanging AWS credentials for Google access tokens.
    *   **Pluggable Auth Credentials:** Enables authentication using an external executable to provide a third-party subject token.

## Key Features

*   **Token Management:** Handles OAuth2 access token fetching and automatic refresh.
*   **ID Tokens:** Provides capabilities to obtain Google ID tokens for services that require them (e.g., Cloud Run, Cloud Functions).
*   **HTTP Transport Integration:** Designed to work seamlessly with HTTP client libraries for making authenticated API calls.
*   **Quota Project ID:** Supports specifying a project ID for quota and billing purposes.
*   **Universe Domain Support:** Allows configuration for different Google Cloud universe domains.

## Usage

This module is typically used as a transitive dependency when you include other Google Cloud client libraries or the `google-auth-library-bom`.

For detailed information on how to configure and use these credentials, please refer to the main [README.md](../../README.md) in the root of this repository, particularly the sections on:

*   [Application Default Credentials](../../README.md#application-default-credentials)
*   [Workload Identity Federation](../../README.md#workload-identity-federation)
*   [Workforce Identity Federation](../../README.md#workforce-identity-federation)
*   [Downscoping with Credential Access Boundaries](../../README.md#downscoping-with-credential-access-boundaries) (features like `DownscopedCredentials` are part of this module).

### Example: Obtaining Application Default Credentials

```java
import com.google.auth.oauth2.GoogleCredentials;
import java.io.IOException;

// ...

try {
    GoogleCredentials credentials = GoogleCredentials.getApplicationDefault();
    // Use the credentials to authorize API calls
    // For example, with google-api-client:
    // HttpRequestInitializer requestInitializer = new HttpCredentialsAdapter(credentials);
    // Bigquery bigquery = new Bigquery.Builder(new NetHttpTransport(), new GsonFactory(), requestInitializer)
    //     .setApplicationName("YourApplicationName")
    //     .build();
} catch (IOException e) {
    // Handle credential loading errors
    e.printStackTrace();
}
```

For specific credential types like `ServiceAccountCredentials`, `UserCredentials`, etc., you can often load them directly from a file or by using their respective builders. Check the Javadoc for each class for detailed instantiation instructions.
