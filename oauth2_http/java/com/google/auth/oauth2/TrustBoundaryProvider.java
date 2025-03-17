import java.io.IOException;

public interface TrustBoundaryProvider {
  /**
   * Returns the URL endpoint for trust boundary lookups
   */
  String getTrustBoundaryLookupEndpointUrl();

  /**
   * Returns the TrustBoundaryInfo instance for this credential
   */
  TrustBoundaryInfo getTrustBoundaryInfo();

  /**
   * Refreshes trust boundary information
   */
  void refreshTrustBoundary() throws IOException;
} 