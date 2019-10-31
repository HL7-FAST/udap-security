package org.hl7.davinci.priorauth;

import java.util.logging.Level;
import java.util.logging.Logger;

import org.hl7.davinci.priorauth.Endpoint.RequestType;
import org.hl7.fhir.instance.model.api.IBaseResource;
import org.hl7.fhir.r4.model.Bundle;
import org.hl7.fhir.r4.model.Claim;
import org.hl7.fhir.r4.model.ClaimResponse;
import org.hl7.fhir.r4.model.OperationOutcome;
import org.hl7.fhir.r4.model.ResourceType;
import org.hl7.fhir.r4.model.StringType;
import org.hl7.fhir.r4.model.Bundle.BundleEntryComponent;
import org.hl7.fhir.r4.model.Claim.ClaimStatus;
import org.hl7.fhir.r4.model.Subscription.SubscriptionStatus;

public class FhirUtils {

  static final Logger logger = PALogger.getLogger();

  /**
   * Enum for the ClaimResponse Disposition field Values are Granted, Denied,
   * Partial, Pending, and Cancelled
   */
  public enum Disposition {
    GRANTED("Granted"), DENIED("Denied"), PARTIAL("Partial"), PENDING("Pending"), CANCELLED("Cancelled"),
    UNKNOWN("Unknown");

    private final String value;

    Disposition(String value) {
      this.value = value;
    }

    public String value() {
      return this.value;
    }
  }

  /**
   * Enum for the ClaimResponse.item reviewAction extensions used for X12 HCR01
   * Responde Code. Codes taken from X12 and CMS
   * http://www.x12.org/x12org/subcommittees/X12N/N0210_4010MultProcedures.pdf
   * https://www.cms.gov/Research-Statistics-Data-and-Systems/Computer-Data-and-Systems/ESMD/Downloads/esMD_X12_278_09_2016Companion_Guide.pdf
   */
  public enum ReviewAction {
    APPROVED("A1"), PARTIAL("A2"), DENIED("A3"), PENDED("A4"), CANCELLED("A6");

    private final String value;

    ReviewAction(String value) {
      this.value = value;
    }

    public StringType value() {
      return new StringType(this.value);
    }
  }

  /**
   * Internal function to get the correct status from a resource depending on the
   * type
   *
   * @param resource - the resource.
   * @return - the status of the resource.
   */
  public static String getStatusFromResource(IBaseResource resource) {
    String status;
    if (resource instanceof Claim) {
      Claim claim = (Claim) resource;
      status = claim.getStatus().getDisplay();
    } else if (resource instanceof ClaimResponse) {
      ClaimResponse claimResponse = (ClaimResponse) resource;
      status = claimResponse.getStatus().getDisplay();
    } else if (resource instanceof Bundle) {
      status = "valid";
    } else {
      status = "unkown";
    }
    status = status.toLowerCase();
    return status;
  }

  /**
   * Internal function to get the Patient ID from the Patient Reference.
   *
   * @param resource - the resource.
   * @return String - the Patient ID.
   */
  public static String getPatientIdFromResource(IBaseResource resource) {
    String patient = "";
    try {
      String patientReference = null;
      if (resource instanceof Claim) {
        Claim claim = (Claim) resource;
        patientReference = claim.getPatient().getReference();
      } else if (resource instanceof ClaimResponse) {
        ClaimResponse claimResponse = (ClaimResponse) resource;
        patientReference = claimResponse.getPatient().getReference();
      } else if (resource instanceof Bundle) {
        Bundle bundle = (Bundle) resource;
        Claim claim = (Claim) bundle.getEntryFirstRep().getResource();
        patient = FhirUtils.getPatientIdFromResource(claim);
      } else {
        return patient;
      }
      String[] patientParts = patientReference.split("/");
      patient = patientParts[patientParts.length - 1];
      logger.info("FhirUtils::getPatientIdFromResource(patient: " + patientParts[patientParts.length - 1] + ")");
    } catch (Exception e) {
      logger.log(Level.SEVERE, "FhirUtils::getPatientIdFromResource(error processing patient)", e);
    }
    return patient;
  }

  /**
   * Convert the response disposition into a review action
   * 
   * @param disposition - the response disposition
   * @return corresponding ReviewAction for the Disposition
   */
  public static ReviewAction dispositionToReviewAction(Disposition disposition) {
    if (disposition == Disposition.DENIED)
      return ReviewAction.DENIED;
    else if (disposition == Disposition.GRANTED)
      return ReviewAction.APPROVED;
    else if (disposition == Disposition.PARTIAL)
      return ReviewAction.PARTIAL;
    else if (disposition == Disposition.PENDING)
      return ReviewAction.PENDED;
    else if (disposition == Disposition.CANCELLED)
      return ReviewAction.CANCELLED;
    else
      return null;
  }

  /**
   * Find the first instance of a ClaimResponse in a bundle
   * 
   * @param bundle - the bundle search through for the ClaimResponse
   * @return ClaimResponse in the bundle or null if not found
   */
  public static ClaimResponse getClaimResponseFromBundle(Bundle bundle) {
    ClaimResponse claimResponse = null;
    for (BundleEntryComponent bec : bundle.getEntry()) {
      if (bec.getResource().getResourceType() == ResourceType.ClaimResponse)
        return (ClaimResponse) bec.getResource();
    }

    return claimResponse;
  }

  /**
   * Find the BundleEntryComponent in a Bundle where the resource has the desired
   * id
   * 
   * @param bundle - the bundle to search through
   * @param id     - the resource id to match
   * @return BundleEntryComponent in Bundle with resource matching id
   */
  public static BundleEntryComponent getEntryComponentFromBundle(Bundle bundle, String id) {
    for (BundleEntryComponent entry : bundle.getEntry()) {
      if (entry.getResource().getId().equals(id)) {
        return entry;
      }
    }
    return null;
  }

  /**
   * Return the id of a resource
   * 
   * @param resource - the resource to get the id from
   * @return the id of the resource
   */
  public static String getIdFromResource(IBaseResource resource) {
    if (resource.getIdElement().hasIdPart())
      return resource.getIdElement().getIdPart();
    return null;
  }

  /**
   * Convert a FHIR resource into JSON.
   * 
   * @param resource - the resource to convert to JSON.
   * @return String - the JSON.
   */
  public static String json(IBaseResource resource) {
    String json = App.FHIR_CTX.newJsonParser().setPrettyPrint(true).encodeResourceToString(resource);
    return json;
  }

  /**
   * Convert a FHIR resource into XML.
   * 
   * @param resource - the resource to convert to XML.
   * @return String - the XML.
   */
  public static String xml(IBaseResource resource) {
    String xml = App.FHIR_CTX.newXmlParser().setPrettyPrint(true).encodeResourceToString(resource);
    return xml;
  }

  /**
   * Format the resource status in a standard way for the database
   * 
   * @param status - the status
   * @return standard string representation of the status
   */
  public static String formatResourceStatus(Object status) {
    if (status instanceof ClaimStatus)
      return ((ClaimStatus) status).getDisplay().toLowerCase();
    else if (status instanceof SubscriptionStatus)
      return ((SubscriptionStatus) status).getDisplay().toLowerCase();
    return "error";
  }

  /**
   * Format a resource into JSON or XML string
   * 
   * @param resource    - the resource to convert
   * @param requestType - the type to represent it as
   * @return JSON or XML string representation of the resource
   */
  public static String getFormattedData(IBaseResource resource, RequestType requestType) {
    return requestType == RequestType.JSON ? FhirUtils.json(resource) : FhirUtils.xml(resource);
  }

  /**
   * Create a FHIR OperationOutcome.
   *
   * @param severity The severity of the result.
   * @param type     The issue type.
   * @param message  The message to return.
   * @return OperationOutcome - the FHIR resource.
   */
  public static OperationOutcome buildOutcome(OperationOutcome.IssueSeverity severity, OperationOutcome.IssueType type,
      String message) {
    OperationOutcome error = new OperationOutcome();
    OperationOutcome.OperationOutcomeIssueComponent issue = error.addIssue();
    issue.setSeverity(severity);
    issue.setCode(type);
    issue.setDiagnostics(message);
    return error;
  }
}
