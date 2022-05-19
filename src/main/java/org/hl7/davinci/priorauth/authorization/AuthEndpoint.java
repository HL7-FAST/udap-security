package org.hl7.davinci.priorauth.authorization;

import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;
import java.util.ArrayList;
import java.util.Date;
import java.util.Base64;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.io.FileInputStream;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.interfaces.RSAPublicKey;
import java.security.interfaces.RSAPrivateKey;

import javax.naming.directory.InvalidAttributeValueException;
import javax.servlet.http.HttpServletRequest;
import javax.transaction.NotSupportedException;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;

import org.hl7.davinci.priorauth.App;
import org.hl7.davinci.priorauth.Audit;
import org.hl7.davinci.priorauth.endpoint.Endpoint;
import org.hl7.davinci.priorauth.PALogger;
import org.hl7.davinci.priorauth.Audit.AuditEventOutcome;
import org.hl7.davinci.priorauth.Audit.AuditEventType;
import org.hl7.davinci.priorauth.Database.Table;
import org.hl7.fhir.r4.model.ContactPoint;
import org.hl7.fhir.r4.model.Organization;
import org.hl7.fhir.r4.model.AuditEvent.AuditEventAction;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;
import org.springframework.http.CacheControl;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.view.RedirectView;



import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;

@CrossOrigin
@RestController
@RequestMapping("/auth")
public class AuthEndpoint {

    static final Logger logger = PALogger.getLogger();
    static final SecureRandom random = new SecureRandom();

    static final String INVALID_REQUEST = "invalid_request";
    static final String INVALID_CLIENT = "invalid_client";
    
    // for test purposes only, dummy id
    static final String CLIENT_ID = "FOOBAR";

    @GetMapping(value = "/authorize")
    public RedirectView authorize(HttpServletRequest request,
            @RequestParam(name = "scope", required = true) String scope,
            @RequestParam(name = "state", required = true) String state,
            @RequestParam(name = "client_id", required = true) String client_id,
            @RequestParam(name = "idp", required = false) String idp,
            @RequestParam(name = "username", required = false) String username,
            @RequestParam(name = "redirect_uri", required = true) String redirect_uri) {
        logger.warning("We at the start");
        App.setBaseUrl(Endpoint.getServiceBaseUrl(request));
        if (idp != null) {
            logger.warning("We're in the IDP reroute");
            String idps = App.getDB().readString(Table.IDPID, Collections.singletonMap("url", idp), "url");
            String idp_client_id = "";
            if (idps != null && !idps.equals("null")) {
                logger.warning("I'm here, idp is " + idps);
                idp_client_id = App.getDB().readString(Table.IDPID, Collections.singletonMap("url", idp), "client_id");
                String idp_state = UUID.randomUUID().toString();
                Map<String, Object> idp_state_object = new HashMap<>();
                idp_state_object.put("id", UUID.randomUUID().toString());
                idp_state_object.put("client_id", idp_client_id);
                idp_state_object.put("url", idps);
                idp_state_object.put("scope", scope);
                idp_state_object.put("state", idp_state);
                App.getDB().write(Table.STATE, idp_state_object);
                Map<String, Object> holder_state_object = new HashMap<>();
                holder_state_object.put("id", UUID.randomUUID().toString());
                holder_state_object.put("client_id", client_id);
                holder_state_object.put("state", state);
                App.getDB().write(Table.STATE, holder_state_object);
                String idp_uri_with_params = new String(idp + "/authorize?response_type=code");
                idp_uri_with_params = idp_uri_with_params + "&state=" + idp_state;
                idp_uri_with_params = idp_uri_with_params + "&client_id=" + idp_client_id;
                idp_uri_with_params = idp_uri_with_params + "&scope=openid+udap";
                idp_uri_with_params = idp_uri_with_params + "&redirect_uri=" + Endpoint.getServiceBaseUrl(request) + "/auth/redirect";
                logger.warning("idp URI: " + idp_uri_with_params);
                RedirectView redirectView = new RedirectView();
                redirectView.setUrl(idp_uri_with_params);
                return redirectView;
            }
        }
        else if (scope.contains("openid") && scope.contains("udap")) {
            if (authenticateUser(username)) {
                logger.warning("We're at the IDP");
                RedirectView redirectView = new RedirectView();
                String auth_code = UUID.randomUUID().toString();
                Map<String, Object> code_object = new HashMap<>();
                code_object.put("id", UUID.randomUUID().toString());
                code_object.put("client_id", client_id);
                code_object.put("code", auth_code);
                App.getDB().write(Table.AUTHCODE, code_object);
                String redirect_uri_with_params = redirect_uri + "?code=" + auth_code;
                redirect_uri_with_params = redirect_uri_with_params + "&state=" + state;
                redirectView.setUrl(redirect_uri_with_params);
                return redirectView;
            }
        }
        return null;
    }


    @GetMapping(value = "/redirect")
    public RedirectView redirect(HttpServletRequest request,
    @RequestParam(name = "code", required = true) String code,
    @RequestParam(name = "state", required = true) String state) throws Exception {
        App.setBaseUrl(Endpoint.getServiceBaseUrl(request));
        if (stateIsValid(state)) {
            String idp_id = App.getDB().readString(Table.STATE, Collections.singletonMap("state", state), "client_id");
            String idp_url = App.getDB().readString(Table.STATE, Collections.singletonMap("state", state), "url");
            String scope = App.getDB().readString(Table.STATE, Collections.singletonMap("state", state), "scope");
            String redirect_uri_with_params = idp_url + "/token?";
            redirect_uri_with_params = redirect_uri_with_params + "grant_type=authorization_code";
            redirect_uri_with_params = redirect_uri_with_params + "&code=" + code;
            redirect_uri_with_params = redirect_uri_with_params + "&client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer&";
            redirect_uri_with_params = redirect_uri_with_params + "&scope=system/*.read";

            FileInputStream is = new FileInputStream("pas_keystore.p12");

            KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());
            keystore.load(is, "udap-test".toCharArray());
        
            String alias = "pas";
            Key key = keystore.getKey(alias, "udap-test".toCharArray());
            // if (key instanceof PrivateKey) {
                // Get certificate of public key
            Certificate cert = keystore.getCertificate(alias);
    
                // Get public key
            RSAPublicKey publicKey = (RSAPublicKey) cert.getPublicKey();
    
                // Return a key pair
            // }
            RSAPrivateKey privateKey = (RSAPrivateKey) key;
            Algorithm algorithmRS = Algorithm.RSA256(publicKey, privateKey);
            Map<String, Object> headerClaims = new HashMap();
            headerClaims.put("alg", "rs256");
            String x5c_certs[] = {new String(Base64.getEncoder().encode(cert.getEncoded()))};
            // logger.info("format: " + cert.getType());
            headerClaims.put("x5c", x5c_certs);
            headerClaims.put("kid", alias);
            String signed_assertion_jwt = JWT.create()
            .withIssuer(App.getBaseUrl()+"/auth")
            .withSubject(idp_id)
            .withAudience(idp_url+"/token")
            .withExpiresAt(new Date(new Date().getTime() + 86400000))
            .withIssuedAt(new Date())
            .withJWTId(UUID.randomUUID().toString())
            .withHeader(headerClaims)
            .sign(algorithmRS);
            redirect_uri_with_params = redirect_uri_with_params + "&client_assertion=" + signed_assertion_jwt;
            logger.info("redirect uri: " + redirect_uri_with_params);
            OkHttpClient client = new OkHttpClient();
            Request token_request = new Request.Builder().url(redirect_uri_with_params).header("Content-Type", "application/x-www-form-urlencoded").post(RequestBody.create("", null)).build();
            try (Response response = client.newCall(token_request).execute()) {
                String answer = response.body().string();
                logger.info("response? " + answer);
                // JSONObject jsnobject = new JSONObject(answer);
            } catch (Exception e) {
                logger.info(
                        "ERROR: could not obtain token from IDP");
                logger.log(Level.SEVERE, "Unknown exception occurred", e);
                return null;
            }
            RedirectView redirectView = new RedirectView();
            redirectView.setUrl(redirect_uri_with_params);
            return redirectView;
        }
        return null;
    }

    @PostMapping(value = "/register", consumes = { MediaType.APPLICATION_JSON_VALUE, "application/fhir+json" })
    public ResponseEntity<String> registerClient(HttpServletRequest request, HttpEntity<String> entity) {
        App.setBaseUrl(Endpoint.getServiceBaseUrl(request));
        HttpStatus status = HttpStatus.INTERNAL_SERVER_ERROR;
        String body = entity.getBody();
        String clientId = UUID.randomUUID().toString();
        String formattedData = "{ client_id: \"" + clientId + "\" }";
        try {
            // Read the body
            JSONObject jsonObject = (JSONObject) new JSONParser().parse(body);
            status = HttpStatus.BAD_REQUEST;
            JSONObject jwks = (JSONObject) jsonObject.get("jwks");
            String jwksUrl = (String) jsonObject.get("jwks_url");
            String name = (String) jsonObject.get("organization_name");
            String contact = (String) jsonObject.get("organization_contact");

            if ((jwks != null || jwksUrl != null) && name != null && contact != null) {
                status = HttpStatus.OK;

                Organization organization = new Organization();
                organization.setId(clientId);
                organization.setName(name);
                ContactPoint telecom = new ContactPoint();
                telecom.setValue(contact);
                organization.setTelecom(Collections.singletonList(telecom));

                // Add the new client to the database
                HashMap<String, Object> dataMap = new HashMap<>();
                dataMap.put("id", clientId);
                dataMap.put("jwks", jwks != null ? jwks.toJSONString() : null);
                dataMap.put("jwks_url", jwksUrl);
                dataMap.put("organization", organization);
                App.getDB().write(Table.CLIENT, dataMap);
            } else {
                status = HttpStatus.BAD_REQUEST;
                formattedData = "{ error: \"Body malformed. Must include jwks or jwks_url, organization_name, and organization_contact\" }";
            }
        } catch (ParseException e) {
            logger.log(Level.SEVERE, "AuthEndpoint::registerClient:Unable to parse body\n" + body, e);
        }

        return ResponseEntity.status(status).contentType(MediaType.APPLICATION_JSON)
                .body(formattedData);
    }

    @PostMapping(value = "/token")
    public ResponseEntity<String> token(HttpServletRequest request,
            @RequestParam(name = "scope", required = true) String scope,
            @RequestParam(name = "code", required = true) String code,
            @RequestParam(name = "grant_type", required = true) String grantType,
            @RequestParam(name = "client_assertion_type", required = true) String clientAssertionType,
            @RequestParam(name = "client_assertion", required = true) String token) {
        logger.info("IN TOKEN!!!!!");
        App.setBaseUrl(Endpoint.getServiceBaseUrl(request));
        final String requestQueryParams = "scope=" + scope + "&grant_type=" + grantType + "&client_assertion_type="
                + clientAssertionType + "&client_assertion=" + token;
        logger.info("AuthEndpoint::token:" + requestQueryParams);

        // Check client_credentials
        if (!grantType.equals("authorization_code")) {
            String message = "Invalid grant_type " + grantType + ". Must be authorization_code";
            logger.warning("AuthEndpoint::token:" + message);
            Audit.createAuditEvent(AuditEventType.REST, AuditEventAction.E, AuditEventOutcome.MAJOR_FAILURE, null, request, "POST /token" + requestQueryParams);
            return sendError(INVALID_REQUEST, message);
        }

        // Check client_assertion_type
        if (!clientAssertionType.equals("urn:ietf:params:oauth:client-assertion-type:jwt-bearer")) {
            String message = "Invalid client_assertion_type " + clientAssertionType + ". Must be urn:ietf:params:oauth:client-assertion-type:jwt-bearer";
            logger.warning("AuthEndpoint::token:" + message);
            Audit.createAuditEvent(AuditEventType.REST, AuditEventAction.E, AuditEventOutcome.MAJOR_FAILURE, null, request, "POST /token" + requestQueryParams);
            return sendError(INVALID_REQUEST, message);
        }

        // Check scope
        String[] requestedScopes = scope.split(" ");
        for(String requestedScope : requestedScopes) {
            if (!AuthUtils.getSupportedScopes().contains(requestedScope)) {
                String message = "requested scope " + requestedScope + " is not supported";
                logger.warning("AuthEndpoint::token:" + message);
                Audit.createAuditEvent(AuditEventType.REST, AuditEventAction.E, AuditEventOutcome.MAJOR_FAILURE, null, request, "POST /token" + requestQueryParams);
                return sendError(INVALID_REQUEST, message);
            }
        }

        String[] jwtParts = token.split("\\.");
        if (jwtParts.length != 3) {
            Audit.createAuditEvent(AuditEventType.REST, AuditEventAction.E, AuditEventOutcome.MAJOR_FAILURE, null, request, "POST /token" + requestQueryParams);
            return sendError(INVALID_REQUEST, "client_assertion is not a valid jwt token");
        }

        String clientId = "unknown";
        String jwtHeaderRaw = new String(Base64.getUrlDecoder().decode(jwtParts[0]));
        logger.info("jwtHeader: " + jwtHeaderRaw);
        String jwtBodyRaw = new String(Base64.getUrlDecoder().decode(jwtParts[1]));
        logger.info("jwtBody: " + jwtBodyRaw);
        try {
            JSONObject jwtHeader = (JSONObject) new JSONParser().parse(jwtHeaderRaw);
            JSONObject jwtBody = (JSONObject) new JSONParser().parse(jwtBodyRaw);
            String alg = (String) jwtHeader.get("alg");
            String kid = (String) jwtHeader.get("kid");
            String iss = (String) jwtBody.get("iss");
            clientId = iss;
            logger.info("AuthEndpoint::alg:" + alg + " kid:" + kid + " iss: " + iss);

            if (!alg.equals("RS256")) {
                // if (!alg.equals("RS384") || !alg.equals("EC384")) {
                return sendError(INVALID_REQUEST, "JWT algorithm not supported. Must be RS256 or EC384 (currently unsupported).");
            }

            // Get keys and validate signature
            JSONObject jwks = getJwks(iss);

            List<RSAPublicKey> keys = getKeys(jwks, kid);
            logger.info("key list has length: " + keys.size());
            boolean verified = false;
            for (RSAPublicKey publicKey : keys) {
                logger.info("in the loop!");
                if (tokenIsValid(token, publicKey, iss)) {
                    verified = true;
                    break;
                }
            }
            if (!verified)
                throw new JWTVerificationException("None of the provided jwk validated the client_assertion");
        } catch (ParseException e) {
            logger.log(Level.SEVERE, "AuthEndpoint::Parse Exception decoding jwt", e);
            Audit.createAuditEvent(AuditEventType.REST, AuditEventAction.E, AuditEventOutcome.MAJOR_FAILURE, null, request, "POST /token" + requestQueryParams);
            return sendFailure();
        } catch (NoSuchAlgorithmException e) {
            logger.log(Level.SEVERE, "AuthEndpoint::No Such Algorithm Exception verifying jwt", e);
            Audit.createAuditEvent(AuditEventType.REST, AuditEventAction.E, AuditEventOutcome.MAJOR_FAILURE, null, request, "POST /token" + requestQueryParams);
            return sendFailure();
        } catch (InvalidKeySpecException e) {
            logger.log(Level.SEVERE, "AuthEndpoint::Invalid Key Spec Exception verifying jwt", e);
            Audit.createAuditEvent(AuditEventType.REST, AuditEventAction.E, AuditEventOutcome.MAJOR_FAILURE, null, request, "POST /token" + requestQueryParams);
            return sendFailure();
        } catch (InvalidAttributeValueException e) {
            Audit.createAuditEvent(AuditEventType.REST, AuditEventAction.E, AuditEventOutcome.MAJOR_FAILURE, null, request, "POST /token" + requestQueryParams);
            return sendError(INVALID_CLIENT, "No client registered with that id (" + clientId + "). Please register first");
        } catch (JWTVerificationException e) {
            Audit.createAuditEvent(AuditEventType.REST, AuditEventAction.E, AuditEventOutcome.MAJOR_FAILURE, null, request, "POST /token" + requestQueryParams);
            return sendError(INVALID_CLIENT, "Could not verify client using any of the keys in the jwk set");
        } catch (Exception e) {
            Audit.createAuditEvent(AuditEventType.REST, AuditEventAction.E, AuditEventOutcome.MAJOR_FAILURE, null, request, "POST /token" + requestQueryParams);
            logger.log(Level.SEVERE, "Unknown exception occurred", e);
            return sendError(INVALID_CLIENT, "Could not verify client.");
        }

        // Verification was successful - authorize
        final String authToken = generateAuthToken();

        if (clientId != null)
            App.getDB().update(Table.CLIENT, Collections.singletonMap("id", clientId),
                    Collections.singletonMap("token", authToken));

        Audit.createAuditEvent(AuditEventType.REST, AuditEventAction.E, AuditEventOutcome.SUCCESS, null, request, "POST /token" + requestQueryParams);

        // Create response
        Map<String, Object> response = new HashMap<>();
        response.put("access_token", authToken);
        response.put("token_type", "bearer");
        response.put("expires_in", AuthUtils.TOKEN_LIFE_MIN * 60);
        response.put("scope", "system/*.read");
        return ResponseEntity.status(HttpStatus.OK).contentType(MediaType.APPLICATION_JSON)
                .cacheControl(CacheControl.noStore()).header("Pragma", "no-cache")
                .body(JSONObject.toJSONString(response));
    }


    private static boolean authenticateUser(String username) {
        return true;
    }

    private static boolean stateIsValid(String state) {
        return true;
    }
    /**
     * Generate a new auth token using SecureRandom
     * 
     * @return authorization token
     */
    private static String generateAuthToken() {
        byte[] bytes = new byte[15];
        random.nextBytes(bytes);
        return Base64.getEncoder().encodeToString(bytes);
    }

    /**
     * Create a new ResponseEntity representing an error response
     * (https://tools.ietf.org/html/rfc6749#page-45)
     * 
     * @param error       - the error type
     * @param description - brief description of the error
     * @return BAD REQUEST error response
     */
    private static ResponseEntity<String> sendError(String error, String description) {
        Map<String, String> map = new HashMap<>();
        map.put("error", error);
        map.put("error_description", description);
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).contentType(MediaType.APPLICATION_JSON)
                .body(JSONObject.toJSONString(map));
    }

    /**
     * Create a new ResponseEntity for an internal server error
     * 
     * @return INTERNAL SERVER ERROR response (no body)
     */
    private static ResponseEntity<String> sendFailure() {
        return new ResponseEntity<>(HttpStatus.INTERNAL_SERVER_ERROR);
    }

    /**
     * Get the jwk store for the given client from when they registered
     * 
     * @param clientId - the id of the client to get the jwks
     * @return jwk store for the client or exception
     * @throws ParseException                 JSON Parse error
     * @throws InvalidAttributeValueException No jwks or jwks_url for the given
     *                                        client id
     * @throws NotSupportedException          RI does not support jwks_url right now
     * @throws IOException
     */
    private static JSONObject getJwks(String clientId) throws ParseException, IOException, InvalidAttributeValueException {
        String jwks = App.getDB().readString(Table.CLIENT, Collections.singletonMap("id", clientId), "jwks");
        logger.info("jwks: " + jwks);
        // String[] json_jwks = jwks.substring(1,jwks.length()-1).split(", ");
        // for (int i=0; i< json_jwks.length; i++) {
        //     // json_jwsk[i]
        //     logger.info(json_jwks[i]);
        //     String[] keyPair = json_jwks[i].split("=");
        //     keyPair[0] = "\"" + keyPair[0] + "\"";
        //     keyPair[1] = "\"" + keyPair[1] + "\"";
        //     json_jwks[i] = keyPair[0] + ": " + keyPair[1];
        // }
        jwks = "{\"keys\": [" + jwks + "]}";
        // logger.info("new jwks: " + jwks);
        if (jwks == null || jwks.equals("null")) {
            logger.info("something went wrong");
            String jwksUrl = App.getDB().readString(Table.CLIENT, Collections.singletonMap("id", clientId),
                    "jwks_url");
            if (jwksUrl == null) throw new InvalidAttributeValueException();
            OkHttpClient client = new OkHttpClient();
            okhttp3.Response response = client.newCall(new Request.Builder().get().url(jwksUrl).build()).execute();
            if (response.isSuccessful()) jwks = response.body().string();
            else throw new InvalidAttributeValueException();
        }

        // Convert to JSONObject
        return (JSONObject) new JSONParser().parse(jwks);
    }

    /**
     * Get keys which match kid from jwks
     * 
     * @param jwks - the jwk store
     * @param kid  - the key id to match
     * @return List of RSA Public Keys from the jwk store which match kid
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException
     */
    private static List<RSAPublicKey> getKeys(JSONObject jwks, String kid)
            throws NoSuchAlgorithmException, InvalidKeySpecException {
        // TODO: Support EC384 keys
        RSAPublicKeySpec publicKeySpec;
        KeyFactory kf = KeyFactory.getInstance("RSA");
        List<RSAPublicKey> validKeys = new ArrayList<>();
        
        // Iterate over all the keys in the jwk set
        JSONArray keys = (JSONArray) jwks.get("keys");
        for (Object i : keys) {
            JSONObject key = (JSONObject) i;
            String keyId = (String) key.get("kid");
            if (keyId.equals(kid)) {
                String eRaw = (String) key.get("e");
                String nRaw = (String) key.get("n");
                BigInteger e = new BigInteger(1, Base64.getUrlDecoder().decode(eRaw));
                BigInteger n = new BigInteger(1, Base64.getUrlDecoder().decode(nRaw));
                publicKeySpec = new RSAPublicKeySpec(n, e);
                validKeys.add((RSAPublicKey) kf.generatePublic(publicKeySpec));
            }
        }

        return validKeys;
    }

    /**
     * Validate a token
     * 
     * @param token     - the token to be validated
     * @param publicKey - RSA Public Key used to check token signature
     * @param clientId  - the client id who issued this token
     * @return true if the token is valid, false otherwise
     */
    private static boolean tokenIsValid(String token, RSAPublicKey publicKey, String clientId) {
        try {
            logger.info("checking if token: " + token + " is valid");
            Algorithm algorithm = Algorithm.RSA256(publicKey, null);
            JWTVerifier verifier = JWT.require(algorithm).withSubject(clientId)
                    .withAudience(App.getBaseUrl() + "/auth/token").build();
            verifier.verify(token);
        } catch (Exception e) {
            return false;
        }
        return true;
    }
}
