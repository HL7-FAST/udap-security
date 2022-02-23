package org.hl7.davinci.priorauth.authorization;

import java.util.HashMap;
import java.util.Map;
import java.util.Date;
import java.util.logging.Logger;
import java.util.UUID;
import java.util.Base64;
import java.io.FileInputStream;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.interfaces.RSAPublicKey;
import java.security.interfaces.RSAPrivateKey;


import javax.servlet.http.HttpServletRequest;

import org.hl7.davinci.priorauth.App;
import org.hl7.davinci.priorauth.endpoint.Endpoint;
import org.hl7.davinci.priorauth.PALogger;
import org.json.simple.JSONObject;
import org.json.JSONArray;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;

@CrossOrigin
@RestController
@RequestMapping("/.well-known")
public class WellKnownEndpoint {
   
    static final Logger logger = PALogger.getLogger();

    @GetMapping(value = "smart-configuration", produces = {MediaType.APPLICATION_JSON_VALUE})
    public ResponseEntity<String> smartConfiguration(HttpServletRequest request) {
        logger.info("GET /.well-known/smart-configuration");
        App.setBaseUrl(Endpoint.getServiceBaseUrl(request));

        Map<String, Object> response = new HashMap<>();
        response.put("registration_endpoint", App.getBaseUrl() + "/auth/register");
        response.put("token_endpoint", App.getBaseUrl() + "/auth/token");
        response.put("response_types_supported", "token");
        response.put("scopes_supported", AuthUtils.getSupportedScopes());

        return ResponseEntity.status(HttpStatus.OK).body(JSONObject.toJSONString(response));
    }
    @GetMapping(value = "udap", produces = {MediaType.APPLICATION_JSON_VALUE})
    public ResponseEntity<String> udap(HttpServletRequest request) throws Exception {
        logger.info("GET /.well-known/udap");
        App.setBaseUrl(Endpoint.getServiceBaseUrl(request));

        Map<String, Object> response = new HashMap<>();
        JSONArray udap_versions_supported = new JSONArray();
        udap_versions_supported.put("1");
        response.put("udap_versions_supported", udap_versions_supported);
        JSONArray scopes_supported = new JSONArray();
        scopes_supported.put("openid");
        scopes_supported.put("udap");
        scopes_supported.put("Patient.*");
        response.put("scopes_supported", scopes_supported);
        response.put("registration_endpoint", App.getBaseUrl() + "/auth/register");
        response.put("authorization_endpoint", App.getBaseUrl() + "/auth/authorization");
        response.put("token_endpoint", App.getBaseUrl() + "/auth/token");
        JSONArray token_endpoint_auth_methods_supported = new JSONArray();
        token_endpoint_auth_methods_supported.put("private_key_jwt");
        response.put("token_endpoint_auth_methods_supported", token_endpoint_auth_methods_supported);

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
        String signed_metadata_jwt = JWT.create()
        .withIssuer(App.getBaseUrl())
        .withSubject(App.getBaseUrl())
        .withExpiresAt(new Date(new Date().getTime() + 86400000))
        .withIssuedAt(new Date())
        .withJWTId(UUID.randomUUID().toString())
        .withHeader(headerClaims)
        .withClaim("registration_endpoint", App.getBaseUrl() + "/auth/register")
        .withClaim("authorization_endpoint", App.getBaseUrl() + "/auth/authorization")
        .withClaim("token_endpoint", App.getBaseUrl() + "/auth/token")
        .sign(algorithmRS);

        response.put("signed_metadata", signed_metadata_jwt);
        return ResponseEntity.status(HttpStatus.OK).body(JSONObject.toJSONString(response));

    }
}
