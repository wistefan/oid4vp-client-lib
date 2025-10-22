# OID4VP-Client-Library

[![License badge](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

A Client-Implementation of
the [OpenId for Verifiable Presentations(OpenID4VP) Same Device Flow](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#name-same-device-flow),
intended for usage by services engaging in Machine to Machine(m2m) interactions with services secured through OpenID4VP.

The library allows services to fulfill the roles of Wallet and End-User while interacting with the Verifier-Component,
by providing a starting point for the interaction(using
the [OAuth2 Authorization Endpoint](https://datatracker.ietf.org/doc/html/rfc6749#page-18)),
handling
the [Authorization Request](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#name-authorization-request)
and
responding with
an [Authorization Response](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#name-response)
containing the [Verifiable Presentation](https://www.w3.org/TR/vc-data-model-2.0/#verifiable-presentations).

## Maven

The library is available at maven central:

```xml

<dependency>
    <groupId>io.github.wistefan</groupId>
    <artifactId>oid4vp-client-lib</artifactId>
</dependency>
```

## Example usage

In order to participate in OpenID4VP exchanges, the client requires:

* access to [Verifiable Credentials](https://www.w3.org/TR/vc-data-model-2.0/)
* access to the Key and ID of the Credentials Holder

### Credentials Holder

In order to properly sign the Verifiable Presentations, the library requires the ID and the corresponding private-key to
be provided as [configuration](src/main/java/io/github/wistefan/oid4vp/config/HolderConfiguration.java):

```java
new HolderConfiguration(
    // id of the holder
    URI.create("did:key:zDnaehXH4gDLjLeWcACPyQX9TnvsKiQNt6KT7fdsfyW6fhEYA"),
    // key-id to be used in the token, depending on the type it might be the same as the holder-id 
                "did:key:zDnaehXH4gDLjLeWcACPyQX9TnvsKiQNt6KT7fdsfyW6fhEYA",
    // algorithm to be used for signing the token, needs to be supported by the private key
    JWEAlgorithm.ECDH_ES,
    // the private key to be used for signing
    privateKey
)
```

### Verifiable Credentials

The library expects access to Verifiable Credentials through an implementation of
the [CredentialsRepository](src/main/java/io/github/wistefan/oid4vp/credentials/CredentialsRepository.java).
It comes already with
the [FileSystemCredentialsRepository](src/main/java/io/github/wistefan/oid4vp/credentials/FileSystemCredentialsRepository.java),
expecting
providing credentials stored in a defined folder. The Repo-Implementation currently supports credentials of type "jwt"
and "sd-jwt".

## Usage

The [OID4VPClient](src/main/java/io/github/wistefan/oid4vp/OID4VPClient.java) as the central class provides the ```getAccessToken``` method as 
the central interaction point. In order to use it, the client can be setup as following:

```java
import io.github.wistefan.oid4vp.client.ClientResolver;
import io.github.wistefan.oid4vp.client.DidKeyClientResolver;
import io.github.wistefan.oid4vp.client.DidWebClientResolver;
import io.github.wistefan.oid4vp.client.X509SanDnsClientResolver;
import io.github.wistefan.oid4vp.config.HolderConfiguration;
import io.github.wistefan.oid4vp.config.RequestParameters;

import java.net.URI;
import java.net.http.HttpClient;
import java.util.List;
import java.util.Set;

// in order to have all key-types properly working(especially ED-25519), its recommended to provide a bouncycastle provider
// if only RSA and EC is required, this can be ommitted in most cases
Security.addProvider(new BouncyCastleProvider());

PrivateKey privateKey = loadPrivateKey("EC", "secret/private-key.pem");
HolderConfiguration holderConfiguration = new HolderConfiguration(
        URI.create("did:key:zDnaehXH4gDLjLeWcACPyQX9TnvsKiQNt6KT7fdsfyW6fhEYA"),
        "did:key:zDnaehXH4gDLjLeWcACPyQX9TnvsKiQNt6KT7fdsfyW6fhEYA",
        JWEAlgorithm.ECDH_ES,
        privateKey
);

// http client for interaction with the verifier
HttpClient httpClient = HttpClient.newHttpClient();

// provides serialization and deserialization capabilities to the client
ObjectMapper objectMapper = new ObjectMapper();
// configuration required to properly work with the DCQL-Library
// if the mapper is retrieved from the context, objectMapper.copy() is recommended to not interfer with the general config
objectMapper.setPropertyNamingStrategy(PropertyNamingStrategies.SNAKE_CASE);
SimpleModule deserializerModule = new SimpleModule();
deserializerModule.addDeserializer(CredentialFormat .class, new CredentialFormatDeserializer());
deserializerModule.addDeserializer(TrustedAuthorityType .class, new TrustedAuthorityTypeDeserializer());
objectMapper.registerModule(deserializerModule);

CredentialsRepository credentialsRepository = new FileSystemCredentialsRepository("/path/to/test-credentials", objectMapper);

// only instantiate the evaluators required
DCQLEvaluator dcqlEvaluator = new DCQLEvaluator(List.of(
        new JwtCredentialEvaluator(),
        new DcSdJwtCredentialEvaluator(),
        new VcSdJwtCredentialEvaluator(),
        new MDocCredentialEvaluator(),
        new LdpCredentialEvaluator()));

// service to sign the vp-token
SigningService signingService = new HolderSigningService(holderConfiguration, objectMapper);

// resolvers for the verifier's client id. Only instantiate the required once
List<ClientResolver> clientResolverList = List.of(new X509SanDnsClientResolver(), new DidWebClientResolver(httpClient, objectMapper), new DidKeyClientResolver());

OID4VPClient client = new OID4VPClient(httpClient, holderConfiguration, objectMapper, clientResolverList, dcqlEvaluator, credentialsRepository, signingService);

// request to be authorized
RequestParameters requestParameters = new RequestParameters(URI.create("https://my-secured-service.io"), "/some-sub-path", "secured-service", Set.of("openid", "read"));

// get the token
client.getAccessToken(requestParameters);
```

## Limitations

The library currently does not support [response encryption](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#name-encrypted-responses).

## License

OID4VP-Client-Library is licensed under the Apache License, Version 2.0. See [LICENSE](./LICENSE) for the full license text.

