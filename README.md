# UDAP Security Reference Implementation

The Da Vinci Prior Authorization Reference Implementation (RI) is a software project that conforms to the [UDAP Security Implementation Guide (IG)](http://build.fhir.org/ig/HL7/fhir-udap-security-ig/) developed by the [ONC FAST Project](https://oncprojectracking.healthit.gov/wiki/pages/viewpage.action?pageId=43614268).

## Requirements

- Java JDK 11

## Getting Started

Build, test, and start the Prior Authorization microservice:

```
./gradlew installBootDist
./gradlew clean check
./gradlew bootRun
```

To run the microservice in debug mode (which enables debug log statements, an endpoint to view the database, and and endpoint to prefill the database with test data) use:

```
./gradlew bootRun --args='debug'
```

## Configuration Notes

The server on the `dev` branch is always configured to run on Logicahealth. If you are running locally or on another cloud server there are a few extra configuration steps:

1. This server expects to be running on HTTPS. If you are not using SSL the authorization will fail. Either follow the steps under "SSL Certificates" below to add SSL to your local version, or modify `getServiceBaseUrl()` in `Endpoint.java` to use `http`.
2. The default tokenUri points to LogicaHealth. Update `tokenUri` in `Metadata.java` to be the correct host.

## Docker

Build the docker image:

```
docker build -t hspc/udap-security:latest .
```

Run the docker image:

```
docker run -p 9000:9000 -it --rm --name udap-security hspc/udap-security:latest
```

If you are building the docker image locally from a MITRE machine you must copy over the BA Certificates to the Docker image. Download the `MITRE BA NPE CA-3` and `MITRE BA ROOT` certs from the [MII](http://www2.mitre.org/tech/mii/pki/). Copy the two files to the root directory of this project.

Build and run using:

```
docker build -f Dockerfile.mitre -t mitre/udap-security .
docker run -p 9000:9000 -it --rm --name udap-security mitre/udap-security
```

