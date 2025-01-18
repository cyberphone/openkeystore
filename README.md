# openkeystore
TEE Key Store and Credential Provisioning System

This project defines SKS (Secure Key Store) which can hold X.509 certificates
and symmetric keys as well as associated attributes such as logotypes, key ACLs and URLs:<br>
https://cyberphone.github.io/doc/security/sks-api-arch.pdf

The project also defines KeyGen2 which is a credential provisioning and management system
for SKS:<br>
https://cyberphone.github.io/doc/security/keygen2.html

## JSON Support
The JSON library supports a clear text signature system called JSF:<br>
https://cyberphone.github.io/doc/security/jsf.html<br>
as well as a "matching" encryption scheme coined JEF:<br>
https://cyberphone.github.io/doc/security/jef.html

## CBOR Support
The CBOR library also supports signatures and encryption:<br>
https://cyberphone.github.io/javaapi/org/webpki/cbor/package-summary.html

## Requirements
* Java SDK Version 21 or later
* Ant 1.10.8 or later
* The projects are being developed using VS Code but there's no dependence on VS Code.

Currently only the "library" project is suitable for public use.
To create the openkeystore library, perform the following steps:
```
$ cd library
$ ant build
```
It is recommendable running the following JUnit tests as well:
```
$ ant testsks
$ ant testkeygen2
$ ant testjson
$ ant testcbor
```
## API
Now you should have a file <code>library/dist/webpki.org-libext-1.00.jar</code> which
implements the API described in https://cyberphone.github.io/javaapi/overview-summary.html.
## Proof of Concept Implementation
There also is an Android proof-of-concept implementation which allows you to test provisioning
and then using provisioned keys for authentication:<br>
https://play.google.com/store/apps/details?id=org.webpki.mobile.android

## Android JSON, JOSE/JWS, JSF, and JEF support
To create a source distribution for Android perform:
```
$ cd library
$ ant android-json
```
Now you should have a file <code>library/dist/android.json.zip</code> which can be imported in an Android project.

An Android demo/test project is available at:<br>
https://github.com/cyberphone/android-json

## Android CBOR, CSF, and CEF support
To create a source distribution for Android perform:
```
$ cd library
$ ant android-cbor
```
Now you should have a file <code>library/dist/android.cbor.zip</code> which can be imported in an Android project.

An Android demo/test project is available at:<br>
https://github.com/cyberphone/android-cbor
