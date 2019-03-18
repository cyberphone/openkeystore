REM Create a test root CA using our eminent Java CA stuff...

java -cp ..\..\library\dist\webpki.org-libext-1.00.jar;..\third-party-jars\bcprov-jdk16-145.jar org.webpki.ca.CommandLineCA -selfsigned -entity/ca -subject "CN=Demo Root CA, dc=webpki,dc=org" -validity/start 2002-07-10T10:00:00 -validity/end 2030-07-10T09:59:59 -out/keystore rootca.jks -out/storepass testing -out/keypass testing -keysize 2048 -sigalg RSA_SHA256 -serial 1
keytool -export -v -keystore rootca.jks -storepass testing -file rootca.cer
keytool -list -v -keystore rootca.jks -storepass testing

java -cp ..\..\library\dist\webpki.org-libext-1.00.jar;..\third-party-jars\bcprov-jdk16-145.jar org.webpki.ca.CommandLineCA -ca/addpath all -ca/keypass testing -ca/storepass testing -ca/keystore rootca.jks -entity/ca -subject "CN=Demo Sub CA, dc=webpki,dc=org" -validity/start 2005-07-10T10:00:00 -validity/end 2025-07-10T09:59:59 -out/keystore subca.jks -out/storepass testing -out/keypass testing -keysize 2048 -sigalg RSA_SHA256 -serial 200
keytool -export -v -keystore subca.jks -storepass testing -file subca.cer
keytool -list -v -keystore subca.jks -storepass testing

java -cp ..\..\library\dist\webpki.org-libext-1.00.jar;..\third-party-jars\bcprov-jdk16-145.jar org.webpki.ca.CommandLineCA -ca/addpath all -ca/keypass testing -ca/storepass testing -ca/keystore subca.jks -entity/ee -subject "CN=example.com,O=Example Organization,C=US" -validity/start 2012-01-01T00:00:00 -validity/end 2025-07-10T09:59:59 -out/keystore example.jks -out/storepass testing -out/keypass testing  -sigalg RSA_SHA256 -ecccurve NIST_P_256
keytool -export -v -keystore example.jks -storepass testing -file example.cer
keytool -list -v -keystore example.jks -storepass testing

java -cp ..\..\library\dist\webpki.org-libext-1.00.jar;..\third-party-jars\bcprov-jdk16-145.jar org.webpki.ca.CommandLineCA -ca/addpath 1 -ca/keypass testing -ca/storepass testing -ca/keystore subca.jks -entity/ee -subject "CN=Marion Anderson, SERIALNUMBER=19750710-1518" -validity/start 2012-01-01T00:00:00 -validity/end 2025-07-10T09:59:59 -out/keystore marion.jks -out/storepass testing -out/keypass testing  -sigalg RSA_SHA256 -ecccurve NIST_P_256
keytool -export -v -keystore marion.jks -storepass testing -file marion.cer
keytool -list -v -keystore marion.jks -storepass testing

java -cp ..\..\library\dist\webpki.org-libext-1.00.jar;..\third-party-jars\bcprov-jdk16-145.jar org.webpki.ca.CommandLineCA -ca/addpath all -ca/keypass testing -ca/storepass testing -ca/keystore subca.jks -entity/ee -subject " CN=secure.mybank.com, O=My Bank" -validity/start 2012-01-01T00:00:00 -validity/end 2025-07-10T09:59:59 -out/keystore mybank.jks -out/storepass testing -out/keypass testing  -sigalg RSA_SHA256 -keysize 2048
keytool -export -v -keystore mybank.jks -storepass testing -file mybank.cer
keytool -list -v -keystore mybank.jks -storepass testing


