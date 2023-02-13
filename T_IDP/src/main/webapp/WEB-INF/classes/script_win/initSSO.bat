@echo off

set JAV_PATH="C:\Program Files\Java\jre1.8.0_361\bin"
set CAT_PATH=C:\Users\stella\Desktop\Directory\(WAS)_Tomcat\lib
set SSO_PATH=C:\Users\stella\Desktop\Sample\T_IDP\src\main\webapp\WEB-INF\lib
set SSS=C:\Users\stella\Desktop\Sample\T_IDP\build\classes

%JAV_PATH%\java -cp %SSS%;%SSO_PATH%\ldapjdk.jar;%SSO_PATH%\tibero6-jdbc.jar;%SSO_PATH%\mssql-jdbc-7.4.1.jre8.jar;%SSO_PATH%\mysql-connector-java-5.1.49.jar;%SSO_PATH%\postgresql-42.2.18.jre6.jar;%SSO_PATH%\JDBC-9.3.0.0206-cubrid.jar;%SSO_PATH%\MagicJCrypto-v2.0.0.0.jar;%SSO_PATH%\jcaos-arcCert-1.5.3.5.jar;%SSO_PATH%\magicsso-server-4.0.0.3.jar;%SSO_PATH%\magicsso-svadd-4.0.0.3.jar;%CAT_PATH%\servlet-api.jar -Dfile.encoding=UTF-8 com.dreamsecurity.sso.server.config.InitSSO

set JAV_PATH=
set CAT_PATH=
set SSO_PATH=
