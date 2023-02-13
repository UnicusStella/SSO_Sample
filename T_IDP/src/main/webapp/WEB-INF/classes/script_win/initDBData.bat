@echo off

set JAV_PATH=C:\java\jdk-1.6.0.45\bin
set CAT_PATH=C:\sw\tomcat-6.0.53\lib
set SSO_PATH=D:\work\tomcat-6.0.53\webapps\ssoserver\WEB-INF\lib

%JAV_PATH%\java -cp %SSO_PATH%\ldapjdk.jar;%SSO_PATH%\tibero6-jdbc.jar;%SSO_PATH%\mssql-jdbc-7.4.1.jre8.jar;%SSO_PATH%\mysql-connector-java-5.1.49.jar;%SSO_PATH%\postgresql-42.2.18.jre6.jar;%SSO_PATH%\JDBC-9.3.0.0206-cubrid.jar;%SSO_PATH%\MagicJCrypto-v2.0.0.0.jar;%SSO_PATH%\jcaos-1.4.9.6.jar;%SSO_PATH%\magicsso-server-4.0.0.3.jar;%SSO_PATH%\magicsso-svadd-4.0.0.3.jar;%CAT_PATH%\servlet-api.jar -Dfile.encoding=UTF-8 com.dreamsecurity.sso.server.config.InitDBData

set JAV_PATH=
set CAT_PATH=
set SSO_PATH=
