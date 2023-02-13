#!/bin/sh
CAT_PATH=/home/tomcat8.5.45/lib
SSO_PATH=/home/tomcat8.5.45/webapps/ssoserver/WEB-INF/lib

java -cp $SSO_PATH/ldapjdk.jar:$SSO_PATH/tibero6-jdbc.jar:$SSO_PATH/mssql-jdbc-7.4.1.jre8.jar:$SSO_PATH/mysql-connector-java-5.1.49.jar:$SSO_PATH/postgresql-42.2.18.jre6.jar:$SSO_PATH/JDBC-9.3.0.0206-cubrid.jar:$SSO_PATH/MagicJCrypto-v2.0.0.0.jar:$SSO_PATH/jcaos-1.4.9.6.jar:$SSO_PATH/magicsso-server-4.0.0.3.jar:$SSO_PATH/magicsso-svadd-4.0.0.3.jar:$CAT_PATH/servlet-api.jar -Dfile.encoding=UTF-8 com.dreamsecurity.sso.server.config.InitSSO
