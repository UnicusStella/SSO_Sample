#!/bin/sh
CAT_PATH=/home/tomcat8.5.45
SSO_PATH=/home/tomcat8.5.45/webapps/ssoserver/WEB-INF

java -cp $SSO_PATH/tibero6-jdbc.jar:$SSO_PATH/mssql-jdbc-7.4.1.jre8.jar:$SSO_PATH/mysql-connector-java-5.1.49.jar:$SSO_PATH/postgresql-42.2.18.jre6.jar:$SSO_PATH/JDBC-9.3.0.0206-cubrid.jar:$SSO_PATH/lib/MagicJCrypto-v2.0.0.0.jar:$SSO_PATH/lib/jcaos-1.4.9.6.jar:$SSO_PATH/lib/magicsso-server-4.0.0.3.jar:$CAT_PATH/lib/servlet-api.jar com.dreamsecurity.sso.server.config.InitStart $1 $SSO_PATH/classes/cert/TEST_IDP_Enc.der
