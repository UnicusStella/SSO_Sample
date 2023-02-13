#!/bin/sh
CAT_PATH=/home/tomcat8.5.45
SSO_PATH=/home/tomcat8.5.45/webapps/ssoagent/WEB-INF

java -cp $SSO_PATH/lib/MagicJCrypto-v2.0.0.0.jar:$SSO_PATH/lib/jcaos-1.4.9.6.jar:$SSO_PATH/lib/magicsso-agent-4.0.0.3.jar:$CAT_PATH/lib/servlet-api.jar com.dreamsecurity.sso.agent.config.InitStart $1 $SSO_PATH/dreamsso/cert/TEST_SP1_Enc.der
