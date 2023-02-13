#!/bin/sh
CAT_PATH=/home/tomcat8.5.45/lib
SSO_PATH=/home/tomcat8.5.45/webapps/ssoagent/WEB-INF/lib

java -cp $SSO_PATH/MagicJCrypto-v2.0.0.0.jar:$SSO_PATH/jcaos-1.4.9.6.jar:$SSO_PATH/magicsso-agent-4.0.0.3.jar:$SSO_PATH/magicsso-agadd-4.0.0.3.jar:$CAT_PATH/servlet-api.jar -Dfile.encoding=UTF-8 com.dreamsecurity.sso.agent.config.InitConfig
