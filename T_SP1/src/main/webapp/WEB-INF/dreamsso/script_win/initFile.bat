@echo off

set JAV_PATH=C:\java\jdk-1.6.0.45\bin
set CAT_PATH=C:\sw\tomcat-6.0.53\lib
set SSO_PATH=D:\work\tomcat-6.0.53\webapps\ssoagent\WEB-INF\lib

%JAV_PATH%\java -cp %SSO_PATH%\MagicJCrypto-v2.0.0.0.jar;%SSO_PATH%\jcaos-1.4.9.6.jar;%SSO_PATH%\magicsso-agent-4.0.0.3.jar;%SSO_PATH%\magicsso-agadd-4.0.0.3.jar;%CAT_PATH%\servlet-api.jar -Dfile.encoding=UTF-8 com.dreamsecurity.sso.agent.config.InitFile

set JAV_PATH=
set CAT_PATH=
set SSO_PATH=
