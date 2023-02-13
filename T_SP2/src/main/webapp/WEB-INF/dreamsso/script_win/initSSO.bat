@echo off

set JAV_PATH="C:\Program Files\Java\jre1.8.0_361\bin"
set CAT_PATH=C:\Users\stella\Desktop\Directory\(WAS)_Tomcat\lib
set SSO_PATH=C:\Users\stella\Desktop\Sample\T_SP2\src\main\webapp\WEB-INF\lib
set SSS=C:\Users\stella\Desktop\Sample\T_SP2\build\classes

%JAV_PATH%\java -cp %SSS%;%SSO_PATH%\MagicJCrypto-v2.0.0.0.jar;%SSO_PATH%\jcaos-1.4.9.6.jar;%SSO_PATH%\magicsso-agent-4.0.0.3.jar;%SSO_PATH%\magicsso-agadd-4.0.0.3.jar;%CAT_PATH%\servlet-api.jar -Dfile.encoding=UTF-8 com.dreamsecurity.sso.agent.config.InitSSO

set JAV_PATH=
set CAT_PATH=
set SSO_PATH=
