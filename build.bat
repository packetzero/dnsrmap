set TOP=%cd%
set DIST=platform\win32-msvc2012

mkdir %DIST% 
cd %DIST%

REM @echo on

cmake -G "Visual Studio 11 2012" ..\..
msbuild -p:Configuration=Debug ZiftenDnsRMap.sln
REM msbuild -p:Configuration=Release ZDnsRMap.sln

