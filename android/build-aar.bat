@echo off
:: Build the shared Go core into android\app\libs\libgsm.aar.
::
:: Prerequisites (one-time):
::   - Go 1.26.3+ and the Android NDK (Android Studio: SDK Manager -> NDK)
::   - set ANDROID_NDK_HOME=C:\path\to\ndk\<version>
::   - go install golang.org/x/mobile/cmd/gomobile@latest
::   - go install golang.org/x/mobile/cmd/gobind@latest
::   - gomobile init
setlocal
set HERE=%~dp0
set TUNNEL_DIR=%HERE%..\core-go\tunnel
set OUT=%HERE%app\libs\libgsm.aar

if not exist "%HERE%app\libs" mkdir "%HERE%app\libs"
echo Building libgsm.aar from core-go\tunnel ...
pushd "%TUNNEL_DIR%"
gomobile bind -target=android -androidapi 21 -o "%OUT%" .
if errorlevel 1 ( popd & echo BUILD FAILED & exit /b 1 )
popd
echo OK -^> %OUT%
echo Now open the android\ folder in Android Studio and build the app.
