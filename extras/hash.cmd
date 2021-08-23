:::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
::                                                                           ::
:: Extract MD5/SHA256 hash of folders and files.                             ::
::                                                                           ::
:: Output format is different according to the chosen algorithm for          ::
:: remaining compatible with the NSRL files format.                          ::
::                                                                           ::
:: Usage:                                                                    ::
::     hash.cmd {md5|sha256}                                                 ::
::                                                                           ::
:::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::

@ECHO OFF

SETLOCAL ENABLEDELAYEDEXPANSION

SET arg=%1

IF [%1]==[] (
    CALL :POPUP_ERR "INVALID ARGUMENT" "Allowed parameters: MD5 or SHA256"
    EXIT /B
)

CALL :UPPERCASE arg

IF NOT %arg% == SHA256 (
    IF NOT %arg% == MD5 (
        CALL :POPUP_ERR "INVALID ARGUMENT" "Allowed parameters: MD5 or SHA256"
        EXIT /B
    )
)

:::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::

SET OS_VER=
SET TAB=
SET HASH_TYPE=%arg%

CALL :SET_TAB
CALL :SET_OSVERSION

:::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
:: Specify below your folders or files to be hashed.                         ::
:: Keep in mind that the folders browsing is NOT recursive                   ::
:::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::

CALL :ANALYZE_DIR "*.exe" "C:\Program Files\Internet Explorer"
CALL :ANALYZE_DIR "*.exe" "C:\Program Files\McAfee\Agent"
CALL :ANALYZE_DIR "*.exe" "C:\Program Files\McAfee\Endpoint Encryption"
CALL :ANALYZE_DIR "*.exe" "C:\Program Files\McAfee\Endpoint Encryption Agent"
CALL :ANALYZE_DIR "*.exe" "C:\Program Files\Microsoft Office\root\Office16"
CALL :ANALYZE_DIR "*.exe" "C:\Program Files\Mozilla Firefox"

CALL :ANALYZE_DIR "*.exe" "C:\Program Files (x86)\Google\Chrome\Application"
CALL :ANALYZE_DIR "*.exe" "C:\Program Files (x86)\Internet Explorer"
CALL :ANALYZE_DIR "*.exe" "C:\Program Files (x86)\Lenovo\System Update"
CALL :ANALYZE_DIR "*.exe" "C:\Program Files (x86)\Mozilla Maintenance Service"

CALL :ANALYZE_DIR "*.exe" C:\Windows
CALL :ANALYZE_DIR "*.exe" C:\Windows\System32

rem CALL :ANALYZE_FILE C:\Windows\System32\cmd.exe
rem CALL :ANALYZE_FILE C:\Windows\System32\cscript.exe
rem CALL :ANALYZE_FILE C:\Windows\System32\rundll32.exe
rem CALL :ANALYZE_FILE C:\Windows\System32\svchost.exe
rem CALL :ANALYZE_FILE C:\Windows\System32\wscript.exe

:::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::

EXIT /B


:::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
::                                                                           ::
::                                                                           ::
::                                                                           ::
:::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::


:POPUP
    PowerShell -Command "Add-Type -AssemblyName PresentationFramework;[System.Windows.MessageBox]::Show('%2','%1')"

    EXIT /B

:::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::

:POPUP_ERR
    PowerShell -Command "Add-Type -AssemblyName PresentationFramework;[System.Windows.MessageBox]::Show('%2','%1','OK', 'Stop')"

    EXIT /B

:::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::

:IS_VALID_HASH
    SET hash_str=%1
    SET hash_str_len=
    SET hash_len=32

    CALL :STRLEN %hash_str% hash_str_len

    IF %HASH_TYPE% == SHA256 (SET hash_len=64 )

    IF !hash_str_len! EQU %hash_len% (

        ECHO %hash_str%| findstr /r /i "^[A-F0-9]*$">nul

        IF %errorlevel% EQU 0 (
            SET %~2=1
        ) ELSE (
            SET %~2=0
        )

    ) ELSE (
        SET %~2=0)

    EXIT /B

:::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::

:UPPERCASE
    SET %~1=!%~1:a=A!
    SET %~1=!%~1:b=B!
    SET %~1=!%~1:c=C!
    SET %~1=!%~1:d=D!
    SET %~1=!%~1:e=E!
    SET %~1=!%~1:f=F!
    SET %~1=!%~1:g=G!
    SET %~1=!%~1:h=H!
    SET %~1=!%~1:i=I!
    SET %~1=!%~1:j=J!
    SET %~1=!%~1:k=K!
    SET %~1=!%~1:l=L!
    SET %~1=!%~1:m=M!
    SET %~1=!%~1:n=N!
    SET %~1=!%~1:o=O!
    SET %~1=!%~1:p=P!
    SET %~1=!%~1:q=Q!
    SET %~1=!%~1:r=R!
    SET %~1=!%~1:s=S!
    SET %~1=!%~1:t=T!
    SET %~1=!%~1:u=U!
    SET %~1=!%~1:v=V!
    SET %~1=!%~1:w=W!
    SET %~1=!%~1:x=X!
    SET %~1=!%~1:y=Y!
    SET %~1=!%~1:z=Z!

    EXIT /B

:::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::

:STRLEN
    SET "s=#%~1"
    SET "len=0"

    For %%N in (4096 2048 1024 512 256 128 64 32 16 8 4 2 1) do (
      IF "!s:~%%N,1!" neq "" (
        SET /a "len+=%%N"
        SET "s=!s:~%%N!"
      )
    )

    SET %~2=%len%

    EXIT /B

:::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::

:SET_TAB
    FOR /F "delims= " %%T IN ('robocopy /L . . /njh /njs') DO SET "TAB=%%T"

    EXIT /B

:::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::

:SET_OSVERSION
    FOR /F "tokens=4-7 delims=[.] " %%i IN ('ver') DO @(

        IF %%i==Version ( 
            SET OS_VER=%%j.%%k.%%l
        ) ELSE (
            SET OS_VER=%%i.%%j.%%k
        )

        SET OS_VER=!OS_VER: =!
    )

    EXIT /B

:::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::

:ANALYZE_DIR
    SET filter=%1
    SET current_folder=%2
    SET OLDDIR=%CD%

    IF NOT EXIST %current_folder%\ EXIT /B

    CD %current_folder%

    FOR %%G IN (%filter%) DO (

        SET current_folder=!current_folder:"=!

        CALL :ANALYZE_FILE "!current_folder!\%%G"
    )

    CD %OLDDIR%

    EXIT /B

:::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::

:ANALYZE_FILE
    SET current_file=%1

    IF NOT EXIST %current_file% EXIT /B

    SET count=1
    SET current_file=%current_file:"=%

    FOR /F "tokens=*" %%F IN ('certutil -hashfile "%current_file%" %HASH_TYPE%') DO (

        IF !count! EQU 2 (
            SET hash_str=%%F
            SET hash_str=!hash_str: =!
            SET ret=

            CALL :IS_VALID_HASH !hash_str! ret

            IF !ret! EQU 1 (

                CALL :UPPERCASE hash_str

                IF %HASH_TYPE% == SHA256 (
                    ECHO %OS_VER%%TAB%!hash_str!%TAB%"%current_file%"
                ) ELSE (
                    ECHO "%OS_VER%","!hash_str!","%current_file%"
                )
            )
        )

        SET /a count+=1 )

    EXIT /B
