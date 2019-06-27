Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunONce" -Name "NextStep" -Force -Confirm:$false

$bat = @(
    "Registry::\HKEY_CLASSES_ROOT\Installer\Products\0EE540D3694D7224A962B266E54C968A",
    "Registry::\HKEY_CLASSES_ROOT\Installer\Products\0F82903D025B36A4AA4A3FB9F015C1B6",
    "Registry::\HKEY_CLASSES_ROOT\Installer\Products\12AB68C719520A4428500EE06CC4EB2E",
    "Registry::\HKEY_CLASSES_ROOT\Installer\Products\1524B761A56D68E42BD5F44AED57D5CB",
    "Registry::\HKEY_CLASSES_ROOT\Installer\Products\1F7C4C552DF7FE343AE49CC3847311D2",
    "Registry::\HKEY_CLASSES_ROOT\Installer\Products\220331102F3A02646AC9B303DDEFFC30",
    "Registry::\HKEY_CLASSES_ROOT\Installer\Products\275344964DA94804D897CBD91B7AB340",
    "Registry::\HKEY_CLASSES_ROOT\Installer\Products\281D213DCD7929749BA8F812525E240D",
    "Registry::\HKEY_CLASSES_ROOT\Installer\Products\2D46B22BB385D1F45A33EE9619F3EFEC",
    "Registry::\HKEY_CLASSES_ROOT\Installer\Products\33F458D220195584BA7C2F32CF1CBB72",
    "Registry::\HKEY_CLASSES_ROOT\Installer\Products\4092D2D56E67A714CB481FEC81A83F65",
    "Registry::\HKEY_CLASSES_ROOT\Installer\Products\447D5F725BE37FA49A5E8CC51EAB2993",
    "Registry::\HKEY_CLASSES_ROOT\Installer\Products\4905B15AD97054C4B9093DF8DBE661F0",
    "Registry::\HKEY_CLASSES_ROOT\Installer\Products\4CE6B0B0EFC060841802B4BEDDC5AF64",
    "Registry::\HKEY_CLASSES_ROOT\Installer\Products\507D8DD28DFF78B4C9ECB7300244AFD5",
    "Registry::\HKEY_CLASSES_ROOT\Installer\Products\552B97FEF430D8B46B81AA5D43805E97",
    "Registry::\HKEY_CLASSES_ROOT\Installer\Products\5CD0D4782F187854282D91C9FDBF54EF",
    "Registry::\HKEY_CLASSES_ROOT\Installer\Products\5CFA1FB474BC84A4C90FAD53A0487485",
    "Registry::\HKEY_CLASSES_ROOT\Installer\Products\670F66CD9F75EE24D8AEB0C396FE4145",
    "Registry::\HKEY_CLASSES_ROOT\Installer\Products\6B0C8CD2094CB4A41A2D075EF8A07D27",
    "Registry::\HKEY_CLASSES_ROOT\Installer\Products\6C4565625BDBFA649A99CB84486A43CA",
    "Registry::\HKEY_CLASSES_ROOT\Installer\Products\6FC2949BD950C5F44BA34C0732C054CF",
    "Registry::\HKEY_CLASSES_ROOT\Installer\Products\75C7FD1C38BA8CB42B1A8BBB90FE73C5",
    "Registry::\HKEY_CLASSES_ROOT\Installer\Products\75EC2E788D0650747800DC62D19BF844",
    "Registry::\HKEY_CLASSES_ROOT\Installer\Products\7816A77FD8133E74DAF127A0297EAFF6",
    "Registry::\HKEY_CLASSES_ROOT\Installer\Products\78B1321F70D750F4A953F9C27705C9C1",
    "Registry::\HKEY_CLASSES_ROOT\Installer\Products\83A797D244F7C3B4F8E9683E0FD31D11",
    "Registry::\HKEY_CLASSES_ROOT\Installer\Products\850E69DC6552A4147AD14E1C3362FADC",
    "Registry::\HKEY_CLASSES_ROOT\Installer\Products\87547F62582190C4080C9201C653B7DF",
    "Registry::\HKEY_CLASSES_ROOT\Installer\Products\884431EC979AC444A8FE5CBAD1633436",
    "Registry::\HKEY_CLASSES_ROOT\Installer\Products\89BCFC71F093A9D48ACD8355B033D8BF",
    "Registry::\HKEY_CLASSES_ROOT\Installer\Products\8F2B530453A15974FBFBC9A83E365FBB",
    "Registry::\HKEY_CLASSES_ROOT\Installer\Products\8FABDFC440764764CAEFFDCC859C6A8D",
    "Registry::\HKEY_CLASSES_ROOT\Installer\Products\9622A7C075EB80540AF62F6003BD1BCE",
    "Registry::\HKEY_CLASSES_ROOT\Installer\Products\979C81EC57E9AA94C83B594C1496499A",
    "Registry::\HKEY_CLASSES_ROOT\Installer\Products\9961FA4833EDBE84BA2FEF869F2AF11B",
    "Registry::\HKEY_CLASSES_ROOT\Installer\Products\A394301E077BE9943AC67C713FD6A168",
    "Registry::\HKEY_CLASSES_ROOT\Installer\Products\AFD9D628CBF1D51459EA03D9410C522C",
    "Registry::\HKEY_CLASSES_ROOT\Installer\Products\B211916280DC1D1419C38EB8C9426839",
    "Registry::\HKEY_CLASSES_ROOT\Installer\Products\B4444FA74A1D2A44DAFA04313E8CC140",
    "Registry::\HKEY_CLASSES_ROOT\Installer\Products\B46412E5800605748AC607ED311B765D",
    "Registry::\HKEY_CLASSES_ROOT\Installer\Products\B597886CEDCA56042A099721F5891C24",
    "Registry::\HKEY_CLASSES_ROOT\Installer\Products\B8CA8C94D28365C4C8B71CEAA6EDF255",
    "Registry::\HKEY_CLASSES_ROOT\Installer\Products\BFB608DFAA334954082A6118D9FC3859",
    "Registry::\HKEY_CLASSES_ROOT\Installer\Products\C07BC708D51E11347A40AC44FCD0F0E7",
    "Registry::\HKEY_CLASSES_ROOT\Installer\Products\C24CE56EBB502234085177F958100942",
    "Registry::\HKEY_CLASSES_ROOT\Installer\Products\C3BCA729167A9904894ACA34B14A0D40",
    "Registry::\HKEY_CLASSES_ROOT\Installer\Products\D02D31FEB1FD19A42807D76B84B0C29B",
    "Registry::\HKEY_CLASSES_ROOT\Installer\Products\D0BA5E38B21844940968A0934BD6263D",
    "Registry::\HKEY_CLASSES_ROOT\Installer\Products\D418DA1707B01394EBFEA9F38703CB9B",
    "Registry::\HKEY_CLASSES_ROOT\Installer\Products\D799291D404BD58439A02446BBE27353",
    "Registry::\HKEY_CLASSES_ROOT\Installer\Products\D88655B0829CCE249832EA42B9AB7CB7",
    "Registry::\HKEY_CLASSES_ROOT\Installer\Products\E0DC56801F90AAA4BBCAF2F94632A77A",
    "Registry::\HKEY_CLASSES_ROOT\Installer\Products\E1C41A1FD7EDD8E42A934DF6D4311D29",
    "Registry::\HKEY_CLASSES_ROOT\Installer\Products\E39335F8BFAC24E4E8B6F9E11A62D5FC",
    "Registry::\HKEY_CLASSES_ROOT\Installer\Products\E6A647FC39FE11D4796F684FA7399135",
    "Registry::\HKEY_CLASSES_ROOT\Installer\Products\EFDF2EBC1F51C9141918E652CEB5E3DC",
    "Registry::\HKEY_CLASSES_ROOT\Installer\Products\F0415451BE21FB54EBB2E8CA9BBCBD0C",
    "Registry::\HKEY_CLASSES_ROOT\Installer\Products\FC95049193921A04EBF4AC60D6B4ED8F"
)

$bat | % {If (Test-Path $_) { Remove-Item $_ -Recurse -Force -Confirm:$false }}

$keys = @{
    'AZDC01' = "7795-79A8-4931-CFDB"
    'AZHV02' = "1082-A77C-D606-A1A0"
    'AZSCAN01' = "7795-79A8-4931-CFDB"
    'AZEXCH01' = "1082-A77C-D606-A1A0"
    'DSH-GM' = "CC1F-A2F4-4FE2-9BAA"
    'DAC02' = "C6A3-BD62-0915-85F8"
    'DACDC01' = "C6A3-BD62-0915-85F8"
    'ECSDC01' = "1942-11D1-DFCF-604F"
    'ECSGS01' = "C91E-D29A-C966-68DA"
    'GVDDC01' = "38AB-256D-E91F-6412"
    'HLDC-001' = "13C1-A3B5-9854-564F"
    'LGIDC01' = "F307-66EA-5F71-7BFA"
    'MSICW02' = "F0CF-0504-1E28-449D"
    'MSIDC01' = "F02F-232A-E415-F67C"
    'NCHASQL01' = "72B5-92A1-D409-35BA"
    'OSANTDC01' = "1DAC-2823-B8E0-B1D0"
    'DCSRV02' = "3A7E-5334-430B-94D4"
    'EXCHSRV01' = "3A81-F6E3-2B3F-E881"
    'FPSRV' = "3A86-1AC1-DED9-FBC1"
    'SSRV' = "3A7E-4C24-D7DD-3A95"
    'TSRV' = "3A7F-856B-E648-8A9F"
    'UCDC01' = "0F8B-E77B-51F3-D623"
    'WAREDC01' = "DC96-5ECF-390E-E69D"
}

$key = $keys["$($env:COMPUTERNAME)"]

$args = @(
    "/i"
    ('"{0}"' -f "C:\Users\Public\spx_6.8.2.msi")
    "/qn"
    "IACCEPT=STORAGECRAFT.EULA"
)

If ($null -ne $key) {
    $args += "KEY=$key"
}

Start-Process "msiexec.exe" -ArgumentList $args -Wait -NoNewWindow
