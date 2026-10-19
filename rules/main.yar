rule EICAR_Test_File
{
    meta:
        description = "Standard EICAR Anti-Virus Test File"
        score = 100
        author = "Standard"
    strings:
        $eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    condition:
        $eicar
}

rule Suspicious_PDF_JavaScript
{
    meta:
        description = "Detects PDF files with embedded JavaScript (/JS or /JavaScript)"
        score = 60
        author = "SecureScan"
    strings:
        $pdf_magic = { 25 50 44 46 } // %PDF
        $js1 = "/JS"
        $js2 = "/JavaScript"
    condition:
        $pdf_magic at 0 and ($js1 or $js2)
}

rule Suspicious_PDF_OpenAction
{
    meta:
        description = "Detects PDF files with an automatic OpenAction"
        score = 40
        author = "SecureScan"
    strings:
        $pdf_magic = { 25 50 44 46 }
        $action = "/OpenAction"
    condition:
        $pdf_magic at 0 and $action
}

rule Suspicious_Office_Macro
{
    meta:
        description = "Detects MS Office files with embedded VBA Macros"
        score = 50
        author = "SecureScan"
    strings:
        $zip_magic = { 50 4B 03 04 } // PK..
        $vba = "vbaProject.bin" ascii nocase
    condition:
        $zip_magic at 0 and $vba
}

rule Suspicious_Shellcode_Pattern
{
    meta:
        description = "Detects common NOP sleds often used in shellcode/exploits"
        score = 70
        author = "SecureScan"
    strings:
        $nop_sled = { 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 }
    condition:
        $nop_sled
}
