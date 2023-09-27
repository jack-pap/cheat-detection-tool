rule DLL_Injection_Detection {
    meta:
        description = "Rule for detecting DLL files used in cheating for multiple games" 
        author = "Jack Papaioannou"
    strings:     
        //Cuphead Signatures
        $expModMVID = "9EA7E569-C36E-40BC-A862-0FA27DC28C22" nocase ascii wide
        $expModBytes = {9ea7e569c36e40bca8620fa27dc28c22}
        $weapModMVID = "3A38F040-EA14-454B-A34C-56E81A78C174" nocase ascii wide 
        $weapModBytes = {40F0383A14EA4B45A34C56E81A78C174}    
        $trainerModMVID = "0987943C-8750-4314-843E-9053ADF65CB5" nocase ascii wide 
        $trainModBytes =  {3C94780950871443E8439053ADF65CB5}
        $accessModMVID = "1320D140-2329-4C5B-8D49-7DA2B2244B45" nocase ascii wide
        $accModBytes = {31333230443134302D323332392D344335422D384434392D374441324232343434423435}

        //Valheim Signatures
        $durandaModMVID = "82F61A1E-39C4-40C2-B80A-97E80D3116E8" nocase ascii wide
        $testModMVID = "7C4C7696-B98B-40A5-A7A2-BAFB94E410D8" nocase ascii wide
        $sharpModMVID = "0FE877EB-C0F7-44A3-BB50-A75BE6E725DF" nocase ascii wide
        $shieldModMVID = "39A2B4E2-91B3-4155-B5E2-A36A4D30851F" nocase ascii wide
        $coreModMVID = "F15E66EC-8BAC-455D-A00F-C30EB5E18D09" nocase ascii wide
        $valModMVID = "58F888E0-D56A-4620-958C-8E58A768C70D" nocase ascii wide

        //Half-Life 2 Signatures
        $hl2Mod = "ec7dfa6de2ec3faadf6079df6bb714eb8fa6b2c1" nocase ascii wide
    condition:
        any of them
}