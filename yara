rule emotet_malware {
    meta:
        description = "Detects Emotet malware activity"
        author = "fevar54"
    strings:
        $str1 = "User-Agent: Mozilla/4.0 (compatible; MSIE 8.0;"
        $str2 = "Mime-Version: 1.0"
        $str3 = "Content-Type: multipart/mixed; boundary"
        $str4 = "Content-Disposition: attachment; filename"
    condition:
        all of them
}
