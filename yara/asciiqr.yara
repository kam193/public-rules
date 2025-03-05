rule Possible_Unicode_QR_utf8
{
	meta:
		description = "Suspicious combination Unicode chars suggesting creating a QR code. Detection of UTF-8 representation"
		author = "Kamil Mańkowski"
		category = "info"
		info = "https://blog.barracuda.com/2024/10/09/novel-phishing-techniques-ascii-based-qr-codes-blob-uri"

	strings:
		$block1 = {e2 96 88}
		$block2 = {e2 96 80}
		$block3 = {e2 96 84}

	condition:
		all of ($block*) and (#block1 + #block2 + #block3) > 50
}

rule Possible_Unicode_QR_html
{
	meta:
		description = "Suspicious combination Unicode chars suggesting creating a QR code. Detection of HTML entity representation"
		author = "Kamil Mańkowski"
		category = "info"
		info = "https://blog.barracuda.com/2024/10/09/novel-phishing-techniques-ascii-based-qr-codes-blob-uri"

	strings:
		$block1 = "&block;"
		$block2 = "&uhblk;"
		$block3 = "&lhblk;"

	condition:
		all of ($block*) and (#block1 + #block2 + #block3) > 50
}
