# Sends the report through Exchange (or any SMTP relay) with System.Net.Mail.
#
# The message is multipart/alternative (plain text + HTML) which renders best in Gmail and scores better
# with spam filters; the complete report is attached as an HTML file.

function Send-HCReportMail {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][hashtable]$Email,
        [Parameter(Mandatory)][string]$Subject,
        [Parameter(Mandatory)][string]$Html,
        [Parameter(Mandatory)][string]$Text,
        [string[]]$Attachments,
        [pscredential]$Credential,
        [switch]$HighPriority,
        [string[]]$To
    )
    if (-not $Email.SmtpServer) { throw 'Email.SmtpServer is not set in the config.' }
    if (-not $Email.From) { throw 'Email.From is not set in the config.' }
    $recipients = if ($To) { $To } else { @($Email.To) }
    if (-not ($recipients | Where-Object { $_ })) { throw 'Email.To is empty.' }
    if ($Credential -and -not $Email.UseStartTls) {
        throw 'Refusing to send SMTP credentials without encryption: set Email.UseStartTls = $true (port 587 on Exchange).'
    }

    $message = [System.Net.Mail.MailMessage]::new()
    $client = $null
    try {
        $message.From = [System.Net.Mail.MailAddress]::new([string]$Email.From)
        foreach ($address in $recipients) { if ($address) { $message.To.Add([string]$address) } }
        foreach ($address in @($Email.Cc)) { if ($address) { $message.CC.Add([string]$address) } }
        foreach ($address in @($Email.Bcc)) { if ($address) { $message.Bcc.Add([string]$address) } }
        if ($Email.ReplyTo) { $message.ReplyToList.Add([string]$Email.ReplyTo) }
        $message.Subject = $Subject
        $message.SubjectEncoding = [System.Text.Encoding]::UTF8
        $message.HeadersEncoding = [System.Text.Encoding]::UTF8
        $message.Headers.Add('Auto-Submitted', 'auto-generated')        # RFC 3834: no auto-replies
        $message.Headers.Add('X-Auto-Response-Suppress', 'All')          # Exchange: no OOF / receipts
        if ($HighPriority) { $message.Priority = [System.Net.Mail.MailPriority]::High }

        $plain = [System.Net.Mail.AlternateView]::CreateAlternateViewFromString($Text, [System.Text.Encoding]::UTF8, 'text/plain')
        $plain.TransferEncoding = [System.Net.Mime.TransferEncoding]::Base64
        $rich = [System.Net.Mail.AlternateView]::CreateAlternateViewFromString($Html, [System.Text.Encoding]::UTF8, 'text/html')
        $rich.TransferEncoding = [System.Net.Mime.TransferEncoding]::Base64
        $message.AlternateViews.Add($plain)
        $message.AlternateViews.Add($rich)

        foreach ($file in @($Attachments | Where-Object { $_ })) {
            $attachment = [System.Net.Mail.Attachment]::new($file, 'text/html')
            $attachment.Name = [System.IO.Path]::GetFileName($file)
            $attachment.ContentType.CharSet = 'utf-8'
            $message.Attachments.Add($attachment)
        }

        $client = [System.Net.Mail.SmtpClient]::new([string]$Email.SmtpServer, [int](Get-HCOption $Email 'Port' 25))
        $client.EnableSsl = [bool]$Email.UseStartTls
        $client.Timeout = 60000
        if ($Credential) {
            $client.Credentials = $Credential.GetNetworkCredential()
        } elseif ($Email.UseDefaultCredentials) {
            $client.UseDefaultCredentials = $true
        }
        $client.Send($message)
    } finally {
        if ($client) { $client.Dispose() }
        $message.Dispose()
    }
}
