<?php

class EmailValidator {


    function isEmailDeliverable($email, $fromEmail = 'akashchawan986@gmail.com')
    {
        $result = [
            'email' => $email,
            'valid_format' => false,
            'domain_exists' => false,
            'smtp_check' => false,
            'deliverable' => false,
            'response' => '',
            'message' => '',
            'send_email' => 0
        ];

        // Step 1: Validate format
        if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
            $result['message'] = 'Invalid email format';
            return $result;
        }
        $result['valid_format'] = true;

        // Step 2: Check MX records
        list($user, $domain) = explode('@', $email);
        if (!checkdnsrr($domain, 'MX')) {
            $result['message'] = 'No MX record found — domain cannot receive mail';
            return $result;
        }

        $result['domain_exists'] = true;
        getmxrr($domain, $mxRecords);
        if (empty($mxRecords)) {
            $result['message'] = 'No MX host found';
            return $result;
        }
        $smtpResponse = [];
        // Step 3: Connect to mail server via SMTP
        foreach ($mxRecords as $host) {
            $connection = @fsockopen($host, 25, $errno, $errstr, 10);
            if (!$connection) {
                continue; // try next MX server
            }

            stream_set_timeout($connection, 5);

            $response = fgets($connection);
            if (strpos($response, '220') === false) {
                fclose($connection);
                continue;
            }

            // SMTP handshake
            fputs($connection, "HELO example.com\r\n");
            fgets($connection);

            fputs($connection, "MAIL FROM:<$fromEmail>\r\n");
            fgets($connection);

            fputs($connection, "RCPT TO:<$email>\r\n");
            $smtpResponse = fgets($connection);

            fputs($connection, "QUIT\r\n");
            fclose($connection);

            $result['smtp_check'] = true;
            $result['response'] = trim($smtpResponse);

            // Interpret response
            if (preg_match('/^250/i', $smtpResponse)) {
                $result['deliverable'] = true;
                $result['message'] = 'Email address is deliverable';
                $result['send_email'] = 1;
            } elseif (preg_match('/^550/i', $smtpResponse)) {
                $result['deliverable'] = false;
                $result['message'] = 'Mailbox not found';
            } else {
                $result['deliverable'] = false;
                $result['message'] = 'Uncertain response: ' . trim($smtpResponse);
            }

            break; // Stop after first successful MX connection
        }

        if (!$result['smtp_check']) {
            $result['send_email'] = 1;
            $result['message'] = 'Unable to connect to any mail server (port 25 blocked or timed out)';
        }
        $result["response"] = $smtpResponse;
        return $result;
    }
}
