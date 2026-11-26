<?php
/**
 * Plugin Name: Rustiron Mail Relay
 * Description: Sends WordPress mail directly over the site's D-071 Unix socket without shell exec or TCP egress (D-019, D-046, D-071).
 * Version: 1.0.0
 */

if (!defined('ABSPATH')) {
    exit;
}

/**
 * Resolves the site's own fixed Unix socket path from its account root.
 * Never accepts caller-supplied paths or network hosts.
 */
function rustiron_mail_relay_socket_path(): ?string
{
    $account = basename(dirname(ABSPATH));
    if (!preg_match('/^rs_[a-z][a-z0-9_]{0,31}$/', $account)) {
        return null;
    }
    return '/run/rustiron-mail/' . $account . '/smtp';
}

/**
 * Reads one complete SMTP response (supporting multi-line replies) and returns
 * [status_code, full_response_line].
 */
function rustiron_mail_relay_read_reply($stream): array
{
    $code = 0;
    $lines = [];
    while (($line = fgets($stream, 4096)) !== false) {
        $trimmed = rtrim($line, "\r\n");
        $lines[] = $trimmed;
        if (strlen($trimmed) >= 3 && ctype_digit(substr($trimmed, 0, 3))) {
            $code = (int) substr($trimmed, 0, 3);
            if (strlen($trimmed) === 3 || $trimmed[3] === ' ') {
                break;
            }
        }
    }
    return [$code, implode(' | ', $lines)];
}

/**
 * Sends one SMTP command over the Unix socket and verifies the expected 3-digit
 * reply code.
 */
function rustiron_mail_relay_cmd($stream, string $command, int $expected): void
{
    if (fwrite($stream, $command . "\r\n") === false) {
        throw new \PHPMailer\PHPMailer\Exception('Rustiron mail relay write failed');
    }
    [$code, $reply] = rustiron_mail_relay_read_reply($stream);
    if ($code !== $expected) {
        throw new \PHPMailer\PHPMailer\Exception(
            'Rustiron mail relay rejected command (code ' . $code . '): ' . $reply
        );
    }
}

/**
 * Strips CR/LF/NUL/angle brackets from an SMTP envelope address.
 */
function rustiron_mail_relay_clean_addr(string $addr): string
{
    $clean = trim(str_replace(["\r", "\n", "\0", '<', '>'], '', $addr));
    if ($clean === '' || strpbrk($clean, " \t") !== false || strpos($clean, '@') === false) {
        throw new \PHPMailer\PHPMailer\Exception('Rustiron mail relay refused invalid address');
    }
    return $clean;
}

if (!class_exists('Rustiron_Unix_Socket_PHPMailer', false)) {
    if (!class_exists('\PHPMailer\PHPMailer\PHPMailer', false)) {
        require_once ABSPATH . WPINC . '/PHPMailer/PHPMailer.php';
        require_once ABSPATH . WPINC . '/PHPMailer/SMTP.php';
        require_once ABSPATH . WPINC . '/PHPMailer/Exception.php';
    }

    /**
     * PHPMailer transport that keeps WordPress's full MIME builder (`preSend`)
     * and transmits the resulting message strictly over the site's D-071 Unix
     * socket without invoking PHP's sendmail/exec path.
     */
    final class Rustiron_Unix_Socket_PHPMailer extends \PHPMailer\PHPMailer\PHPMailer
    {
        public function preSend()
        {
            // Force SMTP MIME assembly so PHPMailer includes complete To: and
            // Subject: headers (unlike PHP native mail mode which omits them).
            $this->Mailer = 'smtp';
            return parent::preSend();
        }

        public function postSend()
        {
            $socket = rustiron_mail_relay_socket_path();
            if ($socket === null) {
                throw new \PHPMailer\PHPMailer\Exception('Rustiron mail relay could not derive site account');
            }

            $errno = 0;
            $errstr = '';
            $stream = @stream_socket_client('unix://' . $socket, $errno, $errstr, 10);
            if ($stream === false) {
                throw new \PHPMailer\PHPMailer\Exception(
                    'Rustiron mail relay socket unavailable (' . $errno . '): ' . $errstr
                );
            }

            stream_set_timeout($stream, 15);
            try {
                [$greet, $reply] = rustiron_mail_relay_read_reply($stream);
                if ($greet !== 220) {
                    throw new \PHPMailer\PHPMailer\Exception(
                        'Rustiron mail relay unexpected banner (' . $greet . '): ' . $reply
                    );
                }

                $sender = rustiron_mail_relay_clean_addr($this->Sender !== '' ? $this->Sender : $this->From);
                $recipients = [];
                foreach (array_merge($this->to, $this->cc, $this->bcc) as $entry) {
                    if (isset($entry[0]) && is_string($entry[0]) && $entry[0] !== '') {
                        $recipients[] = rustiron_mail_relay_clean_addr($entry[0]);
                    }
                }
                if ($recipients === []) {
                    throw new \PHPMailer\PHPMailer\Exception('Rustiron mail relay received no recipients');
                }

                rustiron_mail_relay_cmd($stream, 'EHLO localhost', 250);
                rustiron_mail_relay_cmd($stream, 'MAIL FROM:<' . $sender . '>', 250);
                foreach ($recipients as $rcpt) {
                    rustiron_mail_relay_cmd($stream, 'RCPT TO:<' . $rcpt . '>', 250);
                }
                rustiron_mail_relay_cmd($stream, 'DATA', 354);

                // Normalize line endings to CRLF and apply RFC 5321 dot-stuffing.
                $raw = $this->MIMEHeader . "\r\n" . $this->MIMEBody;
                $raw = str_replace(["\r\n", "\r"], "\n", $raw);
                $stuffed = preg_replace('/^\./m', '..', $raw);
                $wire = str_replace("\n", "\r\n", $stuffed);
                if (substr($wire, -2) !== "\r\n") {
                    $wire .= "\r\n";
                }
                if (fwrite($stream, $wire . ".\r\n") === false) {
                    throw new \PHPMailer\PHPMailer\Exception('Rustiron mail relay DATA write failed');
                }
                [$code, $dataReply] = rustiron_mail_relay_read_reply($stream);
                if ($code !== 250) {
                    throw new \PHPMailer\PHPMailer\Exception(
                        'Rustiron mail relay rejected message (' . $code . '): ' . $dataReply
                    );
                }
                @fwrite($stream, "QUIT\r\n");
                return true;
            } finally {
                fclose($stream);
            }
        }
    }
}

add_action(
    'plugins_loaded',
    static function (): void {
        global $phpmailer;
        if (!($phpmailer instanceof Rustiron_Unix_Socket_PHPMailer)) {
            $phpmailer = new Rustiron_Unix_Socket_PHPMailer(true);
        }
    },
    1
);
