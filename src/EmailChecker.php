<?php

class EmailChecker
{
    private $email;
    private $domain;
    private $results = [];

    public function __construct($email)
    {
        $this->email = $email;

        // Validate the email format
        if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
            throw new Exception("Invalid email format.");
        }

        // Extract domain from the email
        $this->domain = substr(strrchr($email, "@"), 1);
    }

    /**
     * Check MX records.
     */
    private function checkMX()
    {
        if (checkdnsrr($this->domain, "MX")) {
            $this->results['MX'] = [
                'status' => true,
                'message' => "MX records found for '{$this->domain}'.",
            ];
        } else {
            $this->results['MX'] = [
                'status' => false,
                'message' => "No MX records found for '{$this->domain}'.",
            ];
        }
    }

    /**
     * Check A records.
     */
    private function checkA()
    {
        if (checkdnsrr($this->domain, "A")) {
            $this->results['A'] = [
                'status' => true,
                'message' => "A records found for '{$this->domain}'.",
            ];
        } else {
            $this->results['A'] = [
                'status' => false,
                'message' => "No A records found for '{$this->domain}'.",
            ];
        }
    }

    /**
     * Check SPF records.
     */
    private function checkSPF()
    {
        $records = dns_get_record($this->domain, DNS_TXT);
        foreach ($records as $record) {
            if (isset($record['txt']) && stripos($record['txt'], 'v=spf1') === 0) {
                $this->results['SPF'] = [
                    'status' => true,
                    'message' => "SPF record found: {$record['txt']}",
                ];
                return;
            }
        }

        $this->results['SPF'] = [
            'status' => false,
            'message' => "No SPF record found for '{$this->domain}'.",
        ];
    }

    /**
     * Check DKIM records.
     */
    private function checkDKIM($selector = 'default')
    {
        $dkimDomain = "{$selector}._domainkey.{$this->domain}";
        $records = dns_get_record($dkimDomain, DNS_TXT);
        foreach ($records as $record) {
            if (isset($record['txt']) && stripos($record['txt'], 'v=DKIM1') === 0) {
                $this->results['DKIM'] = [
                    'status' => true,
                    'message' => "DKIM record found for selector '$selector': {$record['txt']}",
                ];
                return;
            }
        }

        $this->results['DKIM'] = [
            'status' => false,
            'message' => "No DKIM record found for selector '$selector'.",
        ];
    }

    /**
     * Check DMARC records.
     */
    private function checkDMARC()
    {
        $dmarcDomain = "_dmarc.{$this->domain}";
        $records = dns_get_record($dmarcDomain, DNS_TXT);
        foreach ($records as $record) {
            if (isset($record['txt']) && stripos($record['txt'], 'v=DMARC1') === 0) {
                $this->results['DMARC'] = [
                    'status' => true,
                    'message' => "DMARC record found: {$record['txt']}",
                ];
                return;
            }
        }

        $this->results['DMARC'] = [
            'status' => false,
            'message' => "No DMARC record found for '{$this->domain}'.",
        ];
    }

    /**
     * Check BIMI records.
     */
    private function checkBIMI()
    {
        $bimiDomain = "_bimi.{$this->domain}";
        $records = dns_get_record($bimiDomain, DNS_TXT);
        foreach ($records as $record) {
            if (isset($record['txt'])) {
                $this->results['BIMI'] = [
                    'status' => true,
                    'message' => "BIMI record found: {$record['txt']}",
                ];
                return;
            }
        }

        $this->results['BIMI'] = [
            'status' => false,
            'message' => "No BIMI record found for '{$this->domain}'.",
        ];
    }

    /**
     * Run all validations.
     */
    public function validate($dkimSelector = 'default')
    {
        $this->checkMX();
        $this->checkA();
        $this->checkSPF();
        $this->checkDKIM($dkimSelector);
        $this->checkDMARC();
        $this->checkBIMI();
        return $this->results;
    }

    /**
     * Format validation results as JSON.
     */
    public function getResultsAsJson()
    {
        return json_encode($this->results, JSON_PRETTY_PRINT);
    }

    /**
     * Format validation results as a readable string.
     */
    public function getResultsAsString()
    {
        $output = "Validation Results for '{$this->email}':\n";
        foreach ($this->results as $key => $result) {
            $status = $result['status'] ? 'PASS' : 'FAIL';
            $output .= "[{$key}] {$status}: {$result['message']}\n";
        }
        return $output;
    }
}

