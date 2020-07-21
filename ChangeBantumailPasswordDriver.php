<?php

require 'vendor/autoload.php';
use GuzzleHttp\Client;

class ChangeBantumailPasswordDriver implements \RainLoop\Providers\ChangePassword\ChangePasswordInterface
{
    /**
     * @var string
     */
    private $sAllowedEmails = '';

    /**
     * @param string $sAllowedEmails
     *
     * @return \ChangeBantumailPasswordDriver
     */
    public function SetAllowedEmails($sAllowedEmails)
    {
        $this->sAllowedEmails = $sAllowedEmails;
        return $this;
    }

    /**
     * @param \RainLoop\Model\Account $oAccount
     *
     * @return bool
     */
    public function PasswordChangePossibility($oAccount)
    {
        return $oAccount && $oAccount->Email() &&
            \RainLoop\Plugins\Helper::ValidateWildcardValues($oAccount->Email(), $this->sAllowedEmails);
    }

    /**
     * @param \RainLoop\Model\Account $oAccount
     * @param string $sPrevPassword
     * @param string $sNewPassword
     *
     * @return bool
     */
    public function ChangePassword(\RainLoop\Account $oAccount, $sPrevPassword, $sNewPassword)
    {
        $client = new Client([ 'base_uri' => 'https://api.bantumail.com','timeout'  => 5.0,'http_errors' => false]);
        
        $response = $client->request(
            'POST',
            '/login',
            [ 'json' => [ 'Username' => $oAccount->Email(), 'Password' => $sPrevPassword ] ]
        );
        
        if ($response->getStatusCode() != 200) {
            error_log(sprintf("Could not login: %s", $response->getReasonPhrase()), 0);
            return false;
        }
        
        $tokenResponse = json_decode($response->getBody(), false);
        
        if (empty($tokenResponse->Token)) {
            error_log(sprintf("Could not login: %s", json_encode($tokenResponse)), 0);
            return false;
        }

        $response = $client->request(
            'PATCH',
            '/v1/password',
            [
                'headers'  => [ 'Authorization' => sprintf("Bearer %s", $tokenResponse->Token) ],
                'json' => [
                    'OldPassword' => $sPrevPassword,
                    'NewPassword' => $sNewPassword,
                    'NewPasswordConfirm' => $sNewPassword,
                    ]
            ]
        );

        if ($response->getStatusCode() != 200) {
            error_log(sprintf("Could not update password: %s", $response->getReasonPhrase()), 0);
            return false;
        }

        return true;
    }
}
