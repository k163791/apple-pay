## Apple Pay NodeJS
Example for decrypting the Apple Pay Token in Nodejs

- Apple pay token reference: https://developer.apple.com/documentation/passkit_apple_pay_and_wallet/apple_pay/payment_token_format_reference
- Apple CA Download Link: https://www.apple.com/certificateauthority/

### Description
This example caters to both `RSA_v1` and `EC_v1` encryption
 - You need the `PaymentProcessing.pem`, `MerchantIdentity.pem` and the `AppleRootCA-G3.cer` downloaded and at root level.
 - After adding thses files, just run `yarn install` or `npm install`.
 - After installation finishes, just run `node index` and then you can send the payload to the API.
