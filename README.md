# sanitize-url

PHP port of braintree/sanitize-url typescript package.

## How to use

```php
use Bachilli\SanitizeUrl;

$sanitizeUrl = new SanitizeUrl();

$sanitizeUrl->sanitizeUrl('https://www.example.com');
// output: https://www.example.com

$sanitizeUrl->sanitizeUrl('javascript:alert(\'XSS\')');
// output: about:blank
```