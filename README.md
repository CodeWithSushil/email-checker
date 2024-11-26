### Email Checker
* Email DNS Checker.

### `Usage`
```php
<?php

require "vendor/autoloader.php";

try {
  $email = "example@example.com";
  $validator = new EmailChecker($email);
  $results = $validator->validate();

  // Display results as a string 
  echo $validator->getResultsAsString();

  // Display results as JSON 
  // echo $validator->getResultsAsJson();

} catch (Exception $e) {
    echo "Error: ". $e->getMessage();
}
```
