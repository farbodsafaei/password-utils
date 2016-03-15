# password-utils [![Build Status](https://travis-ci.org/farbodsafaei/password-utils.svg?branch=master)](https://travis-ci.org/farbodsafaei/password-utils)

PasswordUtils is a fast, simple and lightweight utility class containing series of methods for creating, comparing, and generating secure passwords to be stored on database or used for other purposes. It uses Java's latest built-in hashing algorithms and is independent of any other libraries.

#### Output format

All passwords are salted and hashed by selecting a desired hash algorithm. The secure salted and hashed passwords are generated in the below format to be used in the applications as desired:

```
algorithm:salt:hash
```

The first section is the name of the algorithm in plaintext. Second section is the salt value encoded in Based64 and third section is the hashed value of the raw password and salt combined then encoded in Base64. The separator character is a ':' (colon character). Example:

```
SHA512:nkQfEBbs7FwwcADCq5UGtg==:H/Bg9EQfNXrPybVLXBg9MNx1hB2VHM9db5Fwzvlx3i1k53lOEJM9eTofCkMBddQEzRd9sNDCACZZsflh42IyCw==
```

Break-down of above line:  
Algorithm: ```SHA512```  
Salt (Base64): ```nkQfEBbs7FwwcADCq5UGtg==```  
Hash (Base64): ```H/Bg9EQfNXrPybVLXBg9MNx1hB2VHM9db5Fwzvlx3i1k53lOEJM9eTofCkMBddQEzRd9sNDCACZZsflh42IyCw==```  

#### How to

Simply pass the raw password (in plaintext) to the ```createPassword()``` method with a desired hash algorithm:

```java
String rawPassword = "badPassword1234";
String result = PasswordUtils.createPassword(rawPassword, HashAlgorithm.SHA512);
```

For faster and easier usage, no algorithm is required to be passed and a default (SHA-256) hash algorithm will be used:
  
```java
String rawPassword = "badPassword1234";
String result = PasswordUtils.createPassword(rawPassword);
```

The result string will contain a properly formatted password hash:  

```
SHA512:nkQfEBbs7FwwcADCq5UGtg==:H/Bg9EQfNXrPybVLXBg9MNx1hB2VHM9db5Fwzvlx3i1k53lOEJM9eTofCkMBddQEzRd9sNDCACZZsflh42IyCw==
```

To verify a raw password (in plaintext) with a hashed password (with the same format created using this class) simply use ```verifyPassword()``` method:

```java
String rawPassword = "badPassword1234";
String alreadyHashedPassword = "SHA512:nkQfEBbs7FwwcADCq5UGtg==:H/Bg9EQfNXrPybVLXBg9MNx1hB2VHM9db5Fwzvlx3i1k53lOEJM9eTofCkMBddQEzRd9sNDCACZZsflh42IyCw==";
boolean result = PasswordUtils.verifyPassword(rawPassword, alreadyHashedPassword);
```
