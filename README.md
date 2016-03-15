# password-utils

PasswordUtils is a fast and lightweight utility class containing series of methods for creating, comparing, and generating secure passwords to be stored on database or used for other purposes. It uses Java's latest build-in hashing algorithms and is independent of any other libraries.

#### OutPut format

All the passwords are salted and hashed by selecting a desired hash algorithm. The secure salted and hashed passwords are generated in the below format to be used in the applications as desired:
 
 ```algorithm:salt:hash```

The first part is the name of the algorithm, second section is the salt value and third section is the hashed value of the raw password and salt  combined. The separator character is a ':' (colon character). The salt and hash are Base64 encoded at the end when generating the final hash string.

```SHA512:nkQfEBbs7FwwcADCq5UGtg==:H/Bg9EQfNXrPybVLXBg9MNx1hB2VHM9db5Fwzvlx3i1k53lOEJM9eTofCkMBddQEzRd9sNDCACZZsflh42IyCw==```

### How to

Simply provide the raw password to the ```createPassword()``` function and select a desired hash algorithm:

```java
String rawPassword = "badPassword1234";
String result = createPassword(rawPassword, HashAlgorithm.SHA512);
```

For faster and easier usage, no algorithm needed to be supplied and a default (SHA-256) hash algorithm will be used:
  
```java
String rawPassword = "badPassword1234";
String result = PasswordUtils.createPassword(rawPassword);
```

The ```result`` string will contain a properly formatted password hash:  

```SHA512:nkQfEBbs7FwwcADCq5UGtg==:H/Bg9EQfNXrPybVLXBg9MNx1hB2VHM9db5Fwzvlx3i1k53lOEJM9eTofCkMBddQEzRd9sNDCACZZsflh42IyCw==```


To verify a raw password with a hashed password (with the same format created in this class):

```java
String rawPassword = "badPassword1234";
String alreadyHashedPassword = "SHA512:nkQfEBbs7FwwcADCq5UGtg==:H/Bg9EQfNXrPybVLXBg9MNx1hB2VHM9db5Fwzvlx3i1k53lOEJM9eTofCkMBddQEzRd9sNDCACZZsflh42IyCw==";
boolean isEqual = PasswordUtils.verifyPassword(rawPassword, alreadyHashedPassword);
```
