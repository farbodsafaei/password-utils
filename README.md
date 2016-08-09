# password-utils [![Build Status](https://travis-ci.org/farbodsafaei/password-utils.svg?branch=master)](https://travis-ci.org/farbodsafaei/password-utils)  [![codecov](https://codecov.io/gh/farbodsafaei/password-utils/branch/master/graph/badge.svg)](https://codecov.io/gh/farbodsafaei/password-utils)  [![Codacy Badge](https://api.codacy.com/project/badge/Grade/43f0d64da2b94c1e913d98243c882421)](https://www.codacy.com/app/farbod-safaei/password-utils?utm_source=github.com&amp;utm_medium=referral&amp;utm_content=farbodsafaei/password-utils&amp;utm_campaign=Badge_Grade)

PasswordUtils is a fast, simple and lightweight utility class containing series of methods for creating, comparing, hashing, and random generating secure passwords to be stored on database or used for other purposes. It uses Java's latest built-in hashing algorithms and is independent of any other libraries. Check [API documentation](http://farbodsafaei.github.io/password-utils/target/site/apidocs/) for details.

#### Hashing output format

All passwords are salted and hashed by selecting a desired hash algorithm using PBKDF2. The secure salted and hashed passwords are generated in the below format to be used in the applications as desired:

`algorithm:salt:hash`

The first section is the name of the algorithm in plaintext. Second section is the salt value encoded in Based64 and third section is the hashed value of the raw password and salt combined then encoded in Base64. The separator character is a ':' (colon character). Example:

`PBKDF2WITHHMACSHA512:Gbf2cL/XUqItqaXr4P5//A==:tn2M44bFJBAGrMbvqlZB88KwtywIsRlGx8c5o25PdQ2RbOlum/1Oqz8jL3Rr31HW56Jv81HnhScpcCNZuF8AFA==`

Break-down of above line:  
Algorithm: ```PBKDF2WITHHMACSHA512```  
Salt (Base64): ```Gbf2cL/XUqItqaXr4P5//A==```  
Hash (Base64): ```tn2M44bFJBAGrMbvqlZB88KwtywIsRlGx8c5o25PdQ2RbOlum/1Oqz8jL3Rr31HW56Jv81HnhScpcCNZuF8AFA==```  

#### How to hash a password

Simply pass the raw password (in plaintext) to the `hashPassword()` method with a desired hash algorithm:

```java
String rawPassword = "badPassword1234";
String result = PasswordUtils.hashPassword(rawPassword, HashAlgorithm.PBKDF2WITHHMACSHA512);
```

For faster and easier usage, no algorithm is required to be passed and a default (PBKDF2WithHmacSHA256) hash algorithm will be used:
  
```java
String rawPassword = "badPassword1234";
String result = PasswordUtils.hashPassword(rawPassword);
```

The result string will contain a properly formatted password hash:  

`PBKDF2WITHHMACSHA512:Gbf2cL/XUqItqaXr4P5//A==:tn2M44bFJBAGrMbvqlZB88KwtywIsRlGx8c5o25PdQ2RbOlum/1Oqz8jL3Rr31HW56Jv81HnhScpcCNZuF8AFA==`

To verify a raw password (in plaintext) with a hashed password (with the same format created using this class) simply use `verifyPassword()` method:

```java
String rawPassword = "badPassword1234";
String alreadyHashedPassword = "PBKDF2WITHHMACSHA512:amtsQmttJqy3Y6fb6x4A9g==:gfGnWJxhRMMEIjEPueKPIpkK4fo6l/rtIgb0pUFKPfoQagUbQ756uoSkLzo26kJu0yPDwO9B8KqMFyF8J1iWqA==";
boolean result = PasswordUtils.verifyPassword(rawPassword, alreadyHashedPassword);
```

#### How to generate a random password

To generate a random password, simply call `generateRandomPassword(int length)` and pass a desired length or call `generateRandomPassword()` with no arguements which uses default length.

Random password generator in this class can be used to create secure temporary passwords. It uses a random combination of letters, numbers and special characters to generate a password. Values are taken from ranges: `[A-Z] [a-z] [0-9]` and special characters: 
```! "  #  $   %   &  '  (  )  *  +  ,  -  .  /  :  ;  <  =  >  ?  @ [  \  ]  ^  _  `  {  |  }  ~``` 

 Example:
 ```java
 PasswordUtils.generateRandomPassword();
 ```
 
 the output will be a sequence of random characters based on the above criteria, such as:
 
 `_&4'IW2;q%`
 
