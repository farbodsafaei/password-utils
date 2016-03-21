/*
 * Copyright 2016 Farbod Safaei
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *     http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.binaryheart.common.security;

/**
 * PBKDF2 (Password-Based Key Derivation Function 2) algorithms singleton.
 * 
 * This class contains constants of algorithms supported by
 * {@link javax.crypto.SecretKeyFactory} class.
 * 
 * @author Farbod Safaei
 *
 */
public enum HashAlgorithm {

 
    /**
     * String representation of  algorithm
     */
    PBKDF2WITHHMACMD5("PBKDF2WithHmacMD5"),
    
    /**
     * String representation of  algorithm
     */
    PBKDF2WITHHMACSHA1("PBKDF2WithHmacSHA1"),
    
    /**
     * String representation of  algorithm
     */
    PBKDF2WITHHMACSHA224("PBKDF2WithHmacSHA224"),
    
    /**
     * String representation of  algorithm
     */
    PBKDF2WITHHMACSHA256("PBKDF2WithHmacSHA256"),
    
    /**
     * String representation of  algorithm
     */
    PBKDF2WITHHMACSHA384("PBKDF2WithHmacSHA384"),
    
    /**
     * String representation of  algorithm
     */
    PBKDF2WITHHMACSHA512("PBKDF2WithHmacSHA512");
    
    private HashAlgorithm(String s) {
        this.algorithm = s;
    }
  
    private String algorithm;
    
    /**
     * Getter method to get the string value of enum constant
     * 
     * @return String value of hash algorithm
     */
    public String getAlgorithm() {
        return this.algorithm;
    }
    
};
