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
 * Hash algorithms singleton. 
 * 
 * This class contains constants of hash algorithms supported by {@link java.security.MessageDigest} class
 *  
 * @author Farbod Safaei
 *
 */
public enum HashAlgorithm {

    /**
     * String representation of MD2 algorithm
     */
    MD2("MD2"),

    /**
     * String representation of MD5 algorithm
     */
    MD5("MD5"),

    /**
     * String representation of SHA-1 algorithm
     */
    SHA1("SHA-1"),

    /**
     * String representation of SHA-224 algorithm
     */
    SHA224("SHA-224"),

    /**
     * String representation of SHA-256 algorithm
     */
    SHA256("SHA-256"),

    /**
     * String representation of SHA-384 algorithm
     */
    SHA384("SHA-384"),
    
    /**
     * String representation of SHA-512 algorithm
     */
    SHA512("SHA-512");
    
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
