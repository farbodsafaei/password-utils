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
 * Seed algorithms singleton. 
 * 
 * This class contains constants of seed algorithms supported by {@link java.security.SecureRandom} class
 *  
 * @author Farbod Safaei
 */
public enum SeedAlgorithm {

    /**
     * String representation of NativePRNG algorithm
     */
    NATIVEPRNG("NativePRNG"),

    /**
     * String representation of NativePRNGBlocking algorithm
     */
    NATIVEPRNGBLOCKING("NativePRNGBlocking"),

    /**
     * String representation of NativePRNGNonBlocking algorithm
     */
    NATIVEPRNGNonBLOCKING("NativePRNGNonBlocking"),

    /**
     * String representation of PKCS11 algorithm
     */
    PKCS11("PKCS11"),

    /**
     * String representation of SHA1PRNG algorithm
     */
    SHA1PRNG("SHA1PRNG"),

    /**
     * String representation of Windows-PRNG algorithm
     */
    WINDOWSPRNG("Windows-PRNG");
    
    private SeedAlgorithm(String s) {
        this.algorithm = s;
    }
  
    private String algorithm;
    
    /**
     * Getter method to get the string value of enum constant
     * 
     * @return String value of seed algorithm
     */
    public String getAlgorithm() {
        return this.algorithm;
    }
}
