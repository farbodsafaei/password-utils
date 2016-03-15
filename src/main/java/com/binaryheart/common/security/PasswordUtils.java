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

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

import com.binaryheart.common.exception.InvalidHashException;

/**
 * PasswordUtils is a fast, simple, and lightweight utility class containing 
 * series of methods for creating, comparing, and generating secure passwords 
 * to be stored on database or used for other purposes. It uses Java's latest 
 * built-in hashing algorithms and is independent of any other libraries.
 * 
 * <p>
 * All the passwords are salted and hashed using a selectable hash algorithm. 
 * The secure salted and hashed passwords are generated in the below format 
 * to be used in the applications as desired:
 * <p>
 * 
 * {@code algorithm:salt:hash}
 * 
 * <p>
 * The first part is the name of the algorithm, second section is the salt
 * value and third section is the hashed value of the raw password and salt 
 * combined. The separator character is a ':' (colon character). The salt
 * and hash are Base64 encoded at the end when generating the final hash string.
 * </p>
 * 
 * {@code SHA512:nkQfEBbs7FwwcADCq5UGtg==:H/Bg9EQfNXrPybVLXBg9MNx1hB2VHM9db5Fwzvlx3i1k53lOEJM9eTofCkMBddQEzRd9sNDCACZZsflh42IyCw==}
 * 
 * @author Farbod Safaei - farbod@binaryheart.com
 *
 */
public final class PasswordUtils {

    private static final int HASH_SECTION_SIZE = 3;
    private static final int HASH_SECTION_ALGORITHM_INDEX = 0;
    private static final int HASH_SECTION_SALT_INDEX = 1;
    private static final int DEFAULT_SALT_SEED_SIZE = 16;
    private static final String SECTION_SEPARATOR = ":";
    private static final String ERROR_NULL_PASSWORD = "Password is null or empty!";
    private static final SeedAlgorithm DEFAULT_RANDOM_SEED_ALGORITHM = SeedAlgorithm.SHA1PRNG;
    private static final HashAlgorithm DEFAULT_HASH_ALGORITHM = HashAlgorithm.SHA256;

    // No reason to instantiate
    private PasswordUtils() {}
    
    private static String createHashedPassword(final String rawPassword, final byte[] salt, HashAlgorithm algorithm) {
        try {
            byte[] rawPasswordByte = Base64.getEncoder().encode(rawPassword.getBytes(StandardCharsets.UTF_8));
            MessageDigest messageDigest = MessageDigest.getInstance(algorithm.getAlgorithm());
            messageDigest.update(salt);
            byte[] hashed = messageDigest.digest(rawPasswordByte);
            messageDigest.reset();
            return Base64.getEncoder().encodeToString(hashed);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalArgumentException(e);
        }
    }
    
    /**
     * Generates a hashed password for the given raw password string
     * 
     * It uses the default HashAlgorithm which is "SHA-256".
     * 
     * @param rawPassword
     *            raw password value in in {@code String} format
     *            
     * @return String representation of a Base64 encoded hashed password and 
     *            Base64 encoded salt with the format of {@code algorithm:salt:hash}
     * 
     * @throws IllegalArgumentException
     *            if the parameter is null or empty string
     */
    public static String createPassword(final String rawPassword) throws IllegalArgumentException {
        if (rawPassword == null || rawPassword.isEmpty()) {
            throw new IllegalArgumentException(ERROR_NULL_PASSWORD);
        }
        return createPassword(rawPassword, DEFAULT_HASH_ALGORITHM);
    }

    /**
     * Generates a hashed password based on the given algorithm from {@link HashAlgorithm}.
     * Any values such as HashAlgorithm.MD2, HashAlgorithm.MD5, HashAlgorithm.SHA1, 
     * HashAlgorithm.SHA224, HashAlgorithm.SHA256, HashAlgorithm.SHA384, HashAlgorithm.SHA512
     * Can be used for generating secure passwords. A secure random seed will be generated 
     * each time and is combined with the raw password to generate a secure hash.
     *  
     * <p>Note: For better security, it is not recommended using MD2, MD5 or SHA1
     * to hash passwords.</p> 
     * 
     * The output format will have 3 separated sections:
     * {@code algorithm:salt:hash}, salt and hash will be additionally Base64 encoded.
     * 
     * @param rawPassword
     *            raw password value in {@code String} format
     *            
     * @param algorithm
     *            A value from {@link HashAlgorithm}
     *            
     * @return String representation of a hashed password and salt with the
     *         format of {@code algorithm:salt:hash}
     *         
     * @throws IllegalArgumentException
     *            if rawPassword parameter is null or empty string
     *         
     */
    public static String createPassword(final String rawPassword, HashAlgorithm algorithm) throws IllegalArgumentException {
        if (rawPassword == null || rawPassword.isEmpty()) {
            throw new IllegalArgumentException(ERROR_NULL_PASSWORD);
        }        
        byte[] salt = generateRandomSalt();
        String hash = createHashedPassword(rawPassword, salt, algorithm);
        return generateformattedHash(hash, Base64.getEncoder().encodeToString(salt), algorithm);
    }

    private static String generateformattedHash(final String hash, final String salt, HashAlgorithm algorithm) {
        StringBuilder result = new StringBuilder(algorithm.name());
        result.append(SECTION_SEPARATOR).append(salt).append(SECTION_SEPARATOR).append(hash);
        return result.toString();
    }
    
    /**
     * Generates a salt value using the default seed size provided in this class.
     * 
     * <p>Note: To preserve consistency seed size should not be changed.</p>
     * 
     * This method uses "SHA1PRNG" algorithm to generate the salt
     * 
     * @return Base64 encoded salt value
     * 
     * @throws IllegalArgumentException
     *          If seed algorithm does not exist
     */
    private static byte[] generateRandomSalt() throws IllegalArgumentException {
        return generateRandomSalt(DEFAULT_RANDOM_SEED_ALGORITHM, DEFAULT_SALT_SEED_SIZE);
    }

    /**
     * Generates a salt value using a seed algorithm and a seed size
     *          
     * @param seedAlgorithm
     *          A value from {@code SeedAlgorithm}
     *           
     * @param seedSize
     *          Size of seed
     *          
     * @return  byte array of random generated salt
     * 
     * @throws IllegalArgumentException
     *          If seed algorithm is not correct or does not exist
     */
    public static byte[] generateRandomSalt(SeedAlgorithm seedAlgorithm, final int seedSize) throws IllegalArgumentException {
        try {
            return SecureRandom.getInstance(seedAlgorithm.name()).generateSeed(seedSize);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalArgumentException(e);
        }
    }

    /**
     * Verifies a provided raw password (in plaintext, unsalted and not hashed)
     * by salting and hashing it and comparing it to a target value (usually 
     * coming from database).
     * 
     * @param rawPassword
     *            Raw password in plain text
     * 
     * @param hashedPassword
     *            Fully formatted hashed password (target) to compare with, 
     *            formatted as {@code algorithm:salt:hash}
     * 
     * @return {@code true} if password matches the hashed value and
     *         {@code false} if the password does not match the hashed value
     *         
     * @throws InvalidHashException
     *          if hashedPassword does not have the format of {@code algorithm:salt:hash}
     *          
     * @throws IllegalArgumentException
     *            if any of parameters are null or empty string
     */
    public static boolean verifyPassword(final String rawPassword, final String hashedPassword) 
            throws IllegalArgumentException, InvalidHashException {
        if (rawPassword == null || rawPassword.isEmpty() || hashedPassword == null || hashedPassword.isEmpty()) {
            throw new IllegalArgumentException(ERROR_NULL_PASSWORD);
        }                
        boolean result = false;
        String[] suppliedPasswordArray = hashedPassword.split(SECTION_SEPARATOR);
        if (suppliedPasswordArray.length != HASH_SECTION_SIZE) {
            throw new InvalidHashException();
        }
        HashAlgorithm algorithm = HashAlgorithm.valueOf(suppliedPasswordArray[HASH_SECTION_ALGORITHM_INDEX]);
        byte[] salt = Base64.getDecoder().decode(suppliedPasswordArray[HASH_SECTION_SALT_INDEX]);
        String hash = createHashedPassword(rawPassword, salt, algorithm);
        String tempHashedPassword = generateformattedHash(hash, Base64.getEncoder().encodeToString(salt), algorithm);
        if (tempHashedPassword.equals(hashedPassword)) {
            result = true;
        }
        return result;
    }

}
