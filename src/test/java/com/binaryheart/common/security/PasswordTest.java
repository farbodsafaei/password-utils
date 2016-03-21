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

import org.junit.Assert;
import org.junit.Test;

import com.binaryheart.common.exception.InvalidHashException;

/**
 * Sample test class
 * 
 * @author Farbod Safaei
 *
 */
public class PasswordTest {

    /*
     * Following raw password and salt and hashed result have been previously generated
     * sha512HashedWithSalt is basically the result of rawPassword hashed with the base64EncodedSalt 
     * 
     * Note: following values are generated using default values for salt seed, key size and iterations. If those values change
     * the password verification test will fail!
     */
    String RAW_PASSWORD = "badPassword1234";
    String BASE64_ENCODED_SALT = "Gbf2cL/XUqItqaXr4P5//A==:";
    String PBKDF2WITHHMACSHA512_WITH_SALT = "tn2M44bFJBAGrMbvqlZB88KwtywIsRlGx8c5o25PdQ2RbOlum/1Oqz8jL3Rr31HW56Jv81HnhScpcCNZuF8AFA==";
    String FORMATTED_HASH = "PBKDF2WITHHMACSHA512:Gbf2cL/XUqItqaXr4P5//A==:tn2M44bFJBAGrMbvqlZB88KwtywIsRlGx8c5o25PdQ2RbOlum/1Oqz8jL3Rr31HW56Jv81HnhScpcCNZuF8AFA==";
    String FORMATTED_HASH_2 = "PBKDF2WITHHMACSHA512:amtsQmttJqy3Y6fb6x4A9g==:gfGnWJxhRMMEIjEPueKPIpkK4fo6l/rtIgb0pUFKPfoQagUbQ756uoSkLzo26kJu0yPDwO9B8KqMFyF8J1iWqA==";
    String BASE64_ENCODED_SALT_2 = "amtsQmttJqy3Y6fb6x4A9g==";

    /**
     * Password verification test
     * @throws InvalidHashException
     */
    @Test
    public void createPasswordWithDefaultHash() throws InvalidHashException {
        Assert.assertEquals(true, PasswordUtils.verifyPassword(RAW_PASSWORD, FORMATTED_HASH));
    }

    /**
     * Making sure the same raw password does not generate the same hash (random salt verification)
     */
    @Test
    public void createPasswordWithSHA512() {
        String generatedPasswordHash = PasswordUtils.hashPassword(RAW_PASSWORD, HashAlgorithm.PBKDF2WITHHMACSHA512);
        Assert.assertNotEquals(FORMATTED_HASH, generatedPasswordHash);
    }
    
    @Test
    public void createRandomPasswordWithDefaultSize() {
        String generatedPassword = PasswordUtils.generateRandomPassword();
        Assert.assertEquals(10, generatedPassword.length());
    }
    
    @Test
    public void createRandomPassword() {
        String generatedPassword = PasswordUtils.generateRandomPassword(15);
        Assert.assertNotEquals(10, generatedPassword.length());
    }
}
