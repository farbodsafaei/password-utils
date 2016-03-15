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
     */
    String RAW_PASSWORD = "badPassword1234";
    String BASE64_ENCODED_SALT = "nkQfEBbs7FwwcADCq5UGtg==";
    String SHA512_WITH_SALT = "LT99LKWP4b+1l9Hmxl5eTPxtpBJWPYfyacggHJcQ6vv6B6vvH+4+GJMeopVAxZs63EVv6Jtbr538yWJMHWhy2A==";
    String FORMATTED_HASH = "SHA512:nkQfEBbs7FwwcADCq5UGtg==:LT99LKWP4b+1l9Hmxl5eTPxtpBJWPYfyacggHJcQ6vv6B6vvH+4+GJMeopVAxZs63EVv6Jtbr538yWJMHWhy2A==";
    String FORMATTED_HASH_2 = "SHA512:U0lkelJEbDlHVDdKSkdpNElMNVhTZz09:o1KEo42sfcOCiUHaXxfFY5det8H0rtPq848TVrOqITpHL50aT+tOKrnkUsFMh/GpNV1o02z39xUe6IItIRud0g==";
    String BASE64_ENCODED_SALT_2 = "U0lkelJEbDlHVDdKSkdpNElMNVhTZz09";

    /**
     * Password verification test
     * @throws InvalidHashException
     */
    @Test
    public void createPasswordWithDefaultHash() throws InvalidHashException {
        Assert.assertEquals(true, PasswordUtils.verifyPassword(RAW_PASSWORD, FORMATTED_HASH));
    }

    /**
     * Making sure the same raw password does generate exact hash (random salt verification)
     */
    @Test
    public void createPasswordWithSHA512() {
        String generatedPasswordHash = PasswordUtils.createPassword(RAW_PASSWORD, HashAlgorithm.SHA512);
        System.out.println("FORMATTED: " + FORMATTED_HASH);
        System.out.println("GENERATED: " + generatedPasswordHash);
        Assert.assertNotEquals(FORMATTED_HASH, generatedPasswordHash);
    }
    
    //@Test
    public void verifyPassword() {
        
    }
}
