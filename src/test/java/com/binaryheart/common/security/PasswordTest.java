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
    String base64EncodedSalt = "nkQfEBbs7FwwcADCq5UGtg==";
    String sha512HashedWithSalt = "H/Bg9EQfNXrPybVLXBg9MNx1hB2VHM9db5Fwzvlx3i1k53lOEJM9eTofCkMBddQEzRd9sNDCACZZsflh42IyCw==";
    String rawPassword = "badPassword1234";
    String formattedHash = "SHA512:nkQfEBbs7FwwcADCq5UGtg==:H/Bg9EQfNXrPybVLXBg9MNx1hB2VHM9db5Fwzvlx3i1k53lOEJM9eTofCkMBddQEzRd9sNDCACZZsflh42IyCw==";

    /**
     * Password verification test
     * @throws InvalidHashException
     */
    @Test
    public void createPasswordWithDefaultHash() throws InvalidHashException {
        Assert.assertEquals(true, PasswordUtils.verifyPassword(rawPassword, formattedHash));
    }

    /**
     * Making sure the same raw password does generate exact hash (random salt verification)
     */
    @Test
    public void createPasswordWithSHA512() {
        String generatedPasswordHash = PasswordUtils.createPassword("badPassword124", HashAlgorithm.SHA512);
        Assert.assertNotEquals(formattedHash, generatedPasswordHash);
    }
}
