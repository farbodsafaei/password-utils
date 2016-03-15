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
package com.binaryheart.common.exception;

/**
 * This exception is thrown when a hash algorithm is not found or illegally 
 * defined in the code when creating or getting an instance of MessageDigest 
 * or SecureRandom classes.
 * 
 * The class uses a default message to simplify code in the other classes.
 * 
 * @author Farbod Safaei - farbod@binaryheart.com
 */
public class InvalidHashException extends Exception {

    private static final long serialVersionUID = -5646380458040389507L;
    private static String message = "Invalid hash algorithm";
   
    /**
     * Default constructor 
     */
    public InvalidHashException() {
        super(message);
    }
    
    /**
     * Constructor wiht {@code Throwable} parameter
     * 
     * @param cause cause (usually another caught exception) of throwing this exception
     */
    public InvalidHashException (Throwable cause) {
        super(message, cause);
    }
    
}
