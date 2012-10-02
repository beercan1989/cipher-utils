package com.jbacon.cryptography.utils;

import org.junit.runner.RunWith;
import org.junit.runners.Suite;
import org.junit.runners.Suite.SuiteClasses;

@RunWith(Suite.class)
@SuiteClasses({ GenericCipherUtilsTest.class, PasswordBasedCiphersTest.class, SymmetricCiphersTest.class })
public class AllTests {

}
