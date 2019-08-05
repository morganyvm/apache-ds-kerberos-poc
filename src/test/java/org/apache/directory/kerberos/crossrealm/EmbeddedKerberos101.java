package org.apache.directory.kerberos.crossrealm;

import static org.junit.Assert.fail;

import java.nio.file.Path;
import java.nio.file.Paths;

import org.apache.directory.server.annotations.CreateKdcServer;
import org.apache.directory.server.annotations.CreateLdapServer;
import org.apache.directory.server.annotations.CreateTransport;
import org.apache.directory.server.core.annotations.ApplyLdifFiles;
import org.apache.directory.server.core.annotations.CreateDS;
import org.apache.directory.server.core.annotations.CreateIndex;
import org.apache.directory.server.core.annotations.CreatePartition;
import org.apache.directory.server.core.integ.AbstractLdapTestUnit;
import org.apache.directory.server.core.integ.FrameworkRunner;
import org.junit.Test;
import org.junit.runner.RunWith;

/**
 * @author morgany
 * @see https://directory.apache.org/apacheds/advanced-ug/7-embedding-apacheds.html
 */
@RunWith(FrameworkRunner.class)
//@formatter:off
@CreateDS(name = "SourceDS", enableAccessControl = false, allowAnonAccess = false, enableChangeLog = true, partitions = {
        @CreatePartition(name = "source", suffix = "dc=example,dc=com", indexes = {
                @CreateIndex(attribute = "objectClass"), @CreateIndex(attribute = "dc"), 
                @CreateIndex(attribute = "ou"),
                @CreateIndex(attribute = "krb5PrincipalName") }) })
//@formatter:on
@CreateLdapServer(transports = { @CreateTransport(protocol = "LDAP") })
@CreateKdcServer(transports = { @CreateTransport(protocol = "TCP", address = "127.0.0.1", port = 6086),
        @CreateTransport(protocol = "KRB", address = "127.0.0.1", port = 6088) })
@ApplyLdifFiles("single-realm/directory-server/principals.ldif")
public class EmbeddedKerberos101 extends AbstractLdapTestUnit {

    // paths
    private static final Path BASE_PATH = Paths.get(System.getProperty("user.dir")).resolve("target")
            .resolve("test-classes");

    private static final Path KERBEROS_CONF_DIR = BASE_PATH.resolve("single-realm").resolve("kerberos");
    
    private static final Path KERBEROS_CLIENT_CONF_DIR = KERBEROS_CONF_DIR.resolve("client");

    public void beforeClass() {

        System.setProperty("sun.security.spnego.debug", "true");
        System.setProperty("sun.security.krb5.debug", "true");
        System.setProperty("java.security.krb5.realm", "EXAMPLE.COM");
        System.setProperty("java.security.krb5.kdc", "127.0.0.1:6088");

        // see:
        // https://docs.oracle.com/javase/8/docs/jre/api/security/jaas/spec/com/sun/security/auth/login/ConfigFile.html
        System.setProperty("java.security.auth.login.config", KERBEROS_CLIENT_CONF_DIR.resolve("kerberos.jaas").toString());
    }

    @Test
    public void test() {

        try {
            sun.security.krb5.Config.refresh();
        } catch (sun.security.krb5.KrbException e) {
            fail(e.getMessage());
        }
    }
}
