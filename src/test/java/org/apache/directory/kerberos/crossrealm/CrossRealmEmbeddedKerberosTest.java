package org.apache.directory.kerberos.crossrealm;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.fail;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

import org.apache.directory.server.core.integ.AbstractLdapTestUnit;
import org.apache.kerby.kerberos.kerb.KrbException;
import org.apache.kerby.kerberos.kerb.admin.kadmin.local.LocalKadmin;
import org.apache.kerby.kerberos.kerb.admin.kadmin.local.LocalKadminImpl;
import org.apache.kerby.kerberos.kerb.client.KrbClient;
import org.apache.kerby.kerberos.kerb.server.KdcServer;
import org.apache.kerby.kerberos.kerb.type.ticket.SgtTicket;
import org.apache.kerby.kerberos.kerb.type.ticket.TgtTicket;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExternalResource;

/**
 * @author morgany
 */
public class CrossRealmEmbeddedKerberosTest extends AbstractLdapTestUnit {

    // see:
    // https://web.mit.edu/kerberos/krb5-1.12/doc/admin/conf_files/krb5_conf.html
    private static final String KRB5_CONFIG_ENVIRONMENT_VARIABLE = System.getenv("KRB5_CONFIG");
    
    private static final String SOURCE_REALM_NAME = "SOURCEREALM.EXAMPLE.COM";
    private static final String TARGET_REALM_NAME = "TARGETREALM.EXAMPLE.COM";
    // paths
    private static final Path BASE_PATH = Paths.get(System.getProperty("user.dir")).resolve("target")
            .resolve("test-classes").resolve("cross-realm");

    private static final Path KERBEROS_ROOT_DIR = BASE_PATH.resolve("kerberos");
    
    private static final Path KERBEROS_CLIENT_CONF_DIR = KERBEROS_ROOT_DIR.resolve("client");
    
    private static final Path KERBEROS_SERVERS_CONF_DIR = KERBEROS_ROOT_DIR.resolve("server");

    private static final Path KERBEROS_KDC_SOURCE_DIR = KERBEROS_SERVERS_CONF_DIR.resolve("source");

    private static final Path KERBEROS_KDC_TARGET_DIR = KERBEROS_SERVERS_CONF_DIR.resolve("target");

    // principal names
    private static final String KRBTGT_SOURCEREALM_AT_TARGETREALM_PRINCIPAL_NAME = "krbtgt/" + SOURCE_REALM_NAME + "@"
            + TARGET_REALM_NAME;

    private static final String KAFKA_HOST1_AT_SOURCEREALM_PRINCIPAL_NAME = "kafka/host1.example.sourcedomain.com@"
            + SOURCE_REALM_NAME;

    private static final String HIVE_HOST2_AT_TARGETREALM_PRINCIPAL_NAME = "hive/host2.example.targetdomain.com@"
            + TARGET_REALM_NAME;

    private static final String KAFKA_CONSUMER_AT_TARGETREALM_PRINCIPAL_NAME = "kafka_consumer@" + TARGET_REALM_NAME;

    // keytabs
    private static final File KAFKA_CONSUMER_AT_TARGETREALM_KEYTAB_FILE = KERBEROS_KDC_TARGET_DIR
            .resolve("kafka_consumer.keytab").toFile();

    @Rule
    public ExternalResource resource = getExternalResource();

    private ExternalResource getExternalResource() {
        return new ExternalResource() {

            private KdcServer sourceKerbyServer;
            private KdcServer targetKerbyServer;

            @Override
            protected void before() throws Throwable {

                LocalKadmin sourceLocalKadmin;
                LocalKadmin targetLocalKadmin;
                
                System.setProperty("javax.net.debug","all");
                System.setProperty("sun.security.spnego.debug", "true");
                System.setProperty("sun.security.krb5.debug", "true");

                // cleanup last run
                Files.deleteIfExists(KAFKA_CONSUMER_AT_TARGETREALM_KEYTAB_FILE.toPath());

                sourceKerbyServer = new KdcServer(KERBEROS_KDC_SOURCE_DIR.toFile());
                targetKerbyServer = new KdcServer(KERBEROS_KDC_TARGET_DIR.toFile());

                // enable debug
                sourceKerbyServer.enableDebug();
                targetKerbyServer.enableDebug();

                // initialize kdcs before add principals
                sourceKerbyServer.init();
                targetKerbyServer.init();

                // create local Kadmin
                sourceLocalKadmin = createLocalKadmin(sourceKerbyServer);
                targetLocalKadmin = createLocalKadmin(targetKerbyServer);

                // add principals to source kdc and export keytab
                sourceLocalKadmin.addPrincipal(KAFKA_HOST1_AT_SOURCEREALM_PRINCIPAL_NAME);

                // add principals to target kdc and export keytabs
                targetLocalKadmin.addPrincipal(KAFKA_CONSUMER_AT_TARGETREALM_PRINCIPAL_NAME);
                targetLocalKadmin.exportKeytab(KAFKA_CONSUMER_AT_TARGETREALM_KEYTAB_FILE,
                        KAFKA_CONSUMER_AT_TARGETREALM_PRINCIPAL_NAME);

                targetLocalKadmin.addPrincipal(HIVE_HOST2_AT_TARGETREALM_PRINCIPAL_NAME);

                // start kdcs listeners
                sourceKerbyServer.start();
                targetKerbyServer.start();
            }

            @Override
            protected void after() {
                try {
                    sourceKerbyServer.stop();
                } catch (KrbException e) {
                    e.printStackTrace();
                }
                try {
                    targetKerbyServer.stop();
                } catch (KrbException e) {
                    e.printStackTrace();
                }
            }

            private LocalKadmin createLocalKadmin(KdcServer kdcServer) throws KrbException {

                LocalKadmin kadmin = new LocalKadminImpl(kdcServer.getKdcSetting(), kdcServer.getIdentityService());

                kadmin.createBuiltinPrincipals();
                // secret sauce: Cross Realm Ticket Granting Service.
                kadmin.addPrincipal(KRBTGT_SOURCEREALM_AT_TARGETREALM_PRINCIPAL_NAME, "krbtgt123");

                return kadmin;
            }
        };
    }

    @SuppressWarnings("restriction")
    @Test
    public void test() throws KrbException {

        TgtTicket ticketGrantTicket;
        SgtTicket kafkaServiceGrantTicket;
        SgtTicket hiveServiceGrantTicket;
        KrbClient krbClient = new KrbClient(KERBEROS_CLIENT_CONF_DIR.toFile());

        // client initialization
        krbClient.init();

        ticketGrantTicket = krbClient.requestTgt(KAFKA_CONSUMER_AT_TARGETREALM_PRINCIPAL_NAME,
                KAFKA_CONSUMER_AT_TARGETREALM_KEYTAB_FILE);
        assertNotNull(ticketGrantTicket);

        kafkaServiceGrantTicket = krbClient.requestSgt(ticketGrantTicket, KAFKA_HOST1_AT_SOURCEREALM_PRINCIPAL_NAME);
        assertNotNull(kafkaServiceGrantTicket);

        hiveServiceGrantTicket = krbClient.requestSgt(ticketGrantTicket, HIVE_HOST2_AT_TARGETREALM_PRINCIPAL_NAME);
        assertNotNull(hiveServiceGrantTicket);

        // setup krb5 conf (see:
        // https://docs.oracle.com/javase/8/docs/technotes/guides/security/jgss/tutorials/KerberosReq.html )
        System.setProperty("java.security.krb5.conf",
                KRB5_CONFIG_ENVIRONMENT_VARIABLE == null ? KERBEROS_CLIENT_CONF_DIR.resolve("krb5.conf").toString()
                        : KRB5_CONFIG_ENVIRONMENT_VARIABLE);
        // see:
        // https://docs.oracle.com/javase/8/docs/jre/api/security/jaas/spec/com/sun/security/auth/login/ConfigFile.html
        System.setProperty("java.security.auth.login.config", KERBEROS_CLIENT_CONF_DIR.resolve("kerberos.jaas").toString());
        
        try {
            sun.security.krb5.Config.refresh();
        } catch (sun.security.krb5.KrbException e) {
            fail(e.getMessage());
        }
    }
}
