package com.bhushan5640.bimi;

import com.bhushan5640.bimi.db.BimiCertificate;
import com.bhushan5640.bimi.db.BimiCertificateRepository;
import com.bhushan5640.bimi.db.JdbcBimiCertificateRepository;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;

import java.security.cert.X509Certificate;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Integration test for BIMI certificate analysis against real PostgreSQL database.
 *
 * This test requires:
 * - PostgreSQL running on localhost:5432
 * - Database 'ctcerts' with table 'bimi_certs'
 * - User 'postgres' with password 'test'
 *
 * Enable by setting environment variable: BIMI_DB_TEST=true
 */
@EnabledIfEnvironmentVariable(named = "BIMI_DB_TEST", matches = "true")
class BimiCertificateAnalysisTest {

    private static final String DB_URL = "jdbc:postgresql://localhost:5432/ctcerts?reWriteBatchedInserts=true";
    private static final String DB_USERNAME = "postgres";
    private static final String DB_PASSWORD = "admin";
    private static final String TABLE_NAME = "bimi_certs";

    private static BimiCertificateRepository repository;
    private static BimiPolicyComplianceAnalyticsService analyzer;

    @BeforeAll
    static void setUp() {
        // Configure column mapping to match the database schema
        JdbcBimiCertificateRepository.ColumnMapping columnMapping =
            JdbcBimiCertificateRepository.ColumnMapping.defaultMapping()
                .withCertId("cert_id")
                .withDer("der")
                .withBrandName("brand_name")
                .withSubject("subject")
                .withIssuer("issuer")
                .withCertificateType("certificate_type")
                .withLogoSvgContent("logo_svg_content")
                .withNames("names")
                .withNotAfter("not_after")
                .withCreatedOn("created_on");

        // Initialize repository
        repository = new JdbcBimiCertificateRepository(
            DB_URL,
            DB_USERNAME,
            DB_PASSWORD,
            TABLE_NAME,
            columnMapping
        );

        // Initialize analyzer
        analyzer = new BimiPolicyComplianceAnalyticsService(repository);
    }

    @Test
    void testDatabaseConnection() {
        assertNotNull(repository, "Repository should be initialized");

        // Test basic database connectivity by fetching all certificates
        List<BimiCertificate> certificates = repository.findAll();
        assertNotNull(certificates, "Certificate list should not be null");

        System.out.println("✓ Successfully connected to database");
        System.out.println("✓ Found " + certificates.size() + " certificates in the database");
    }

    @Test
    void testFindAllCertificates() {
        List<BimiCertificate> certificates = repository.findAll();

        assertNotNull(certificates, "Certificate list should not be null");
        assertFalse(certificates.isEmpty(), "Should have at least one certificate in the database");

        // Verify certificate data structure
        BimiCertificate firstCert = certificates.get(0);
        assertNotNull(firstCert.getCertId(), "Certificate ID should not be null");
        assertNotNull(firstCert.getDer(), "DER should not be null");
        assertNotNull(firstCert.getSubject(), "Subject should not be null");
        assertNotNull(firstCert.getIssuer(), "Issuer should not be null");

        System.out.println("✓ Certificate data structure validated");
        System.out.println("  - First cert ID: " + bytesToHex(firstCert.getCertId()));
        System.out.println("  - Brand name: " + firstCert.getBrandName());
        System.out.println("  - Certificate type: " + firstCert.getCertificateType());
    }

    @Test
    void testFindCertificatesWithLogoContent() {
        List<BimiCertificate> certificates = repository.findAllWithLogoContent();

        assertNotNull(certificates, "Certificate list should not be null");

        System.out.println("✓ Found " + certificates.size() + " certificates with logo content");

        // Verify all returned certificates have logo content
        for (BimiCertificate cert : certificates) {
            assertNotNull(cert.getLogoSvgContent(),
                "Certificate should have logo content: " + bytesToHex(cert.getCertId()));
            assertFalse(cert.getLogoSvgContent().trim().isEmpty(),
                "Logo content should not be empty: " + bytesToHex(cert.getCertId()));
        }
    }

    @Test
    void testFindCertificatesWithBrandName() {
        List<BimiCertificate> certificates = repository.findAllWithBrandName();

        assertNotNull(certificates, "Certificate list should not be null");

        System.out.println("✓ Found " + certificates.size() + " certificates with brand name");

        // Verify all returned certificates have brand name
        for (BimiCertificate cert : certificates) {
            assertNotNull(cert.getBrandName(),
                "Certificate should have brand name: " + bytesToHex(cert.getCertId()));
            assertFalse(cert.getBrandName().trim().isEmpty(),
                "Brand name should not be empty: " + bytesToHex(cert.getCertId()));
        }
    }

    @Test
    void testCertificateTypeDistribution() {
        List<BimiCertificate> certificates = repository.findAll();

        int vmcCount = 0;
        int cmcCount = 0;
        int unknownCount = 0;

        for (BimiCertificate cert : certificates) {
            String certType = cert.getCertificateType();
            if ("VMC".equals(certType)) {
                vmcCount++;
            } else if ("CMC".equals(certType)) {
                cmcCount++;
            } else {
                unknownCount++;
            }
        }

        System.out.println("\n=== Certificate Type Distribution ===");
        System.out.println("VMC (Verified Mark Certificates): " + vmcCount);
        System.out.println("CMC (Common Mark Certificates): " + cmcCount);
        System.out.println("Unknown/Null: " + unknownCount);
        System.out.println("Total: " + certificates.size());

        assertTrue(vmcCount + cmcCount + unknownCount == certificates.size(),
            "All certificates should be categorized");
    }

    @Test
    void testParseCertificateFromDER() throws Exception {
        List<BimiCertificate> certificates = repository.findAll();
        assertFalse(certificates.isEmpty(), "Should have certificates to test");

        BimiCertificate cert = certificates.get(0);

        // Parse certificate from DER
        X509Certificate x509Cert = BimiUtils.makeCertFromDER(cert.getDer());

        assertNotNull(x509Cert, "X509Certificate should be parsed successfully");
        assertNotNull(x509Cert.getSubjectX500Principal(), "Subject should be present");
        assertNotNull(x509Cert.getIssuerX500Principal(), "Issuer should be present");

        System.out.println("\n✓ Successfully parsed certificate from DER");
        System.out.println("  - Subject: " + x509Cert.getSubjectX500Principal().getName());
        System.out.println("  - Issuer: " + x509Cert.getIssuerX500Principal().getName());
        System.out.println("  - Not Before: " + x509Cert.getNotBefore());
        System.out.println("  - Not After: " + x509Cert.getNotAfter());
    }

    @Test
    void testValidateBimiCertificatePolicy() throws Exception {
        List<BimiCertificate> certificates = repository.findAll();
        assertFalse(certificates.isEmpty(), "Should have certificates to test");

        int validCount = 0;
        int invalidCount = 0;

        // Test policy validation on first 10 certificates (or all if less than 10)
        int testLimit = Math.min(10, certificates.size());

        for (int i = 0; i < testLimit; i++) {
            BimiCertificate cert = certificates.get(i);
            X509Certificate x509Cert = BimiUtils.makeCertFromDER(cert.getDer());

            BimiPolicyComplianceAnalyticsService.PolicyValidationResult result =
                BimiPolicyComplianceAnalyticsService.validateBimiCertificatePolicy(x509Cert, cert.getCertificateType());

            assertNotNull(result, "Validation result should not be null");
            assertNotNull(result.getErrors(), "Errors list should not be null");
            assertNotNull(result.getWarnings(), "Warnings list should not be null");

            if (result.isValid()) {
                validCount++;
            } else {
                invalidCount++;
            }
        }

        System.out.println("\n=== Policy Validation Test Results ===");
        System.out.println("Tested: " + testLimit + " certificates");
        System.out.println("Valid: " + validCount);
        System.out.println("Invalid: " + invalidCount);

        assertTrue(validCount + invalidCount == testLimit, "All tested certificates should be validated");
    }

    @Test
    void testAnalyzeCertificatesFullRun() throws Exception {
        // This test runs the full analysis on all certificates
        System.out.println("\n=== Running Full Certificate Analysis ===");

        assertDoesNotThrow(() -> analyzer.analyzeCerts(),
            "Certificate analysis should complete without throwing exceptions");

        System.out.println("\n✓ Full analysis completed successfully");
    }

    @Test
    void testBimiUtilsFunctions() throws Exception {
        List<BimiCertificate> certificates = repository.findAll();
        assertFalse(certificates.isEmpty(), "Should have certificates to test");

        BimiCertificate cert = certificates.get(0);
        X509Certificate x509Cert = BimiUtils.makeCertFromDER(cert.getDer());

        // Test getMarkType
        String markType = BimiUtils.getMarkType(x509Cert);
        assertNotNull(markType, "Mark type should not be null");
        assertTrue(markType.equals("VMC") || markType.equals("CMC"),
            "Mark type should be either VMC or CMC");

        // Test getSubjectAlternativeNames
        List<String> sans = BimiUtils.getSubjectAlternativeNames(x509Cert);
        assertNotNull(sans, "SANs list should not be null");

        // Test isPrecert
        boolean isPrecert = BimiUtils.isPrecert(x509Cert);
        // Just verify it returns without error (can be true or false)

        System.out.println("\n✓ BimiUtils functions tested successfully");
        System.out.println("  - Mark Type: " + markType);
        System.out.println("  - SANs: " + sans);
        System.out.println("  - Is Precert: " + isPrecert);
    }

    @Test
    void testSecurityAnalytics() {
        BimiSecurityAnalyticsService securityService =
            new BimiSecurityAnalyticsService(repository);

        System.out.println("\n=== Testing Security Analytics ===");

        // Test suspicious SVG content analysis
        assertDoesNotThrow(() -> {
            var result = securityService.analyzeSuspiciousSvgContent();
            assertNotNull(result, "Suspicious SVG analysis result should not be null");
            System.out.println("✓ Suspicious SVG content analysis completed");
            System.out.println("  - Total analyzed: " + result.get("totalCertificatesAnalyzed"));
            System.out.println("  - Suspicious found: " + result.get("suspiciousCertificatesCount"));
        }, "Suspicious SVG analysis should complete without errors");

        // Test brand name in SVG title analysis
        assertDoesNotThrow(() -> {
            var result = securityService.analyzeBrandNameInSvgTitle();
            assertNotNull(result, "Brand name analysis result should not be null");
            System.out.println("✓ Brand name in SVG title analysis completed");
            System.out.println("  - Total analyzed: " + result.get("totalCertificatesAnalyzed"));
            System.out.println("  - Missing brand in title: " + result.get("certificatesMissingBrandInTitle"));
        }, "Brand name analysis should complete without errors");
    }

    private static String bytesToHex(byte[] bytes) {
        if (bytes == null) return null;
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}

