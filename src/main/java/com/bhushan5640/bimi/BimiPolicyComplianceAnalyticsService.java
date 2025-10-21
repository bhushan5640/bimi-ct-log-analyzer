package com.bhushan5640.bimi;

import com.bhushan5640.bimi.analyzer.SecurityAnalyzer;
import com.bhushan5640.bimi.db.BimiCertificate;
import com.bhushan5640.bimi.db.BimiCertificateRepository;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;

import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.LocalDate;
import java.time.ZoneId;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

public class BimiPolicyComplianceAnalyticsService {

    private final BimiCertificateRepository repository;

    // BIMI Policy OIDs
    private static final String MARK_CERT_POLICY_OID = "1.3.6.1.4.1.53087.1.1";
    private static final String BIMI_EKU_OID = "1.3.6.1.5.5.7.3.31";
    private static final String LOGOTYPE_EXT_OID = "1.3.6.1.5.5.7.1.12";

    // Subject DN OIDs
    private static final String MARK_TYPE_OID = "1.3.6.1.4.1.53087.1.13";
    private static final String TRADEMARK_OFFICE_OID = "1.3.6.1.4.1.53087.1.2";
    private static final String TRADEMARK_COUNTRY_OID = "1.3.6.1.4.1.53087.1.3";
    private static final String TRADEMARK_ID_OID = "1.3.6.1.4.1.53087.1.4";
    private static final String STATUTE_COUNTRY_OID = "1.3.6.1.4.1.53087.3.2";
    private static final String STATUTE_CITATION_OID = "1.3.6.1.4.1.53087.3.5";
    private static final String PRIOR_USE_URL_OID = "1.3.6.1.4.1.53087.5.1";

    public BimiPolicyComplianceAnalyticsService(BimiCertificateRepository repository) {
        this.repository = repository;
    }

    /**
     * Validates BIMI certificate policy compliance
     */
    public static class PolicyValidationResult {
        private final boolean isValid;
        private final List<String> errors;
        private final List<String> warnings;

        public PolicyValidationResult(boolean isValid, List<String> errors, List<String> warnings) {
            this.isValid = isValid;
            this.errors = errors;
            this.warnings = warnings;
        }

        public boolean isValid() { return isValid; }
        public List<String> getErrors() { return errors; }
        public List<String> getWarnings() { return warnings; }
    }

    /**
     * Validates BIMI certificate against policy requirements
     */
    public static PolicyValidationResult validateBimiCertificatePolicy(X509Certificate cert, String certificateType) {
        List<String> errors = new ArrayList<>();
        List<String> warnings = new ArrayList<>();

        try {
            // 1. Check required certificatePolicies extension
            if (!hasCertificatePolicy(cert, MARK_CERT_POLICY_OID)) {
                errors.add("Missing required Mark Certificate General Policy Identifier (1.3.6.1.4.1.53087.1.1) in certificatePolicies extension");
            }

            // 2. Check required Extended Key Usage
            if (!hasExtendedKeyUsage(cert, BIMI_EKU_OID)) {
                errors.add("Missing required BIMI EKU (1.3.6.1.5.5.7.3.31) in extKeyUsage extension");
            }

            // 3. Check required logotype extension and validate its content
            if (!hasExtension(cert, LOGOTYPE_EXT_OID)) {
                errors.add("Missing required logotype extension (1.3.6.1.5.5.7.1.12)");
            } else {
                // Validate logotype content according to BIMI specification
                BimiUtils.LogotypeValidationResult logotypeResult = BimiUtils.validateLogotypeExtension(cert);
                if (!logotypeResult.isValid()) {
                    errors.addAll(logotypeResult.getErrors());
                }
                warnings.addAll(logotypeResult.getWarnings());
            }

            // 4. Check subject DN requirements
            X500Name subject = new X500Name(cert.getSubjectX500Principal().getName());

            // markType is REQUIRED for all certificates
            String markType = getSubjectAttribute(subject, MARK_TYPE_OID);
            if (markType == null || markType.trim().isEmpty()) {
                LocalDate notBefore = cert.getNotBefore().toInstant().atZone(ZoneId.systemDefault()).toLocalDate();
                LocalDate thresholdDate = LocalDate.of(2024, 9, 26);
                if (!notBefore.isBefore(thresholdDate))
                {
                    // Certificate issued on or after Sept 26, 2024 - markType is required
                    errors.add("Missing required subject:markType (1.3.6.1.4.1.53087.1.13)");
                }
            } else {
                // Validate mark type specific requirements
                validateMarkTypeRequirements(cert, subject, markType, errors, warnings, certificateType);
            }

        } catch (Exception e) {
            errors.add("Error parsing certificate: " + e.getMessage());
        }

        boolean isValid = errors.isEmpty();
        return new PolicyValidationResult(isValid, errors, warnings);
    }

    private static void validateMarkTypeRequirements(X509Certificate cert, X500Name subject, String markType,
            List<String> errors, List<String> warnings, String certificateType) {

        switch (markType.toLowerCase()) {
            case "registered mark":
            case "modified registered mark":
                // Required for Registered Mark and Modified Registered Mark
                if (getSubjectAttribute(subject, TRADEMARK_COUNTRY_OID) == null) {
                    errors.add("Missing required subject:trademarkCountryOrRegionName (1.3.6.1.4.1.53087.1.3) for " + markType);
                }
                if (getSubjectAttribute(subject, TRADEMARK_ID_OID) == null) {
                    errors.add("Missing required subject:trademarkIdentifier (1.3.6.1.4.1.53087.1.4) for " + markType);
                }
                // trademarkOfficeName may be required when country has multiple IP agencies
                if (getSubjectAttribute(subject, TRADEMARK_OFFICE_OID) == null) {
                    // warnings.add("Missing subject:trademarkOfficeName (1.3.6.1.4.1.53087.1.2) - may be required for countries with multiple IP agencies");
                }
                break;

            case "government mark":
                // Required for Government Mark
                if (getSubjectAttribute(subject, STATUTE_COUNTRY_OID) == null) {
                    errors.add("Missing required subject:statuteCountryName (1.3.6.1.4.1.53087.3.2) for Government Mark");
                }
                if (getSubjectAttribute(subject, STATUTE_CITATION_OID) == null) {
                    errors.add("Missing required subject:statuteCitation (1.3.6.1.4.1.53087.3.5) for Government Mark");
                }
                break;

            case "prior use mark":
                // Required for Prior Use Mark (issued on or after April 15, 2025)
                LocalDate notBefore = cert.getNotBefore().toInstant().atZone(ZoneId.systemDefault()).toLocalDate();
                LocalDate thresholdDate = LocalDate.of(2025, 4, 15);

                if (!notBefore.isBefore(thresholdDate)) {
                    // Certificate issued on or after April 15, 2025 - priorUseMarkSourceURL is required
                    if (getSubjectAttribute(subject, PRIOR_USE_URL_OID) == null) {
                        errors.add("Missing required subject:priorUseMarkSourceURL (1.3.6.1.4.1.53087.5.1) for Prior Use Mark issued on or after April 15, 2025");
                    }
                } else {
                    // Certificate issued before April 15, 2025 - priorUseMarkSourceURL is not required
                    if (getSubjectAttribute(subject, PRIOR_USE_URL_OID) == null) {
                        warnings.add("Prior Use Mark issued before April 15, 2025 - priorUseMarkSourceURL not required but recommended");
                    }
                }
                break;

            default:
                warnings.add("Unknown mark type: " + markType);
        }

        // Cross-validate with certificate type
        if (certificateType != null) {
            boolean shouldBeVMC = markType.equalsIgnoreCase("registered mark") ||
                                 markType.equalsIgnoreCase("government mark");
            boolean shouldBeCMC = markType.equalsIgnoreCase("prior use mark") ||
                                 markType.equalsIgnoreCase("modified registered mark");

            if (shouldBeVMC && !"VMC".equals(certificateType)) {
                warnings.add("Mark type '" + markType + "' suggests VMC but certificate type is " + certificateType);
            } else if (shouldBeCMC && !"CMC".equals(certificateType)) {
                warnings.add("Mark type '" + markType + "' suggests CMC but certificate type is " + certificateType);
            }
        }
    }

    private static boolean hasCertificatePolicy(X509Certificate cert, String policyOid) {
        try {
            var extensions = BimiUtils.getExtensions(cert);
            var policiesExt = extensions.getExtension(new ASN1ObjectIdentifier("2.5.29.32"));
            if (policiesExt == null) return false;

            // Parse certificate policies - simplified approach
            var policiesSeq = org.bouncycastle.asn1.ASN1Sequence.getInstance(policiesExt.getParsedValue());
            for (int i = 0; i < policiesSeq.size(); i++) {
                var policyInfo = org.bouncycastle.asn1.ASN1Sequence.getInstance(policiesSeq.getObjectAt(i));
                if (policyInfo.size() > 0) {
                    var oid = ASN1ObjectIdentifier.getInstance(policyInfo.getObjectAt(0));
                    if (policyOid.equals(oid.getId())) {
                        return true;
                    }
                }
            }
        } catch (Exception e) {
            // Fallback to string search
            byte[] policyExt = cert.getExtensionValue("2.5.29.32");
            if (policyExt != null) {
                return new String(policyExt).contains(policyOid);
            }
        }
        return false;
    }

    private static boolean hasExtendedKeyUsage(X509Certificate cert, String ekuOid) {
        try {
            List<String> ekuList = cert.getExtendedKeyUsage();
            return ekuList != null && ekuList.contains(ekuOid);
        } catch (Exception e) {
            return false;
        }
    }

    private static boolean hasExtension(X509Certificate cert, String oid) {
        try {
            return cert.getExtensionValue(oid) != null;
        } catch (Exception e) {
            return false;
        }
    }

    private static String getSubjectAttribute(X500Name subject, String oid) {
        try {
            ASN1ObjectIdentifier objectId = new ASN1ObjectIdentifier(oid);
            RDN[] rdns = subject.getRDNs(objectId);
            if (rdns != null && rdns.length > 0 && rdns[0].getFirst() != null) {
                return rdns[0].getFirst().getValue().toString();
            }
        } catch (Exception e) {
            // Ignore parsing errors
        }
        return null;
    }

    public void analyzeCerts() throws CertificateException {
        List<BimiCertificate> certificates = repository.findAll();
        var countVmc = 0;
        var countCmc = 0;
        var unknownCount = 0;
        var validCertificates = 0;
        var invalidCertificates = 0;

        Map<String, Integer> errorCounts = new java.util.HashMap<>();
        Map<String, Integer> warningCounts = new java.util.HashMap<>();

        for (BimiCertificate cert : certificates) {
            try {
                X509Certificate x509Cert = BimiUtils.makeCertFromDER(cert.getDer());
                String markType = BimiUtils.getMarkType(x509Cert);

                if ("VMC".equals(cert.getCertificateType())) {
                    countVmc++;
                } else if ("CMC".equals(cert.getCertificateType())) {
                    countCmc++;
                } else {
                    unknownCount++;
                }

                PolicyValidationResult validation = validateBimiCertificatePolicy(x509Cert, cert.getCertificateType());

                if (validation.isValid()) {
                    validCertificates++;
                } else {
                    invalidCertificates++;

                    for (String error : validation.getErrors()) {
                        String errorKey = error;
                        if (error.startsWith("SVG file size")) {
                            errorKey = "SVG file size exceeds recommended limit of 32KB";
                        }
                        errorCounts.put(errorKey, errorCounts.getOrDefault(errorKey, 0) + 1);
                    }

                    System.out.println("\n=== POLICY VALIDATION FAILED ===");
                    System.out.println("Certificate ID: " + bytesToHex(cert.getCertId()));
                    System.out.println("Brand Name: " + cert.getBrandName());
                    System.out.println("Certificate Type: " + cert.getCertificateType());
                    System.out.println("Not Before: " + x509Cert.getNotBefore() + ", Not After: " + x509Cert.getNotAfter());
                    System.out.println("Subject: " + BimiUtils.getSubjectAlternativeNames(x509Cert));
                    System.out.println("Issuer: " + x509Cert.getIssuerX500Principal().getName());
                    System.out.println("Precertificate: " + (BimiUtils.isPrecert(x509Cert) ? "Yes" : "No"));
                    System.out.println("Errors:");
                    for (String error : validation.getErrors()) {
                        System.out.println("  - " + error);
                    }
                    if (!validation.getWarnings().isEmpty()) {
                        System.out.println("Warnings:");
                        for (String warning : validation.getWarnings()) {
                            System.out.println("  - " + warning);
                        }
                    }
                }

                for (String warning : validation.getWarnings()) {
                    String warningKey = warning;
                    if (warning.contains("aspect ratio")) {
                        warningKey = "SVG should be square for optimal display";
                    }
                    warningCounts.put(warningKey, warningCounts.getOrDefault(warningKey, 0) + 1);
                }

            } catch (Exception e) {
                System.err.println("Error processing certificate ID " + bytesToHex(cert.getCertId()) + ": " + e.getMessage());
                invalidCertificates++;
                String processingError = "Certificate Processing Error: " + e.getMessage();
                errorCounts.put(processingError, errorCounts.getOrDefault(processingError, 0) + 1);
            }
        }

        System.out.println("\n=== ANALYSIS SUMMARY ===");
        System.out.println("VMC: " + countVmc + ", CMC: " + countCmc + ", UNKNOWN: " + unknownCount);
        System.out.println("Valid certificates: " + validCertificates);
        System.out.println("Invalid certificates: " + invalidCertificates);
        System.out.println("Total processed: " + (validCertificates + invalidCertificates));

        printErrorAndWarningSummary(errorCounts, warningCounts);
    }

    /**
     * Prints a formatted summary of errors and warnings by exact message
     */
    private void printErrorAndWarningSummary(Map<String, Integer> errorCounts, Map<String, Integer> warningCounts) {
        System.out.println("\n=== ERROR SUMMARY BY EXACT MESSAGE ===");
        if (errorCounts.isEmpty()) {
            System.out.println("No policy violations found!");
        } else {
            // Sort by count (descending) for better readability
            errorCounts.entrySet().stream()
                .sorted(Map.Entry.<String, Integer>comparingByValue().reversed())
                .forEach(entry ->
                    System.out.printf("Count: %d - %s%n", entry.getValue(), entry.getKey()));

            int totalErrors = errorCounts.values().stream().mapToInt(Integer::intValue).sum();
            System.out.printf("%nTotal policy violations: %d%n", totalErrors);
        }

        System.out.println("\n=== WARNING SUMMARY BY EXACT MESSAGE ===");
        if (warningCounts.isEmpty()) {
            System.out.println("No warnings found!");
        } else {
            // Sort by count (descending) for better readability
            warningCounts.entrySet().stream()
                .sorted(Map.Entry.<String, Integer>comparingByValue().reversed())
                .forEach(entry ->
                    System.out.printf("Count: %d - %s%n", entry.getValue(), entry.getKey()));

            int totalWarnings = warningCounts.values().stream().mapToInt(Integer::intValue).sum();
            System.out.printf("%nTotal warnings: %d%n", totalWarnings);
        }

        // Print most common issues
        if (!errorCounts.isEmpty() || !warningCounts.isEmpty()) {
            System.out.println("\n=== MOST COMMON ISSUES ===");

            if (!errorCounts.isEmpty()) {
                var mostCommonError = errorCounts.entrySet().stream()
                    .max(Map.Entry.comparingByValue())
                    .orElse(null);
                if (mostCommonError != null) {
                    System.out.println("Most common error (" + mostCommonError.getValue() + " certificates):");
                    System.out.println("  " + mostCommonError.getKey());
                }
            }

            if (!warningCounts.isEmpty()) {
                var mostCommonWarning = warningCounts.entrySet().stream()
                    .max(Map.Entry.comparingByValue())
                    .orElse(null);
                if (mostCommonWarning != null) {
                    System.out.println("Most common warning (" + mostCommonWarning.getValue() + " certificates):");
                    System.out.println("  " + mostCommonWarning.getKey());
                }
            }
        }
    }

    private static String bytesToHex(byte[] bytes) {
        return SecurityAnalyzer.bytesToHex(bytes);
    }
}
