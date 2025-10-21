package com.bhushan5640.bimi;

import com.bhushan5640.bimi.analyzer.SecurityAnalyzer;
import com.bhushan5640.bimi.db.BimiCertificate;
import com.bhushan5640.bimi.db.BimiCertificateRepository;

import java.util.*;

/**
 * Refactored security analytics service for BIMI certificates.
 * This version is database-agnostic and uses dependency injection.
 */
public class BimiSecurityAnalyticsService {

    private final BimiCertificateRepository repository;
    private final SecurityAnalyzer analyzer;

    public BimiSecurityAnalyticsService(BimiCertificateRepository repository) {
        this.repository = repository;
        this.analyzer = new SecurityAnalyzer();
    }

    /**
     * Comprehensive security analysis of BIMI certificates
     */
    public Map<String, Object> getSecurityAnalytics() {
        Map<String, Object> analytics = new HashMap<>();

        analytics.put("brandNameInSvgTitle", analyzeBrandNameInSvgTitle());
        analytics.put("suspiciousSvgContent", analyzeSuspiciousSvgContent());
        analytics.put("unicodeHomographs", analyzeUnicodeHomographs());
        analytics.put("lookalikeBrands", analyzeLookalikeBrands());
        analytics.put("hiddenContent", analyzeHiddenContent());
        analytics.put("obfuscatedContent", analyzeObfuscatedContent());
        analytics.put("suspiciousUrls", analyzeSuspiciousUrls());
        analytics.put("oversizedLogos", analyzeOversizedLogos());

        return analytics;
    }

    /**
     * Analyzes SVG content for suspicious patterns
     */
    public Map<String, Object> analyzeSuspiciousSvgContent() {
        List<BimiCertificate> certificates = repository.findAllWithLogoContent();
        List<Map<String, Object>> suspiciousCerts = new ArrayList<>();

        for (BimiCertificate cert : certificates) {
            List<String> suspiciousPatterns = analyzer.detectSuspiciousSvgPatterns(cert.getLogoSvgContent());

            if (!suspiciousPatterns.isEmpty()) {
                Map<String, Object> suspiciousCert = new HashMap<>();
                suspiciousCert.put("certId", SecurityAnalyzer.bytesToHex(cert.getCertId()));
                suspiciousCert.put("domain", cert.getNames());
                suspiciousCert.put("brandName", cert.getBrandName());
                suspiciousCert.put("issuer", cert.getIssuer());
                suspiciousCert.put("certificateType", cert.getCertificateType());
                suspiciousCert.put("suspiciousPatterns", suspiciousPatterns);
                suspiciousCert.put("riskLevel", analyzer.calculateRiskLevel(suspiciousPatterns));
                suspiciousCerts.add(suspiciousCert);
            }
        }

        Map<String, Object> analysis = new HashMap<>();
        analysis.put("totalCertificatesAnalyzed", certificates.size());
        analysis.put("suspiciousCertificatesCount", suspiciousCerts.size());
        analysis.put("suspiciousPercentage", certificates.size() > 0 ?
            (double) suspiciousCerts.size() / certificates.size() * 100 : 0);
        analysis.put("suspiciousCertificates", suspiciousCerts);

        return analysis;
    }

    /**
     * Analyzes Unicode homograph attacks in brand names and subjects
     */
    public Map<String, Object> analyzeUnicodeHomographs() {
        List<BimiCertificate> certificates = repository.findAllWithBrandName();
        List<Map<String, Object>> homographs = new ArrayList<>();

        for (BimiCertificate cert : certificates) {
            List<String> suspiciousChars = analyzer.detectUnicodeHomographs(
                cert.getBrandName(), cert.getSubject()
            );

            if (!suspiciousChars.isEmpty()) {
                Map<String, Object> homograph = new HashMap<>();
                homograph.put("certId", SecurityAnalyzer.bytesToHex(cert.getCertId()));
                homograph.put("domain", cert.getNames());
                homograph.put("brandName", cert.getBrandName());
                homograph.put("subject", cert.getSubject());
                homograph.put("issuer", cert.getIssuer());
                homograph.put("certificateType", cert.getCertificateType());
                homograph.put("suspiciousCharacters", suspiciousChars);
                homographs.add(homograph);
            }
        }

        Map<String, Object> analysis = new HashMap<>();
        analysis.put("totalCertificatesChecked", certificates.size());
        analysis.put("homographAttacksDetected", homographs.size());
        analysis.put("homographPercentage", !certificates.isEmpty() ?
            (double) homographs.size() / certificates.size() * 100 : 0);
        analysis.put("homographs", homographs);

        return analysis;
    }

    /**
     * Detects lookalike brands that might be impersonating major brands
     */
    public Map<String, Object> analyzeLookalikeBrands() {
        List<BimiCertificate> certificates = repository.findAllWithBrandName();
        List<Map<String, Object>> lookalikes = new ArrayList<>();

        for (BimiCertificate cert : certificates) {
            String targetBrand = analyzer.findLookalikeBrand(cert.getBrandName());
            if (targetBrand != null) {
                Map<String, Object> lookalike = new HashMap<>();
                lookalike.put("certId", SecurityAnalyzer.bytesToHex(cert.getCertId()));
                lookalike.put("suspiciousBrandName", cert.getBrandName());
                lookalike.put("targetBrand", targetBrand);
                lookalike.put("issuer", cert.getIssuer());
                lookalike.put("subject", cert.getSubject());
                lookalike.put("certificateType", cert.getCertificateType());
                lookalike.put("levenshteinDistance",
                    analyzer.levenshteinDistance(cert.getBrandName().toLowerCase(), targetBrand));
                lookalikes.add(lookalike);
            }
        }

        Map<String, Object> analysis = new HashMap<>();
        analysis.put("totalBrandCertificates", certificates.size());
        analysis.put("lookalikeBrandsDetected", lookalikes.size());
        analysis.put("lookalikeBrandsPercentage", certificates.size() > 0 ?
            (double) lookalikes.size() / certificates.size() * 100 : 0);
        analysis.put("lookalikes", lookalikes);

        return analysis;
    }

    /**
     * Analyzes hidden content in SVG logos
     */
    public Map<String, Object> analyzeHiddenContent() {
        List<BimiCertificate> certificates = repository.findAllWithLogoContent();
        List<Map<String, Object>> hiddenContent = new ArrayList<>();

        for (BimiCertificate cert : certificates) {
            List<String> hiddenElements = analyzer.detectHiddenElements(cert.getLogoSvgContent());

            if (!hiddenElements.isEmpty()) {
                Map<String, Object> hidden = new HashMap<>();
                hidden.put("certId", SecurityAnalyzer.bytesToHex(cert.getCertId()));
                hidden.put("brandName", cert.getBrandName());
                hidden.put("issuer", cert.getIssuer());
                hidden.put("certificateType", cert.getCertificateType());
                hidden.put("hiddenElements", hiddenElements);
                hidden.put("hiddenElementsCount", hiddenElements.size());
                hiddenContent.add(hidden);
            }
        }

        Map<String, Object> analysis = new HashMap<>();
        analysis.put("totalSvgCertificates", certificates.size());
        analysis.put("certificatesWithHiddenContent", hiddenContent.size());
        analysis.put("hiddenContentPercentage", certificates.size() > 0 ?
            (double) hiddenContent.size() / certificates.size() * 100 : 0);
        analysis.put("hiddenContentCertificates", hiddenContent);

        return analysis;
    }

    /**
     * Analyzes obfuscated content and invisible characters
     */
    public Map<String, Object> analyzeObfuscatedContent() {
        List<BimiCertificate> certificates = repository.findAll();
        List<Map<String, Object>> obfuscated = new ArrayList<>();

        for (BimiCertificate cert : certificates) {
            List<String> obfuscationTechniques = analyzer.detectObfuscation(
                cert.getBrandName(), cert.getLogoSvgContent(), cert.getSubject()
            );

            if (!obfuscationTechniques.isEmpty()) {
                Map<String, Object> obfuscatedCert = new HashMap<>();
                obfuscatedCert.put("certId", SecurityAnalyzer.bytesToHex(cert.getCertId()));
                obfuscatedCert.put("brandName", cert.getBrandName());
                obfuscatedCert.put("issuer", cert.getIssuer());
                obfuscatedCert.put("certificateType", cert.getCertificateType());
                obfuscatedCert.put("obfuscationTechniques", obfuscationTechniques);
                obfuscated.add(obfuscatedCert);
            }
        }

        Map<String, Object> analysis = new HashMap<>();
        analysis.put("totalCertificatesAnalyzed", certificates.size());
        analysis.put("obfuscatedCertificates", obfuscated.size());
        analysis.put("obfuscationPercentage", certificates.size() > 0 ?
            (double) obfuscated.size() / certificates.size() * 100 : 0);
        analysis.put("obfuscatedContent", obfuscated);

        return analysis;
    }

    /**
     * Analyzes suspicious URLs in SVG content
     */
    public Map<String, Object> analyzeSuspiciousUrls() {
        List<BimiCertificate> certificates = repository.findAllWithLogoContent();
        List<Map<String, Object>> suspiciousUrls = new ArrayList<>();

        for (BimiCertificate cert : certificates) {
            List<String> urls = analyzer.extractUrls(cert.getLogoSvgContent());

            if (!urls.isEmpty()) {
                Map<String, Object> suspiciousUrl = new HashMap<>();
                suspiciousUrl.put("certId", SecurityAnalyzer.bytesToHex(cert.getCertId()));
                suspiciousUrl.put("brandName", cert.getBrandName());
                suspiciousUrl.put("issuer", cert.getIssuer());
                suspiciousUrl.put("certificateType", cert.getCertificateType());
                suspiciousUrl.put("urls", urls);
                suspiciousUrl.put("urlCount", urls.size());
                suspiciousUrls.add(suspiciousUrl);
            }
        }

        Map<String, Object> analysis = new HashMap<>();
        analysis.put("totalSvgCertificates", certificates.size());
        analysis.put("certificatesWithUrls", suspiciousUrls.size());
        analysis.put("urlsPercentage", certificates.size() > 0 ?
            (double) suspiciousUrls.size() / certificates.size() * 100 : 0);
        analysis.put("suspiciousUrls", suspiciousUrls);

        return analysis;
    }

    /**
     * Analyzes oversized logos that might contain hidden payloads
     */
    public Map<String, Object> analyzeOversizedLogos() {
        List<BimiCertificate> certificates = repository.findAllWithLogoContent();

        // Calculate statistics
        double avgSize = certificates.stream()
            .filter(cert -> cert.getLogoSvgContent() != null)
            .mapToInt(cert -> cert.getLogoSvgContent().getBytes().length)
            .average()
            .orElse(0);

        double threshold = avgSize * 3; // 3x average size

        List<Map<String, Object>> oversized = new ArrayList<>();
        for (BimiCertificate cert : certificates) {
            if (cert.getLogoSvgContent() != null) {
                int size = cert.getLogoSvgContent().getBytes().length;
                if (size > threshold) {
                    Map<String, Object> oversizedLogo = new HashMap<>();
                    oversizedLogo.put("certId", SecurityAnalyzer.bytesToHex(cert.getCertId()));
                    oversizedLogo.put("brandName", cert.getBrandName());
                    oversizedLogo.put("issuer", cert.getIssuer());
                    oversizedLogo.put("certificateType", cert.getCertificateType());
                    oversizedLogo.put("svgSize", size);
                    oversizedLogo.put("sizeRatio", size / avgSize);
                    oversized.add(oversizedLogo);
                }
            }
        }

        Map<String, Object> analysis = new HashMap<>();
        analysis.put("totalSvgCertificates", certificates.size());
        analysis.put("averageSvgSize", Math.round(avgSize));
        analysis.put("oversizedThreshold", Math.round(threshold));
        analysis.put("oversizedLogos", oversized.size());
        analysis.put("oversizedPercentage", certificates.size() > 0 ?
            (double) oversized.size() / certificates.size() * 100 : 0);
        analysis.put("oversizedLogosList", oversized);

        return analysis;
    }

    /**
     * Analyzes BIMI certificates to check if the brand name is present in the SVG <title> element.
     * Returns certificates where the brand name is NOT present in the SVG <title>.
     */
    public Map<String, Object> analyzeBrandNameInSvgTitle() {
        List<BimiCertificate> certificates = repository.findAllActiveWithLogoAndBrandName();
        List<Map<String, Object>> missingBrandInTitle = new ArrayList<>();

        long totalCertificateSize = 0;
        long totalLogoSize = 0;

        for (BimiCertificate cert : certificates) {
            if (cert.getDer() != null) {
                totalCertificateSize += cert.getDer().length;
            }
            if (cert.getLogoSvgContent() != null) {
                totalLogoSize += cert.getLogoSvgContent().getBytes().length;
            }

            boolean found = analyzer.brandNameInSvgTitle(cert.getLogoSvgContent(), cert.getBrandName());
            if (!found) {
                Map<String, Object> certMap = new HashMap<>();
                certMap.put("certId", SecurityAnalyzer.bytesToHex(cert.getCertId()));
                certMap.put("domain", cert.getNames());
                certMap.put("brandName", cert.getBrandName());
                certMap.put("issuer", cert.getIssuer());
                certMap.put("certificateType", cert.getCertificateType());
                certMap.put("svgTitle", extractSvgTitle(cert.getLogoSvgContent()));
                certMap.put("names", cert.getNames());
                missingBrandInTitle.add(certMap);
            }
        }

        Map<String, Object> analysis = new HashMap<>();
        analysis.put("totalCertificatesAnalyzed", certificates.size());
        analysis.put("averageCertificateSize", certificates.size() > 0 ?
            (double) totalCertificateSize / certificates.size() : 0);
        analysis.put("averageLogoSize", certificates.size() > 0 ?
            (double) totalLogoSize / certificates.size() : 0);
        analysis.put("certificatesMissingBrandInTitle", missingBrandInTitle.size());
        analysis.put("missingBrandInTitlePercentage", certificates.size() > 0 ?
            (double) missingBrandInTitle.size() / certificates.size() * 100 : 0);
        analysis.put("certificates", missingBrandInTitle);

        return analysis;
    }

    private String extractSvgTitle(String svgContent) {
        if (svgContent == null) return null;
        return svgContent.replaceAll("(?s).*<title>(.*?)</title>.*", "$1").trim();
    }
}
