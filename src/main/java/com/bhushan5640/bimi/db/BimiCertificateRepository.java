package com.bhushan5640.bimi.db;

import java.util.List;

/**
 * Repository interface for BIMI certificate data access.
 * Implement this interface to adapt to your specific database schema and structure.
 */
public interface BimiCertificateRepository {

    /**
     * Find all certificates with non-null logo SVG content.
     * Used for analyzing SVG-related security issues.
     *
     * @return List of certificates with SVG logos
     */
    List<BimiCertificate> findAllWithLogoContent();

    /**
     * Find all certificates with non-null brand names.
     * Used for brand-related analytics and lookalike detection.
     *
     * @return List of certificates with brand names
     */
    List<BimiCertificate> findAllWithBrandName();

    /**
     * Find all certificates with both logo content and brand name.
     * Used for cross-validation between brand name and SVG title.
     *
     * @return List of certificates with both logo and brand name
     */
    List<BimiCertificate> findAllWithLogoAndBrandName();

    /**
     * Find all active (non-expired) certificates with logo and brand name.
     * Used for current security analysis.
     *
     * @return List of active certificates
     */
    List<BimiCertificate> findAllActiveWithLogoAndBrandName();

    /**
     * Find all certificates.
     * Used for comprehensive analysis.
     *
     * @return List of all certificates
     */
    List<BimiCertificate> findAll();
}

