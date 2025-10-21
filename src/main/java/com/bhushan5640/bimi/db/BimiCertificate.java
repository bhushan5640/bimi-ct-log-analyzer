package com.bhushan5640.bimi.db;

import java.sql.Timestamp;
import java.time.Instant;

/**
 * Data model representing a BIMI (Brand Indicators for Message Identification) certificate.
 * This class contains all certificate-related information including brand details,
 * SVG logo content, and certificate metadata.
 */
public class BimiCertificate {

    private byte[] certId;
    private String names;
    private String brandName;
    private String issuer;
    private String certificateType;
    private String logoSvgContent;
    private String subject;
    private byte[] der;
    private Instant notAfter;
    private Instant notBefore;

    // Default constructor
    public BimiCertificate() {
    }

    // Full constructor
    public BimiCertificate(byte[] certId, String names, String brandName, String issuer,
                          String certificateType, String logoSvgContent, String subject, byte[] der) {
        this.certId = certId;
        this.names = names;
        this.brandName = brandName;
        this.issuer = issuer;
        this.certificateType = certificateType;
        this.logoSvgContent = logoSvgContent;
        this.subject = subject;
        this.der = der;
    }

    // Getters and Setters

    public byte[] getCertId() {
        return certId;
    }

    public void setCertId(byte[] certId) {
        this.certId = certId;
    }

    public String getNames() {
        return names;
    }

    public void setNames(String names) {
        this.names = names;
    }

    public String getBrandName() {
        return brandName;
    }

    public void setBrandName(String brandName) {
        this.brandName = brandName;
    }

    public String getIssuer() {
        return issuer;
    }

    public void setIssuer(String issuer) {
        this.issuer = issuer;
    }

    public String getCertificateType() {
        return certificateType;
    }

    public void setCertificateType(String certificateType) {
        this.certificateType = certificateType;
    }

    public String getLogoSvgContent() {
        return logoSvgContent;
    }

    public void setLogoSvgContent(String logoSvgContent) {
        this.logoSvgContent = logoSvgContent;
    }

    public String getSubject() {
        return subject;
    }

    public void setSubject(String subject) {
        this.subject = subject;
    }

    public byte[] getDer() {
        return der;
    }

    public void setDer(byte[] der) {
        this.der = der;
    }

    public Instant getNotAfter() {
        return notAfter;
    }

    public void setNotAfter(Instant notAfter) {
        this.notAfter = notAfter;
    }

    public Instant getNotBefore() {
        return notBefore;
    }

    public void setNotBefore(Instant notBefore) {
        this.notBefore = notBefore;
    }

    @Override
    public String toString() {
        return "BimiCertificate{" +
                "certId=" + (certId != null ? "byte[" + certId.length + "]" : "null") +
                ", names='" + names + '\'' +
                ", brandName='" + brandName + '\'' +
                ", issuer='" + issuer + '\'' +
                ", certificateType='" + certificateType + '\'' +
                ", logoSvgContent=" + (logoSvgContent != null ? "present(" + logoSvgContent.length() + " chars)" : "null") +
                ", subject='" + subject + '\'' +
                ", der=" + (der != null ? "byte[" + der.length + "]" : "null") +
                '}';
    }

}

