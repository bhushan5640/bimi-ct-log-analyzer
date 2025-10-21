package com.bhushan5640.bimi.db;

import java.sql.*;
import java.util.ArrayList;
import java.util.List;

/**
 * JDBC-based implementation of BimiCertificateRepository.
 * This is a reference implementation that can be customized for different database schemas.
 * Users can either:
 * 1. Use this implementation with their own table/column mappings
 * 2. Create their own implementation of BimiCertificateRepository
 */
public class JdbcBimiCertificateRepository implements BimiCertificateRepository {

    private final String jdbcUrl;
    private final String username;
    private final String password;
    private final String tableName;
    private final ColumnMapping columnMapping;

    /**
     * Column mapping configuration for flexible schema adaptation
     */
    public static class ColumnMapping {
        public String certId = "cert_id";
        public String der = "der";
        public String brandName = "brand_name";
        public String subject = "subject";
        public String issuer = "issuer";
        public String certificateType = "certificate_type";
        public String logoSvgContent = "logo_svg_content";
        public String names = "names";
        public String notAfter = "not_after";
        public String createdOn = "created_on";

        public static ColumnMapping defaultMapping() {
            return new ColumnMapping();
        }

        public ColumnMapping withCertId(String certId) {
            this.certId = certId;
            return this;
        }

        public ColumnMapping withDer(String der) {
            this.der = der;
            return this;
        }

        public ColumnMapping withBrandName(String brandName) {
            this.brandName = brandName;
            return this;
        }

        public ColumnMapping withSubject(String subject) {
            this.subject = subject;
            return this;
        }

        public ColumnMapping withIssuer(String issuer) {
            this.issuer = issuer;
            return this;
        }

        public ColumnMapping withCertificateType(String certificateType) {
            this.certificateType = certificateType;
            return this;
        }

        public ColumnMapping withLogoSvgContent(String logoSvgContent) {
            this.logoSvgContent = logoSvgContent;
            return this;
        }

        public ColumnMapping withNames(String names) {
            this.names = names;
            return this;
        }

        public ColumnMapping withNotAfter(String notAfter) {
            this.notAfter = notAfter;
            return this;
        }

        public ColumnMapping withCreatedOn(String createdOn) {
            this.createdOn = createdOn;
            return this;
        }
    }

    public JdbcBimiCertificateRepository(String jdbcUrl, String username, String password) {
        this(jdbcUrl, username, password, "bimi_certs", ColumnMapping.defaultMapping());
    }

    public JdbcBimiCertificateRepository(String jdbcUrl, String username, String password,
                                         String tableName, ColumnMapping columnMapping) {
        this.jdbcUrl = jdbcUrl;
        this.username = username;
        this.password = password;
        this.tableName = tableName;
        this.columnMapping = columnMapping;
    }

    private Connection getConnection() throws SQLException {
        return DriverManager.getConnection(jdbcUrl, username, password);
    }

    @Override
    public List<BimiCertificate> findAllWithLogoContent() {
        String sql = String.format(
            "SELECT %s, %s, %s, %s, %s, %s, %s, %s, %s, %s FROM %s WHERE %s IS NOT NULL",
            columnMapping.certId, columnMapping.der, columnMapping.brandName,
            columnMapping.subject, columnMapping.issuer, columnMapping.certificateType,
            columnMapping.logoSvgContent, columnMapping.names, columnMapping.notAfter,
            columnMapping.createdOn, tableName, columnMapping.logoSvgContent
        );
        return executeQuery(sql);
    }

    @Override
    public List<BimiCertificate> findAllWithBrandName() {
        String sql = String.format(
            "SELECT %s, %s, %s, %s, %s, %s, %s, %s, %s, %s FROM %s WHERE %s IS NOT NULL",
            columnMapping.certId, columnMapping.der, columnMapping.brandName,
            columnMapping.subject, columnMapping.issuer, columnMapping.certificateType,
            columnMapping.logoSvgContent, columnMapping.names, columnMapping.notAfter,
            columnMapping.createdOn, tableName, columnMapping.brandName
        );
        return executeQuery(sql);
    }

    @Override
    public List<BimiCertificate> findAllWithLogoAndBrandName() {
        String sql = String.format(
            "SELECT %s, %s, %s, %s, %s, %s, %s, %s, %s, %s FROM %s WHERE %s IS NOT NULL AND %s IS NOT NULL",
            columnMapping.certId, columnMapping.der, columnMapping.brandName,
            columnMapping.subject, columnMapping.issuer, columnMapping.certificateType,
            columnMapping.logoSvgContent, columnMapping.names, columnMapping.notAfter,
            columnMapping.createdOn, tableName, columnMapping.logoSvgContent, columnMapping.brandName
        );
        return executeQuery(sql);
    }

    @Override
    public List<BimiCertificate> findAllActiveWithLogoAndBrandName() {
        String sql = String.format(
            "SELECT %s, %s, %s, %s, %s, %s, %s, %s, %s, %s FROM %s " +
            "WHERE %s IS NOT NULL AND %s IS NOT NULL AND %s > NOW()",
            columnMapping.certId, columnMapping.der, columnMapping.brandName,
            columnMapping.subject, columnMapping.issuer, columnMapping.certificateType,
            columnMapping.logoSvgContent, columnMapping.names, columnMapping.notAfter,
            columnMapping.createdOn, tableName, columnMapping.logoSvgContent,
            columnMapping.brandName, columnMapping.notAfter
        );
        return executeQuery(sql);
    }

    @Override
    public List<BimiCertificate> findAll() {
        String sql = String.format(
            "SELECT %s, %s, %s, %s, %s, %s, %s, %s, %s, %s FROM %s",
            columnMapping.certId, columnMapping.der, columnMapping.brandName,
            columnMapping.subject, columnMapping.issuer, columnMapping.certificateType,
            columnMapping.logoSvgContent, columnMapping.names, columnMapping.notAfter,
            columnMapping.createdOn, tableName
        );
        return executeQuery(sql);
    }

    private List<BimiCertificate> executeQuery(String sql) {
        List<BimiCertificate> results = new ArrayList<>();

        try (Connection conn = getConnection();
             Statement stmt = conn.createStatement();
             ResultSet rs = stmt.executeQuery(sql)) {

            while (rs.next()) {
                BimiCertificate cert = new BimiCertificate();
                cert.setCertId(rs.getBytes(columnMapping.certId));
                cert.setDer(rs.getBytes(columnMapping.der));
                cert.setBrandName(rs.getString(columnMapping.brandName));
                cert.setSubject(rs.getString(columnMapping.subject));
                cert.setIssuer(rs.getString(columnMapping.issuer));
                cert.setCertificateType(rs.getString(columnMapping.certificateType));
                cert.setLogoSvgContent(rs.getString(columnMapping.logoSvgContent));
                cert.setNames((String) rs.getObject(columnMapping.names));

                Timestamp notAfterTs = rs.getTimestamp(columnMapping.notAfter);
                if (notAfterTs != null) {
                    cert.setNotAfter(notAfterTs.toInstant());
                }

                results.add(cert);
            }
        } catch (SQLException e) {
            throw new RuntimeException("Database query failed: " + e.getMessage(), e);
        }

        return results;
    }
}

