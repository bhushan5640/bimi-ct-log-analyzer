package com.bhushan5640.bimi;

import com.bhushan5640.bimi.db.BimiCertificateRepository;
import com.bhushan5640.bimi.db.JdbcBimiCertificateRepository;

import java.io.FileInputStream;
import java.io.IOException;
import java.util.Properties;

/**
 * Main application class for BIMI Certificate Security Analyzer.
 */
public class BimiAnalyzerApp {

    public static void main(String[] args) {
        try {
            // Load configuration
            Properties config = loadConfiguration(args);

            // Create repository with configuration
            BimiCertificateRepository repository = createRepository(config);

            // Create analytics service
            var securityAnalyzer = new BimiSecurityAnalyticsService(repository);
            var policyAnalyzer = new BimiPolicyComplianceAnalyticsService(repository);

            // Run analysis
            policyAnalyzer.analyzeCerts();

        } catch (Exception e) {
            System.err.println("Error running BIMI analysis: " + e.getMessage());
            e.printStackTrace();
            System.exit(1);
        }
    }

    /**
     * Loads configuration from properties file or defaults
     */
    private static Properties loadConfiguration(String[] args) throws IOException {
        Properties config = new Properties();

        // Try to load from file if provided as command line argument
        String configFile = args.length > 0 ? args[0] : "config.properties";

        try (FileInputStream fis = new FileInputStream(configFile)) {
            config.load(fis);
            System.out.println("✓ Loaded configuration from: " + configFile);
        } catch (IOException e) {
            System.err.println("Warning: Could not load config file '" + configFile + "', using defaults");
            // Use default configuration
            config.setProperty("db.url", "jdbc:postgresql://localhost:5432/ctcerts?reWriteBatchedInserts=true");
            config.setProperty("db.username", "postgres");
            config.setProperty("db.password", "test");
            config.setProperty("db.table", "bimi_certs");
        }

        return config;
    }

    /**
     * Creates a repository instance based on configuration
     */
    private static BimiCertificateRepository createRepository(Properties config) {
        String dbUrl = config.getProperty("db.url");
        String username = config.getProperty("db.username");
        String password = config.getProperty("db.password");
        String tableName = config.getProperty("db.table", "bimi_certs");

        // Check if custom column mapping is provided
        JdbcBimiCertificateRepository.ColumnMapping columnMapping =
            JdbcBimiCertificateRepository.ColumnMapping.defaultMapping();

        if (config.containsKey("db.column.certId")) {
            columnMapping.withCertId(config.getProperty("db.column.certId"));
        }
        if (config.containsKey("db.column.der")) {
            columnMapping.withDer(config.getProperty("db.column.der"));
        }
        if (config.containsKey("db.column.brandName")) {
            columnMapping.withBrandName(config.getProperty("db.column.brandName"));
        }
        if (config.containsKey("db.column.subject")) {
            columnMapping.withSubject(config.getProperty("db.column.subject"));
        }
        if (config.containsKey("db.column.issuer")) {
            columnMapping.withIssuer(config.getProperty("db.column.issuer"));
        }
        if (config.containsKey("db.column.certificateType")) {
            columnMapping.withCertificateType(config.getProperty("db.column.certificateType"));
        }
        if (config.containsKey("db.column.logoSvgContent")) {
            columnMapping.withLogoSvgContent(config.getProperty("db.column.logoSvgContent"));
        }
        if (config.containsKey("db.column.names")) {
            columnMapping.withNames(config.getProperty("db.column.names"));
        }
        if (config.containsKey("db.column.notAfter")) {
            columnMapping.withNotAfter(config.getProperty("db.column.notAfter"));
        }
        if (config.containsKey("db.column.createdOn")) {
            columnMapping.withCreatedOn(config.getProperty("db.column.createdOn"));
        }

        return new JdbcBimiCertificateRepository(dbUrl, username, password, tableName, columnMapping);
    }
}
