package com.bhushan5640.bimi;

import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.IETFUtils;
import org.bouncycastle.asn1.x509.Extensions;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class BimiUtils {

    private static final String TRADEMARK_OFFICE_OID = "1.3.6.1.4.1.53087.1.2";
    private static final String MARK_TYPE_OID = "1.3.6.1.4.1.53087.1.13";
    private static final String LOGOTYPE_EXT_OID = "1.3.6.1.5.5.7.1.12";

    /**
     * Returns true if the given X509Certificate contains trademark information.
     * It checks for the presence of a specific OID extension (trademark office name)
     * and also checks for mark type in the subject DN.
     */
    public static boolean hasTrademarkInfo(X509Certificate cert) {
        // First check for extension
        byte[] ext = cert.getExtensionValue(TRADEMARK_OFFICE_OID);
        if (ext != null) {
            return true;
        }

        // Check for mark type in subject DN
        String markType = null;
        try {
            X500Name subject = new X500Name(cert.getSubjectX500Principal().getName());
            ASN1ObjectIdentifier markTypeOID = new ASN1ObjectIdentifier(TRADEMARK_OFFICE_OID);
            if (subject.getRDNs(markTypeOID).length > 0) {
                markType = subject.getRDNs(markTypeOID)[0].getFirst().getValue().toString();
                return markType != null && !markType.trim().isEmpty();
            }
        } catch (Exception e) {
            // Parsing error, no further checks
        }

        return false;
    }

    public static X509Certificate loadCert(InputStream in) throws Exception {
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        return (X509Certificate) cf.generateCertificate(in);
    }

    private static final String ENTRUST_MARK_OWNER_OID = "1.3.6.1.4.1.53087.1.2";
    private static final String ENTRUST_JURISDICTION_OID = "1.3.6.1.4.1.53087.1.3";
    private static final String ENTRUST_REGNO_OID       = "1.3.6.1.4.1.53087.1.4";
    // Optional field; do NOT rely on it being present:
    private static final String ENTRUST_MARK_TYPE_OID   = "1.3.6.1.4.1.53087.1.13";

    public static String getMarkType(X509Certificate cert) {
        try {
            X500Name subject = new X500Name(cert.getSubjectX500Principal().getName());

            boolean hasJurisdiction = hasRdn(subject, ENTRUST_JURISDICTION_OID);
            boolean hasRegNo       = hasRdn(subject, ENTRUST_REGNO_OID);

            String registrationType = null;
            try {
                ASN1ObjectIdentifier markTypeOID = new ASN1ObjectIdentifier(MARK_TYPE_OID);
                if (subject.getRDNs(markTypeOID).length > 0) {
                    registrationType = subject.getRDNs(markTypeOID)[0].getFirst().getValue().toString();
                }
            } catch (Exception e) {
               //
            }

        // Classify and return the type
        if (registrationType != null) {
            if (registrationType.equalsIgnoreCase("Registered Mark") || registrationType.equalsIgnoreCase("Government Mark")) {
                return "VMC";
            } else if (registrationType.equalsIgnoreCase("Prior Use Mark") || registrationType.equalsIgnoreCase("Modified Registered Mark")) {
                return "CMC";
            }
        }

            // Heuristic: Entrust VMCs carry BOTH jurisdiction and registration number in Subject.
            if (hasJurisdiction && hasRegNo) {
                return "VMC";
            }

            // If you want to be extra lenient, you could also consider:
            // boolean hasOwner = hasRdn(subject, ENTRUST_MARK_OWNER_OID);
            // if ((hasJurisdiction && hasOwner) || (hasRegNo && hasOwner)) return "VMC";

        } catch (Exception e) {
            // swallow and fall through
        }
        // Fallback: treat as CMC if VMC-specific OIDs are not present
        return "CMC";
    }

    private static boolean hasRdn(X500Name subject, String oid) {
        RDN[] rdns = subject.getRDNs(new ASN1ObjectIdentifier(oid));
        return rdns != null && rdns.length > 0 && rdns[0].getFirst() != null;
    }

    /**
     * Finds and prints the first BIMI certificate that contains trademark information.
     * Stops when one certificate with trademark info is found.
     */
    public static void findAndPrintCertificateWithTrademarkInfo() {
        String dbUrl = "jdbc:postgresql://localhost:5432/ctcerts?reWriteBatchedInserts=true";
        String dbUser = "postgres";
        String dbPassword = "";

        String sql = "SELECT cert_id, der, brand_name, subject, issuer FROM bimi_certs ORDER BY created_on DESC";

        try (Connection conn = DriverManager.getConnection(dbUrl, dbUser, dbPassword);
             PreparedStatement stmt = conn.prepareStatement(sql);
             ResultSet rs = stmt.executeQuery()) {

            System.out.println("Searching for BIMI certificates with trademark information...");
            int certCount = 0;

            while (rs.next()) {
                certCount++;
                byte[] derBytes = rs.getBytes("der");
                byte[] certIdBytes = rs.getBytes("cert_id");
                String brandName = rs.getString("brand_name");
                String subject = rs.getString("subject");
                String issuer = rs.getString("issuer");

                if (derBytes != null) {
                    try {
                        // Load the certificate from DER bytes
                        X509Certificate cert = loadCertFromDer(derBytes);

                        // Check if it has trademark information
                        if (hasTrademarkInfo(cert)) {
                            System.out.println("\n=== FOUND CERTIFICATE WITH TRADEMARK INFO ===");
                            System.out.println("Certificate ID: " + bytesToHex(certIdBytes));
                            System.out.println("Brand Name: " + brandName);
                            System.out.println("Subject: " + subject);
                            System.out.println("Issuer: " + issuer);
                            System.out.println("Serial Number: " + cert.getSerialNumber());
                            System.out.println("Not Before: " + cert.getNotBefore());
                            System.out.println("Not After: " + cert.getNotAfter());

                            // Print trademark extension details if present
                            byte[] trademarkExt = cert.getExtensionValue(TRADEMARK_OFFICE_OID);
                            if (trademarkExt != null) {
                                System.out.println("Trademark Extension (hex): " + bytesToHex(trademarkExt));
                            }

                            // Print mark type from subject DN if present
                            String markType = getMarkType(cert);
                            if (markType != null) {
                                System.out.println("Mark Type from Subject DN: " + markType);
                            }

                            // Print the full certificate
                            System.out.println("\n=== CERTIFICATE DETAILS ===");
                            System.out.println(cert.toString());

                            System.out.println("\nCertificate found after checking " + certCount + " certificates.");
                            return; // Stop when first certificate with trademark info is found
                        }

                        if (certCount % 100 == 0) {
                            System.out.println("Checked " + certCount + " certificates...");
                        }

                    } catch (Exception e) {
                        System.err.println("Error processing certificate ID " + bytesToHex(certIdBytes) + ": " + e.getMessage());
                    }
                }
            }

            System.out.println("No certificates with trademark information found after checking " + certCount + " certificates.");

        } catch (Exception e) {
            System.err.println("Database error: " + e.getMessage());
            e.printStackTrace();
        }
    }

    /**
     * Loads an X509Certificate from DER-encoded bytes
     */
    public static X509Certificate loadCertFromDer(byte[] derBytes) throws Exception {
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        ByteArrayInputStream bis = new ByteArrayInputStream(derBytes);
        return (X509Certificate) cf.generateCertificate(bis);
    }

    /**
     * Converts byte array to hexadecimal string
     */
    private static String bytesToHex(byte[] bytes) {
        if (bytes == null) return "null";
        StringBuilder result = new StringBuilder();
        for (byte b : bytes) {
            result.append(String.format("%02x", b));
        }
        return result.toString();
    }

    /**
     * Main method to run the trademark certificate finder
     */
    public static void main(String[] args) {
        findAndPrintCertificateWithTrademarkInfo();
    }

    /**
     * Logotype validation result class
     */
    public static class LogotypeValidationResult {
        private final boolean isValid;
        private final List<String> errors;
        private final List<String> warnings;
        private final String svgContent;
        private final int fileSize;

        public LogotypeValidationResult(boolean isValid, List<String> errors, List<String> warnings, String svgContent, int fileSize) {
            this.isValid = isValid;
            this.errors = errors;
            this.warnings = warnings;
            this.svgContent = svgContent;
            this.fileSize = fileSize;
        }

        public boolean isValid() { return isValid; }
        public List<String> getErrors() { return errors; }
        public List<String> getWarnings() { return warnings; }
        public String getSvgContent() { return svgContent; }
        public int getFileSize() { return fileSize; }
    }

    /**
     * Validates the logotype extension content according to BIMI specification
     */
    public static LogotypeValidationResult validateLogotypeExtension(X509Certificate cert) {
        List<String> errors = new ArrayList<>();
        List<String> warnings = new ArrayList<>();
        String svgContent = null;
        int fileSize = 0;

        try {
            byte[] logotypeExt = cert.getExtensionValue(LOGOTYPE_EXT_OID);
            if (logotypeExt == null) {
                errors.add("Logotype extension not found");
                return new LogotypeValidationResult(false, errors, warnings, null, 0);
            }

            // Parse the logotype extension to extract SVG content
            svgContent = extractSvgFromLogotypeExtension(logotypeExt);
            if (svgContent == null || svgContent.trim().isEmpty()) {
                errors.add("Invalid SVG content found in logotype extension");
                return new LogotypeValidationResult(false, errors, warnings, null, 0);
            }

            fileSize = svgContent.getBytes().length;

            // Validate SVG content according to BIMI rules
            validateSvgContent(svgContent, fileSize, errors, warnings);

        } catch (Exception e) {
            errors.add("Error parsing logotype extension: " + e.getMessage());
        }

        boolean isValid = errors.isEmpty();
        return new LogotypeValidationResult(isValid, errors, warnings, svgContent, fileSize);
    }

    /**
     * Extracts SVG content from logotype extension using proper ASN.1 parsing
     */
    public static String extractSvgFromLogotypeExtension(byte[] logotypeExt) {
        try {
            // Parse ASN.1 extension data properly
            ASN1Sequence logotypeSequence = parseAsn1Extension(logotypeExt);

            if (logotypeSequence.size() > 0) {
                org.bouncycastle.asn1.ASN1Encodable firstElement = logotypeSequence.getObjectAt(0);
                if (firstElement instanceof org.bouncycastle.asn1.ASN1TaggedObject level1) { // [CONTEXT 2] subjectLogos
                    org.bouncycastle.asn1.ASN1Encodable inner1 = level1.getBaseObject();
                    if (inner1 instanceof org.bouncycastle.asn1.ASN1TaggedObject level2) {    // [CONTEXT 0] direct
                        org.bouncycastle.asn1.ASN1Encodable inner2 = level2.getBaseObject();
                        if (inner2 instanceof org.bouncycastle.asn1.ASN1Sequence subjectLogos) {
                            return extractSvgFromSubjectLogos(subjectLogos);
                        }
                    }
                }
            }
        } catch (Exception e) {
            // Fallback - return null if proper parsing fails
        }
        return null;
    }

    public static void printFullSubject(X509Certificate cert) {
        X500Name x500name = new X500Name(cert.getSubjectX500Principal().getName());
        RDN[] rdns = x500name.getRDNs();

        System.out.println("Full Subject (parsed):");
        for (RDN rdn : rdns) {
            ASN1ObjectIdentifier oid = rdn.getFirst().getType();
            String value = IETFUtils.valueToString(rdn.getFirst().getValue());
            System.out.println("  " + oid.getId() + " = " + value);
        }
    }

    /**
     * Parses ASN.1 extension data from certificate extension bytes
     */
    private static org.bouncycastle.asn1.ASN1Sequence parseAsn1Extension(byte[] extensionBytes) throws java.io.IOException {
        try (org.bouncycastle.asn1.ASN1InputStream asn1InputStream = new org.bouncycastle.asn1.ASN1InputStream(new ByteArrayInputStream(extensionBytes))) {
            org.bouncycastle.asn1.ASN1OctetString octetString = (org.bouncycastle.asn1.ASN1OctetString) asn1InputStream.readObject();

            try (org.bouncycastle.asn1.ASN1InputStream dataInputStream = new org.bouncycastle.asn1.ASN1InputStream(new ByteArrayInputStream(octetString.getOctets()))) {
                return (org.bouncycastle.asn1.ASN1Sequence) dataInputStream.readObject();
            }
        }
    }

    /**
     * Extracts SVG content from subject logos ASN.1 sequence
     */
    private static String extractSvgFromSubjectLogos(org.bouncycastle.asn1.ASN1Sequence subjectLogos) {
        try {
            for (org.bouncycastle.asn1.ASN1Encodable logoInfo : subjectLogos) {
                if (logoInfo instanceof org.bouncycastle.asn1.ASN1Sequence logoInfoSeq && logoInfoSeq.size() > 0) {

                    // Unwrap LogotypeData (may be tagged or direct sequence)
                    org.bouncycastle.asn1.ASN1Encodable firstObj = logoInfoSeq.getObjectAt(0);
                    org.bouncycastle.asn1.ASN1Sequence logotypeData;
                    if (firstObj instanceof org.bouncycastle.asn1.ASN1TaggedObject tagged) {
                        logotypeData = org.bouncycastle.asn1.ASN1Sequence.getInstance(tagged.getBaseObject());
                    } else {
                        logotypeData = org.bouncycastle.asn1.ASN1Sequence.getInstance(firstObj);
                    }

                    if (logotypeData.size() >= 3) {
                        // 2 = embedded Data URI or external URI
                        String svgContent = parseLogoImageField(logotypeData.getObjectAt(2));
                        if (svgContent != null && !svgContent.trim().isEmpty()) {
                            return svgContent;
                        }
                    }
                    else if (logotypeData.size() >= 2) {
                        // 1 = image sequence (older style)
                        org.bouncycastle.asn1.ASN1Sequence images = org.bouncycastle.asn1.ASN1Sequence.getInstance(logotypeData.getObjectAt(1));
                        for (org.bouncycastle.asn1.ASN1Encodable imageDataObj : images) {
                            org.bouncycastle.asn1.ASN1Sequence imageData = org.bouncycastle.asn1.ASN1Sequence.getInstance(imageDataObj);
                            if (imageData.size() > 1) {
                                String svgContent = parseLogoImageField(imageData.getObjectAt(1));
                                if (svgContent != null && !svgContent.trim().isEmpty()) {
                                    return svgContent;
                                }
                            }
                        }
                    }
                }
            }
        } catch (Exception e) {
            // Return null if parsing fails
        }
        return null;
    }

    /**
     * Parses logo image field from ASN.1 structure
     */
    private static String parseLogoImageField(org.bouncycastle.asn1.ASN1Encodable imgObj) {
        try {
            if (imgObj instanceof org.bouncycastle.asn1.DERIA5String ia5) {
                String uri = ia5.getString();
                return handleUriOrDataUri(uri);
            }
            else if (imgObj instanceof org.bouncycastle.asn1.ASN1OctetString octets) {
                String svg = new String(octets.getOctets(), java.nio.charset.StandardCharsets.UTF_8);
                if (svg.contains("<svg") || svg.contains("xmlns=\"http://www.w3.org/2000/svg\"")) {
                    return sanitizeSvgContent(svg);
                }
            }
            else if (imgObj instanceof org.bouncycastle.asn1.ASN1Sequence dataUriSeq) {
                String dataUri = org.bouncycastle.asn1.ASN1IA5String.getInstance(dataUriSeq.getObjectAt(0)).getString();
                return handleUriOrDataUri(dataUri);
            }
        } catch (Exception e) {
            // Return null if parsing fails
        }
        return null;
    }

    /**
     * Handles URI or data URI to extract SVG content
     */
    private static String handleUriOrDataUri(String uri) {
        if (uri == null || uri.trim().isEmpty()) {
            return null;
        }

        String trimmedUri = uri.trim();

        // Handle data URIs
        if (trimmedUri.regionMatches(true, 0, "data:", 0, 5)) {
            return handleDataUri(trimmedUri);
        }

        // For HTTP/HTTPS URIs, we can't fetch content in this validation context
        // Return a placeholder or null
        return null;
    }

    /**
     * Parses data URI to extract SVG content
     */
    private static String handleDataUri(String dataUri) {
        try {
            // Parse data URI: data:<mediatype>(;param=val)*;(base64)?,<data>
            int commaIndex = dataUri.indexOf(',');
            if (commaIndex == -1) {
                return null;
            }

            String header = dataUri.substring(5, commaIndex).toLowerCase(); // Skip "data:"
            String data = dataUri.substring(commaIndex + 1);

            // Parse media type and parameters
            String[] headerParts = header.split(";");
            String mediaType = headerParts[0].trim();

            // Only accept SVG images for BIMI
            if (!mediaType.equals("image/svg+xml") && !mediaType.equals("image/svg+xml-compressed")) {
                return null;
            }

            // Check encoding parameters
            boolean isBase64 = false;
            boolean isGzipCompressed = mediaType.equals("image/svg+xml-compressed");

            for (int i = 1; i < headerParts.length; i++) {
                String param = headerParts[i].trim();
                if (param.equals("base64")) {
                    isBase64 = true;
                }
            }

            // Decode the data
            byte[] decodedData;
            if (isBase64) {
                try {
                    decodedData = Base64.getDecoder().decode(data);
                } catch (IllegalArgumentException e) {
                    return null;
                }
            } else {
                // URL-encoded data
                decodedData = java.net.URLDecoder.decode(data, "UTF-8").getBytes(java.nio.charset.StandardCharsets.UTF_8);
            }

            // Handle compression
            String svgContent;
            if (isGzipCompressed || isGzipData(decodedData)) {
                svgContent = gunzipToString(decodedData);
            } else {
                svgContent = new String(decodedData, java.nio.charset.StandardCharsets.UTF_8);
            }

            return sanitizeSvgContent(svgContent);

        } catch (Exception e) {
            return null;
        }
    }

    /**
     * Detect gzip compression using magic bytes
     */
    private static boolean isGzipData(byte[] data) {
        return data.length >= 2 &&
               (data[0] & 0xFF) == 0x1F &&
               (data[1] & 0xFF) == 0x8B;
    }

    /**
     * Decompress gzipped data to string
     */
    private static String gunzipToString(byte[] compressed) throws java.io.IOException {
        try (java.util.zip.GZIPInputStream gis = new java.util.zip.GZIPInputStream(new ByteArrayInputStream(compressed))) {
            return new String(gis.readAllBytes(), java.nio.charset.StandardCharsets.UTF_8);
        }
    }

    /**
     * Sanitizes SVG content by removing problematic characters
     */
    private static String sanitizeSvgContent(String svg) {
        if (svg == null) {
            return null;
        }

        // Remove null bytes and other problematic control characters
        String sanitized = svg.replace("\u0000", "");

        StringBuilder cleaned = new StringBuilder();
        for (int i = 0; i < sanitized.length(); i++) {
            char c = sanitized.charAt(i);
            // Allow printable ASCII, whitespace, and Unicode characters above 127
            if (c >= 32 || c == '\t' || c == '\n' || c == '\r' || c > 127) {
                cleaned.append(c);
            }
        }

        return cleaned.toString();
    }

    /**
     * Validates SVG content according to BIMI specification rules
     */
    private static void validateSvgContent(String svgContent, int fileSize, List<String> errors, List<String> warnings) {
        // 1. File size validation (SHOULD NOT exceed 32KB)
        if (fileSize > 32768) {
            errors.add("SVG file size (" + fileSize + " bytes) exceeds recommended limit of 32KB");
        }

        // 2. Format validation - must be SVG
        if (!svgContent.trim().contains("<svg")) {
            errors.add("Content is not a valid SVG document");
            return; // Can't continue validation if not SVG
        }

        // 3. SVG Tiny PS profile validation
        validateSvgTinyPsProfile(svgContent, errors, warnings);

        // 4. Security restrictions
        validateSvgSecurity(svgContent, errors, warnings);

        // 5. Required elements validation
        validateRequiredElements(svgContent, errors, warnings);

        // 6. Root element attribute validation
        validateRootElementAttributes(svgContent, errors, warnings);
    }

    /**
     * Validates SVG Tiny PS profile requirements
     */
    private static void validateSvgTinyPsProfile(String svgContent, List<String> errors, List<String> warnings) {
        // Check for baseProfile="tiny-ps"
        if (!svgContent.contains("baseProfile=\"tiny-ps\"")) {
            errors.add("SVG root element missing required baseProfile=\"tiny-ps\" attribute");
        }

        // Check for version="1.2"
        if (!svgContent.contains("version=\"1.2\"")) {
            errors.add("SVG root element missing required version=\"1.2\" attribute");
        }
    }

    /**
     * Validates SVG security restrictions
     */
    private static void validateSvgSecurity(String svgContent, List<String> errors, List<String> warnings) {
        // Check for prohibited script elements
        if (svgContent.contains("<script") || svgContent.contains("javascript:")) {
            errors.add("SVG contains prohibited script elements or JavaScript");
        }

        // Check for animation elements
        if (svgContent.contains("<animate") || svgContent.contains("<animateTransform")) {
            errors.add("SVG contains prohibited animation elements");
        }

        // Check for external references (excluding XML namespaces)
        Pattern externalRefPattern = Pattern.compile("href\\s*=\\s*[\"'][^\"']*://[^\"']*[\"']");
        if (externalRefPattern.matcher(svgContent).find()) {
            errors.add("SVG contains prohibited external references");
        }

        // Check for x= or y= attributes in root svg element
        Pattern rootSvgPattern = Pattern.compile("<svg[^>]*\\s(?:x|y)\\s*=");
        if (rootSvgPattern.matcher(svgContent).find()) {
            errors.add("SVG root element must not contain x= or y= attributes");
        }

        // Check for unsupported elements (filters, effects, embedded images)
        String[] prohibitedElements = {"<filter", "<feGaussianBlur", "<image", "<foreignObject"};
        for (String element : prohibitedElements) {
            if (svgContent.contains(element)) {
                errors.add("SVG may contain unsupported SVG Tiny PS elements: " + element.substring(1));
            }
        }
    }

    /**
     * Validates required elements
     */
    private static void validateRequiredElements(String svgContent, List<String> errors, List<String> warnings) {
        // Required <title> element
        if (!svgContent.contains("<title>") && !svgContent.contains("<title/>") && !svgContent.contains("</title>")) {
            errors.add("SVG missing required <title> element reflecting company name");
        }

        // Recommended <desc> element
        if (!svgContent.contains("<desc>")) {
            // warnings.add("SVG missing recommended <desc> element for accessibility");
        }
    }

    /**
     * Validates root element attributes
     */
    private static void validateRootElementAttributes(String svgContent, List<String> errors, List<String> warnings) {
        // Extract the opening svg tag
        Pattern svgTagPattern = Pattern.compile("<svg[^>]*>");
        Matcher matcher = svgTagPattern.matcher(svgContent);

        if (matcher.find()) {
            String svgTag = matcher.group(0);

            // Check viewBox for aspect ratio recommendations
            if (svgTag.contains("viewBox")) {
                Pattern viewBoxPattern = Pattern.compile("viewBox\\s*=\\s*[\"']([^\"']*)[\"']");
                Matcher viewBoxMatcher = viewBoxPattern.matcher(svgTag);
                if (viewBoxMatcher.find()) {
                    String[] viewBoxValues = viewBoxMatcher.group(1).split("\\s+");
                    if (viewBoxValues.length == 4) {
                        try {
                            double width = Double.parseDouble(viewBoxValues[2]);
                            double height = Double.parseDouble(viewBoxValues[3]);
                            double aspectRatio = width / height;

                            // Check if approximately square (aspect ratio between 0.9 and 1.1)
                            if (aspectRatio < 0.9 || aspectRatio > 1.1) {
                               // warnings.add("SVG should be square for optimal display (current aspect ratio: " + String.format("%.2f", aspectRatio) + ")");
                            }
                        } catch (NumberFormatException e) {
                            errors.add("Invalid viewBox values in SVG");
                        }
                    }
                }
            } else {
                errors.add("SVG missing viewBox attribute for proper scaling");
            }
        }
    }

    public static Extensions getExtensions(X509Certificate certificate) {
        try {
            byte[] tbsData = certificate.getTBSCertificate();

            for(ASN1Encodable thing : ASN1Sequence.getInstance(tbsData)) {
                if (thing instanceof ASN1TaggedObject tagged) {
                    if (tagged.getTagNo() == 3) {
                        ASN1Primitive obj = tagged.getExplicitBaseObject().toASN1Primitive();
                        return Extensions.getInstance(obj);
                    }
                }
            }
        } catch (CertificateEncodingException e) {
            throw new RuntimeException("Failure in getting TBSCertificate data", e);
        }

        return Extensions.getInstance(new DERSequence());
    }

    /**
     * Creates an X509Certificate from DER-encoded bytes
     */
    public static X509Certificate makeCertFromDER(byte[] derBytes) throws java.security.cert.CertificateException {
        if (derBytes == null) {
            throw new IllegalArgumentException("DER bytes cannot be null");
        }
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        ByteArrayInputStream bis = new ByteArrayInputStream(derBytes);
        return (X509Certificate) cf.generateCertificate(bis);
    }

    /**
     * Gets subject alternative names from certificate
     */
    public static List<String> getSubjectAlternativeNames(X509Certificate cert) {
        List<String> sans = new ArrayList<>();
        try {
            java.util.Collection<java.util.List<?>> sanCollection = cert.getSubjectAlternativeNames();
            if (sanCollection != null) {
                for (java.util.List<?> san : sanCollection) {
                    if (san.size() >= 2) {
                        // Type is at index 0, value at index 1
                        // Type 2 = dNSName
                        Integer type = (Integer) san.get(0);
                        String value = (String) san.get(1);
                        if (type == 2) { // dNSName
                            sans.add(value);
                        }
                    }
                }
            }
        } catch (Exception e) {
            // Return empty list if parsing fails
        }
        return sans;
    }

    /**
     * Checks if certificate is a precertificate
     * A precertificate contains the CT poison extension (1.3.6.1.4.1.11129.2.4.3)
     */
    public static boolean isPrecert(X509Certificate cert) {
        try {
            // CT poison extension OID
            byte[] poisonExt = cert.getExtensionValue("1.3.6.1.4.1.11129.2.4.3");
            return poisonExt != null;
        } catch (Exception e) {
            return false;
        }
    }
}

