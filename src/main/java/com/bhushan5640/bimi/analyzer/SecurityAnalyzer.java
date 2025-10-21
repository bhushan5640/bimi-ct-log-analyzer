package com.bhushan5640.bimi.analyzer;

import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

/**
 * Core security analysis engine for BIMI certificates.
 * This class is database-agnostic and operates on BimiCertificate objects.
 */
public class SecurityAnalyzer {

    // Suspicious SVG patterns
    private static final Pattern HIDDEN_CONTENT_PATTERN = Pattern.compile(
        "(?i)" +
            "(" +
            "(?<!-)\\bopacity\\s*[:=]\\s*[\"']?0+(?:\\.0+)?[\"']?" +
            "|visibility\\s*[:=]\\s*[\"']?hidden[\"']?" +
            "|display\\s*[:=]\\s*[\"']?none[\"']?" +
            "|width\\s*[:=]\\s*[\"']?0+[a-z%]*[\"']?" +
            "|height\\s*[:=]\\s*[\"']?0+[a-z%]*[\"']?" +
            "|font-size\\s*[:=]\\s*[\"']?0+[a-z%]*[\"']?"
            + ")"
    );

    private static final Pattern JAVASCRIPT_PATTERN = Pattern.compile(
        "(?i)" +
            "(<script\\b[^>]*>.*?</script>)" +
            "|(<script\\b[^>]*>)" +
            "|(\\s+on[a-zA-Z]+\\s*=)" +
            "|(javascript:[^\\s\"'>]*)" +
            "|(<iframe\\b[^>]*>)" +
            "|(<object\\b[^>]*>)" +
            "|(<embed\\b[^>]*>)"
    );

    private static final Pattern SUSPICIOUS_URLS_PATTERN = Pattern.compile(
        "(?i)href\\s*=\\s*[\"']?(https?://[^\"'\\s>]+)[\"']?"
    );

    private static final Pattern BASE64_PATTERN = Pattern.compile(
        "data:image/[^;]+;base64,([A-Za-z0-9+/=]+)"
    );

    private static final Set<String> SUSPICIOUS_UNICODE_BLOCKS = Set.of(
        "CYRILLIC", "GREEK", "ARMENIAN", "HEBREW", "ARABIC", "DEVANAGARI",
        "BENGALI", "GURMUKHI", "GUJARATI", "ORIYA", "TAMIL", "TELUGU",
        "KANNADA", "MALAYALAM", "SINHALA", "THAI", "LAO", "TIBETAN"
    );

    private static final Set<String> MAJOR_BRANDS = Set.of(
        "google", "microsoft", "apple", "amazon", "facebook", "meta", "tesla",
        "nike", "adidas", "coca-cola", "pepsi", "mcdonalds", "starbucks",
        "visa", "mastercard", "paypal", "netflix", "spotify", "uber", "airbnb",
        "twitter", "linkedin", "instagram", "youtube", "tiktok", "snapchat"
    );

    /**
     * Detects suspicious SVG patterns in a certificate
     */
    public List<String> detectSuspiciousSvgPatterns(String svgContent) {
        List<String> patterns = new ArrayList<>();

        if (svgContent == null) {
            return patterns;
        }

        if (JAVASCRIPT_PATTERN.matcher(svgContent).find()) {
            patterns.add("JavaScript/Script injection");
        }

        if (HIDDEN_CONTENT_PATTERN.matcher(svgContent).find()) {
            patterns.add("Hidden/invisible content");
        }

        if (svgContent.contains("data:") && BASE64_PATTERN.matcher(svgContent).find()) {
            patterns.add("Embedded base64 data");
        }

        if (svgContent.contains("foreignObject")) {
            patterns.add("Foreign object embedding");
        }

        if (svgContent.contains("use href") || svgContent.contains("xlink:href")) {
            patterns.add("External resource references");
        }

        return patterns;
    }

    /**
     * Calculates risk level based on suspicious patterns
     */
    public String calculateRiskLevel(List<String> suspiciousPatterns) {
        int riskScore = suspiciousPatterns.size();

        if (suspiciousPatterns.contains("JavaScript/Script injection")) riskScore += 3;
        if (suspiciousPatterns.contains("Foreign object embedding")) riskScore += 2;

        if (riskScore >= 4) return "HIGH";
        if (riskScore >= 2) return "MEDIUM";
        return "LOW";
    }

    /**
     * Detects Unicode homograph attacks
     */
    public List<String> detectUnicodeHomographs(String brandName, String subject) {
        List<String> suspiciousChars = new ArrayList<>();

        String[] texts = {brandName, subject};
        for (String text : texts) {
            if (text != null) {
                for (char c : text.toCharArray()) {
                    Character.UnicodeBlock block = Character.UnicodeBlock.of(c);
                    if (block != null && SUSPICIOUS_UNICODE_BLOCKS.contains(block.toString())) {
                        suspiciousChars.add(String.format("U+%04X (%c) in %s block",
                            (int) c, c, block.toString()));
                    }
                }
            }
        }

        return suspiciousChars.stream().distinct().collect(Collectors.toList());
    }

    /**
     * Finds lookalike brands that might be impersonating major brands
     */
    public String findLookalikeBrand(String brandName) {
        if (brandName == null) return null;

        String normalizedBrand = brandName.toLowerCase().trim();

        for (String majorBrand : MAJOR_BRANDS) {
            int distance = levenshteinDistance(normalizedBrand, majorBrand);
            if (distance > 0 && distance <= 2 && Math.abs(normalizedBrand.length() - majorBrand.length()) <= 2) {
                return majorBrand;
            }
        }

        return null;
    }

    /**
     * Detects hidden elements in SVG content
     */
    public List<String> detectHiddenElements(String svgContent) {
        List<String> hiddenElements = new ArrayList<>();

        if (svgContent == null) {
            return hiddenElements;
        }

        Matcher matcher = HIDDEN_CONTENT_PATTERN.matcher(svgContent);
        while (matcher.find()) {
            hiddenElements.add("Hidden style: " + matcher.group(1));
        }

        if (svgContent.contains("fill-opacity=\"0\"") || svgContent.contains("stroke-opacity=\"0\"")) {
            hiddenElements.add("Transparent elements");
        }

        if (svgContent.contains("width=\"0\"") || svgContent.contains("height=\"0\"")) {
            hiddenElements.add("Zero-sized elements");
        }

        return hiddenElements;
    }

    /**
     * Detects obfuscation techniques
     */
    public List<String> detectObfuscation(String brandName, String svgContent, String subject) {
        List<String> techniques = new ArrayList<>();

        String[] texts = {brandName, subject, svgContent};
        for (String text : texts) {
            if (text != null) {
                if (text.contains("\u200B") || text.contains("\u200C") || text.contains("\u200D") || text.contains("\uFEFF")) {
                    techniques.add("Zero-width characters");
                }

                if (text.contains("\u202D") || text.contains("\u202E")) {
                    techniques.add("Bidirectional text override");
                }

                if (text.matches(".*[а-я].*") && text.matches(".*[a-z].*")) {
                    techniques.add("Mixed script homoglyphs");
                }
            }
        }

        return techniques.stream().distinct().collect(Collectors.toList());
    }

    /**
     * Extracts URLs from SVG content
     */
    public List<String> extractUrls(String svgContent) {
        List<String> urls = new ArrayList<>();

        if (svgContent == null) {
            return urls;
        }

        Matcher matcher = SUSPICIOUS_URLS_PATTERN.matcher(svgContent);
        while (matcher.find()) {
            urls.add(matcher.group(1));
        }

        return urls;
    }

    /**
     * Checks if brand name is present in SVG title
     */
    public boolean brandNameInSvgTitle(String svgContent, String brandName) {
        if (svgContent == null || brandName == null) return false;

        Matcher m = Pattern.compile("<title>(.*?)</title>", Pattern.CASE_INSENSITIVE | Pattern.DOTALL)
            .matcher(svgContent);
        Set<String> brandWords = new HashSet<>(Arrays.asList(brandName.toLowerCase().split("\\W+")));

        while (m.find()) {
            Set<String> titleWords = new HashSet<>(Arrays.asList(m.group(1).toLowerCase().split("\\W+")));
            for (String w : brandWords) {
                if (!w.isEmpty() && titleWords.contains(w)) {
                    return true;
                }
            }
        }
        return false;
    }

    /**
     * Calculates Levenshtein distance between two strings
     */
    public int levenshteinDistance(String s1, String s2) {
        int[][] dp = new int[s1.length() + 1][s2.length() + 1];

        for (int i = 0; i <= s1.length(); i++) {
            for (int j = 0; j <= s2.length(); j++) {
                if (i == 0) {
                    dp[i][j] = j;
                } else if (j == 0) {
                    dp[i][j] = i;
                } else {
                    dp[i][j] = Math.min(
                        Math.min(dp[i - 1][j] + 1, dp[i][j - 1] + 1),
                        dp[i - 1][j - 1] + (s1.charAt(i - 1) == s2.charAt(j - 1) ? 0 : 1)
                    );
                }
            }
        }

        return dp[s1.length()][s2.length()];
    }

    /**
     * Utility to convert bytes to hex string
     */
    public static String bytesToHex(byte[] bytes) {
        if (bytes == null) return null;
        StringBuilder result = new StringBuilder();
        for (byte b : bytes) {
            result.append(String.format("%02x", b));
        }
        return result.toString();
    }
}
