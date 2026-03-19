namespace AuthenticationSystemAPI.Configuration;

/*
 * ===================================================================
 * JWT SETTINGS - Configuration class for JWT Authentication
 * ===================================================================
 * 
 * Why a separate configuration class?
 * - Centralizes JWT settings in one place
 * - Easy to read from appsettings.json
 * - Type-safe: Compiler catches typos
 * - Dependency Injection: Can inject wherever needed
 * 
 * In appsettings.json, we have:
 * "Jwt": {
 *   "SecretKey": "YourSuperSecretKey...",
 *   "Issuer": "AuthAPI",
 *   "Audience": "AuthAPIUsers",
 *   "ExpirationMinutes": 60
 * }
 */
public class JwtSettings
{
    // Secret Key - Used to sign the JWT token
    // IMPORTANT: In production, use a long, random string (256 bits minimum)
    // This key is used to create the digital signature
    // If exposed, attackers can forge tokens!
    public string SecretKey { get; set; } = string.Empty;

    // Issuer - Who created this token
    // Used to verify the token came from a trusted source
    // Example: "AuthAPI", "MyApplication", etc.
    public string Issuer { get; set; } = string.Empty;

    // Audience - Who this token is intended for
    // Used to ensure token is used for the right application
    // Example: "WebApp", "MobileApp", "AuthAPIUsers"
    public string Audience { get; set; } = string.Empty;

    // Expiration Minutes - How long the token is valid
    // Shorter = more secure (less time for token theft)
    // Longer = more convenient (less frequent re-login)
    // Common values: 15-60 minutes for access tokens
    public int ExpirationMinutes { get; set; } = 60;
}

