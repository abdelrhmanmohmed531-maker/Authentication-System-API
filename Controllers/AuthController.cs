using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using AuthenticationSystemAPI.DTOs;
using AuthenticationSystemAPI.Services;

/*
 * ===================================================================
 * AUTH CONTROLLER - API Endpoint Layer
 * ===================================================================
 * 
 * Clean Architecture - This is the "Presentation" or "API" layer:
 * - Handles HTTP requests and responses
 * - Validates input data
 * - Calls Service layer for business logic
 * - Returns appropriate HTTP status codes
 * 
 * CONTROLLER RESPONSIBILITIES:
 * 1. Receive HTTP requests
 * 2. Validate input (model binding + manual validation)
 * 3. Call appropriate service methods
 * 4. Map responses to HTTP responses
 * 5. Return appropriate status codes
 * 
 * ATTRIBUTE EXPLANATIONS:
 * [ApiController] - Enables API-specific features (automatic model validation, etc.)
 * [Route("api/[controller]")] - URL route: /api/auth
 * [ControllerBase] - Base class for MVC controllers
 * [Authorize] - Requires authentication to access endpoint
 */

namespace AuthenticationSystemAPI.Controllers;

[ApiController]
[Route("api/[controller]")]
public class AuthController : ControllerBase
{
    // Dependency: We need AuthService to handle business logic
    private readonly IAuthService _authService;

    /*
     * Constructor Injection
     * -------------------
     * ASP.NET Core will inject the IAuthService implementation
     * This follows the Dependency Inversion Principle:
     * - High-level modules (Controller) depend on abstractions (IAuthService)
     * - Not on concrete implementations (AuthService)
     */
    public AuthController(IAuthService authService)
    {
        _authService = authService;
    }

    /*
     * REGISTER ENDPOINT
     * ----------------
     * Purpose: Create a new user account
     * 
     * HTTP Method: POST
     * URL: /api/auth/register
     * Content-Type: application/json
     * 
     * Request Body (JSON):
     * {
     *   "username": "johndoe",
     *   "email": "john@example.com",
     *   "password": "Password123"
     * }
     * 
     * Success Response (200 OK):
     * {
     *   "token": "eyJhbGciOiJIUzI1NiIs...",
     *   "username": "johndoe",
     *   "email": "john@example.com",
     *   "role": "User",
     *   "expiresAt": "2024-01-01T12:00:00Z"
     * }
     * 
     * Error Response (400 Bad Request):
     * {
     *   "message": "Username or email already exists"
     * }
     * 
     * FLOW:
     * 1. Client sends POST request with registration data
     * 2. Model binding maps JSON to RegisterRequest
     * 3. [ApiController] automatically validates required fields
     * 4. If invalid, returns 400 Bad Request automatically
     * 5. If valid, calls _authService.RegisterAsync()
     * 6. Service checks for duplicates, hashes password, creates user
     * 7. Service returns AuthResponse with JWT token
     * 8. Controller returns 200 OK with response
     */
    [HttpPost("register")]
    [ProducesResponseType(typeof(AuthResponse), StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status400BadRequest)]
    public async Task<ActionResult<AuthResponse>> Register([FromBody] RegisterRequest request)
    {
        // Additional manual validation (beyond [Required] attributes)
        if (string.IsNullOrWhiteSpace(request.Username) || 
            string.IsNullOrWhiteSpace(request.Email) || 
            string.IsNullOrWhiteSpace(request.Password))
        {
            // Return bad request with error message
            return BadRequest(new ErrorResponse 
            { 
                Message = "All fields are required",
                Code = "VALIDATION_ERROR"
            });
        }

        // Call the service to handle registration logic
        var result = await _authService.RegisterAsync(request);
        
        if (result == null)
        {
            // Registration failed (duplicate username/email)
            // Don't reveal which one failed (security best practice)
            return BadRequest(new ErrorResponse 
            { 
                Message = "Username or email already exists",
                Code = "DUPLICATE_ENTRY"
            });
        }

        // Success! Return the response with token
        return Ok(result);
    }

    /*
     * LOGIN ENDPOINT
     * --------------
     * Purpose: Authenticate user and get JWT token
     * 
     * HTTP Method: POST
     * URL: /api/auth/login
     * Content-Type: application/json
     * 
     * Request Body (JSON):
     * {
     *   "username": "johndoe",
     *   "password": "Password123"
     * }
     * 
     * Success Response (200 OK):
     * {
     *   "token": "eyJhbGciOiJIUzI1NiIs...",
     *   "username": "johndoe",
     *   "email": "john@example.com",
     *   "role": "User",
     *   "expiresAt": "2024-01-01T12:00:00Z"
     * }
     * 
     * Error Response (401 Unauthorized):
     * {
     *   "message": "Invalid username or password"
     * }
     * 
     * FLOW:
     * 1. Client sends POST request with credentials
     * 2. Model binding maps JSON to LoginRequest
     * 3. Controller validates input
     * 4. Calls _authService.LoginAsync()
     * 5. Service finds user, verifies password with BCrypt
     * 6. If valid, generates JWT token
     * 7. Controller returns 200 OK with token
     * 8. If invalid, returns 401 Unauthorized
     */
    [HttpPost("login")]
    [ProducesResponseType(typeof(AuthResponse), StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status401Unauthorized)]
    public async Task<ActionResult<AuthResponse>> Login([FromBody] LoginRequest request)
    {
        // Validate input
        if (string.IsNullOrWhiteSpace(request.Username) || 
            string.IsNullOrWhiteSpace(request.Password))
        {
            return BadRequest(new ErrorResponse 
            { 
                Message = "Username and password are required",
                Code = "VALIDATION_ERROR"
            });
        }

        // Call service to authenticate
        var result = await _authService.LoginAsync(request);
        
        if (result == null)
        {
            // Authentication failed
            // Return 401 Unauthorized (not found or wrong password)
            // Don't reveal which one for security
            return Unauthorized(new ErrorResponse 
            { 
                Message = "Invalid username or password",
                Code = "AUTH_FAILED"
            });
        }

        // Success! Return token
        return Ok(result);
    }

    /*
     * GET PROFILE ENDPOINT
     * --------------------
     * Purpose: Get current user's profile information
     * 
     * HTTP Method: GET
     * URL: /api/auth/profile
     * Authorization: Bearer <token>
     * 
     * Success Response (200 OK):
     * {
     *   "id": 1,
     *   "username": "johndoe",
     *   "email": "john@example.com",
     *   "role": "User",
     *   "createdAt": "2024-01-01T10:00:00Z"
     * }
     * 
     * Error Response (401 Unauthorized):
     * {
     *   "message": "Unauthorized"
     * }
     * 
     * [Authorize] ATTRIBUTE:
     * - Requires valid JWT token to access this endpoint
     * - If no token or invalid token, returns 401
     * - If valid token, allows access and populates User.Claims
     * 
     * FLOW:
     * 1. Client sends GET request with Authorization header
     * 2. [Authorize] attribute intercepts request BEFORE controller
     * 3. JWT Bearer middleware validates token
     * 4. If valid, creates ClaimsPrincipal and sets User property
     * 5. Controller action is called
     * 6. We extract username from User.Claims
     * 7. Call service to get profile data
     * 8. Return profile as JSON
     */
    [Authorize]  // <--- This makes the endpoint protected!
    [HttpGet("profile")]
    [ProducesResponseType(typeof(UserDto), StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status404NotFound)]
    public async Task<ActionResult<UserDto>> GetProfile()
    {
        // Extract username from JWT claims
        // The [Authorize] attribute already validated the token
        // Now we can safely read the user's identity from claims
        var username = User.FindFirst(ClaimTypes.Name)?.Value;
        
        // Should never be null if [Authorize] worked correctly
        if (string.IsNullOrEmpty(username))
        {
            return Unauthorized(new ErrorResponse 
            { 
                Message = "Invalid token",
                Code = "INVALID_TOKEN"
            });
        }

        // Get profile from service
        var profile = await _authService.GetProfileAsync(username);
        
        if (profile == null)
        {
            // User not found (shouldn't happen with valid token)
            return NotFound(new ErrorResponse 
            { 
                Message = "User not found",
                Code = "NOT_FOUND"
            });
        }

        return Ok(profile);
    }

    /*
     * TEST ENDPOINT - For checking if API is working
     * ------------------------------------------------
     * Purpose: Simple endpoint to test basic connectivity
     * No authentication required
     */
    [HttpGet("test")]
    [AllowAnonymous]  // Explicitly allow unauthenticated access
    public IActionResult Test()
    {
        return Ok(new 
        { 
            message = "API is working!",
            timestamp = DateTime.UtcNow
        });
    }
}

